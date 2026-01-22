// Package session implements SAM v3.0-3.3 session management.
// This file implements Datagram3SessionImpl for DATAGRAM3 session handling
// per SAM 3.3 specification for repliable but unauthenticated datagrams with
// hash-based source identification.
package session

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-i2p/go-datagrams"
)

// Datagram3SessionImpl implements the DatagramSession interface for DATAGRAM3 style.
// It embeds *BaseSession and provides repliable but unauthenticated datagram functionality.
//
// Per SAMv3.md and PLAN.md Phase 5:
//   - Repliable but NOT authenticated (unlike DATAGRAM/DATAGRAM2)
//   - Source is a 32-byte hash, not a full destination
//   - Delivered to client as 44-byte base64 hash
//   - Client must do NAMING LOOKUP to get full destination for reply
//   - No replay protection (unauthenticated)
//
// Security Note: Application designers should use extreme caution and consider
// the security implications of unauthenticated datagrams. DATAGRAM3 is suitable
// for scenarios where authentication is not required or handled at application layer.
//
// To reply to a DATAGRAM3 source:
//  1. Receive the 44-byte base64 hash from SAM server
//  2. base64-decode to 32 bytes binary
//  3. base32-encode to 52 characters (lowercase, no padding)
//  4. Append ".b32.i2p" suffix
//  5. Use NAMING LOOKUP to get the full destination
//  6. Cache the result to avoid repeated lookups
type Datagram3SessionImpl struct {
	*BaseSession

	mu sync.RWMutex

	// Forwarding configuration for incoming datagrams
	forwardHost string
	forwardPort int
	forwardAddr net.Addr

	// Receive channel for incoming datagrams (non-forwarding mode)
	// Note: ReceivedDatagram.Source will be a 44-byte base64 hash for DATAGRAM3
	receiveChan chan ReceivedDatagram

	// PacketConn for sending/receiving UDP datagrams
	udpConn net.PacketConn

	// datagramConn is the go-datagrams connection for sending datagrams.
	// This wraps an I2CP session and handles protocol-specific envelope formatting.
	datagramConn *datagrams.DatagramConn

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// receiveWg waits for receive goroutines to complete
	receiveWg sync.WaitGroup
}

// MaxDatagram3Size is the maximum payload size for DATAGRAM3.
// Same as DATAGRAM/DATAGRAM2 - ~31KB for reliability per SAM specification.
const MaxDatagram3Size = 31744

// Datagram3HashSize is the binary size of a DATAGRAM3 source hash (32 bytes).
const Datagram3HashSize = 32

// Datagram3Base64HashSize is the base64-encoded size of a DATAGRAM3 source hash (44 bytes).
const Datagram3Base64HashSize = 44

// Datagram3Base32HashSize is the base32-encoded size of a DATAGRAM3 source hash (52 chars).
const Datagram3Base32HashSize = 52

// NewDatagram3Session creates a new DATAGRAM3 session for repliable but
// unauthenticated datagrams with hash-based source identification.
//
// Parameters:
//   - id: Unique session identifier (nickname)
//   - dest: I2P destination for this session
//   - conn: Control connection (session dies when this closes)
//   - cfg: Session configuration (port settings, etc.)
//
// Per SAM specification, the session starts in Creating state
// and must be activated after setup completes.
//
// Unlike DATAGRAM2, DATAGRAM3 does not support:
//   - Replay protection (unauthenticated)
//   - Offline signatures
func NewDatagram3Session(
	id string,
	dest *Destination,
	conn net.Conn,
	cfg *SessionConfig,
) *Datagram3SessionImpl {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure we have a config with valid defaults
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}

	return &Datagram3SessionImpl{
		BaseSession: NewBaseSession(id, StyleDatagram3, dest, conn, cfg),
		receiveChan: make(chan ReceivedDatagram, 100),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Send transmits a repliable but unauthenticated datagram to the specified destination.
// Implements DatagramSession.Send per SAM specification.
//
// Parameters:
//   - dest: Base64-encoded I2P destination or .i2p hostname
//   - data: Datagram payload (minimum 1 byte, max MaxDatagram3Size)
//   - opts: Send options (FromPort, ToPort)
//
// Returns error if:
//   - Session is not active
//   - Data is empty or too large
//   - Destination lookup fails
//   - Send operation fails
//
// Note: From a SAM perspective, DATAGRAM3 SEND is similar to DATAGRAM SEND.
// The difference is in the underlying I2CP format where the source is a hash
// rather than a full destination, and no authentication is performed.
func (d *Datagram3SessionImpl) Send(dest string, data []byte, opts DatagramSendOptions) error {
	d.mu.RLock()
	if d.Status() != StatusActive {
		d.mu.RUnlock()
		return ErrSessionNotActive
	}
	datagramConn := d.datagramConn
	d.mu.RUnlock()

	// Validate payload size
	if len(data) == 0 {
		return ErrEmptyPayload
	}
	if len(data) > MaxDatagram3Size {
		return ErrPayloadTooLarge
	}

	// Check if datagramConn is configured
	if datagramConn == nil {
		return ErrDatagram3SendNotImplemented
	}

	// Determine destination port (use ToPort if specified, otherwise 0)
	toPort := uint16(opts.ToPort)

	// Send the datagram using go-datagrams
	// DATAGRAM3 uses ProtocolDatagram3 (20) for repliable unauthenticated datagrams
	err := datagramConn.SendTo(data, dest, toPort)
	if err != nil {
		return fmt.Errorf("failed to send datagram3: %w", err)
	}

	return nil
}

// Receive returns a channel for incoming datagrams.
// Implements DatagramSession.Receive.
//
// Each received datagram includes source (as 44-byte base64 hash), ports, and data.
// Unlike DATAGRAM/DATAGRAM2, the Source field is a 44-byte base64-encoded hash,
// not a full destination. Use HashToB32Address to convert for NAMING LOOKUP.
func (d *Datagram3SessionImpl) Receive() <-chan ReceivedDatagram {
	return d.receiveChan
}

// ForwardingAddr returns the UDP address for forwarding, if configured.
// Implements DatagramSession.ForwardingAddr.
func (d *Datagram3SessionImpl) ForwardingAddr() net.Addr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.forwardAddr
}

// SetForwarding configures incoming datagram forwarding to host:port.
// When forwarding is set, incoming datagrams are sent to the specified
// UDP address instead of being delivered to the Receive() channel.
//
// Parameters:
//   - host: Target hostname (default "127.0.0.1" if empty)
//   - port: Target port (must be 1-65535)
//
// Returns error if port is invalid.
func (d *Datagram3SessionImpl) SetForwarding(host string, port int) error {
	if port < 1 || port > 65535 {
		return ErrInvalidForwardingPort
	}

	if host == "" {
		host = "127.0.0.1"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.forwardHost = host
	d.forwardPort = port

	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return err
	}
	d.forwardAddr = addr

	return nil
}

// IsForwarding returns true if forwarding is configured.
func (d *Datagram3SessionImpl) IsForwarding() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.forwardAddr != nil
}

// DeliverDatagram handles an incoming datagram and delivers it to the
// receive channel or forwarding address.
//
// Unlike DATAGRAM2, no replay protection is performed (unauthenticated).
//
// Parameters:
//   - dg: The received datagram (Source is 44-byte base64 hash)
//
// Returns true if the datagram was delivered, false if channel was full.
func (d *Datagram3SessionImpl) DeliverDatagram(dg ReceivedDatagram) bool {
	// Non-blocking send to channel (drop if full)
	select {
	case d.receiveChan <- dg:
		return true
	default:
		// Channel full, datagram dropped
		// This is acceptable per SAM spec (datagrams are best-effort)
		return false
	}
}

// Close terminates the session and releases all resources.
// Safe to call multiple times.
func (d *Datagram3SessionImpl) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Status() == StatusClosed {
		return nil
	}

	// Cancel context to stop background goroutines
	d.cancel()

	// Close UDP connection if open
	if d.udpConn != nil {
		d.udpConn.Close()
		d.udpConn = nil
	}

	// Close datagram connection if we own it
	if d.datagramConn != nil {
		d.datagramConn.Close()
		d.datagramConn = nil
	}

	// Close receive channel
	close(d.receiveChan)

	// Wait for goroutines to finish
	d.receiveWg.Wait()

	// Close base session
	return d.BaseSession.Close()
}

// SetDatagramConn sets the go-datagrams connection for sending datagrams.
// This should be called during session setup after the I2CP session is established.
// The DatagramConn should be created with ProtocolDatagram3 for DATAGRAM3 sessions.
func (d *Datagram3SessionImpl) SetDatagramConn(conn *datagrams.DatagramConn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.datagramConn = conn
}

// DatagramConn returns the go-datagrams connection, or nil if not configured.
func (d *Datagram3SessionImpl) DatagramConn() *datagrams.DatagramConn {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.datagramConn
}

// HashToB32Address converts a 44-byte base64-encoded hash (as received in
// DATAGRAM3) to a .b32.i2p address suitable for NAMING LOOKUP.
//
// Per SAMv3.md DATAGRAM3 specification:
//  1. base64-decode the 44-byte string to 32 bytes binary
//  2. base32-encode to 52 characters (lowercase, no padding)
//  3. Append ".b32.i2p" suffix
//
// Example:
//
//	hash := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
//	addr, err := HashToB32Address(hash)
//	// addr = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p"
//
// This address can then be used with NAMING LOOKUP to obtain the full
// destination for replying to the datagram sender.
//
// Returns error if:
//   - Hash is not exactly 44 bytes
//   - Hash cannot be base64-decoded
//   - Decoded hash is not exactly 32 bytes
func HashToB32Address(hash string) (string, error) {
	// Validate input length
	if len(hash) != Datagram3Base64HashSize {
		return "", ErrInvalidHashLength
	}

	// Base64-decode to 32 bytes binary
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidHashFormat, err)
	}

	if len(decoded) != Datagram3HashSize {
		return "", ErrInvalidHashLength
	}

	// Base32-encode to 52 characters (lowercase, no padding)
	// I2P uses lowercase base32 without padding
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded)
	encoded = strings.ToLower(encoded)

	// Append .b32.i2p suffix
	return encoded + ".b32.i2p", nil
}

// ValidateHash checks if a string is a valid 44-byte base64-encoded hash
// as used in DATAGRAM3 source identification.
//
// Returns true if the hash:
//   - Is exactly 44 bytes long
//   - Can be base64-decoded to exactly 32 bytes
func ValidateHash(hash string) bool {
	if len(hash) != Datagram3Base64HashSize {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}

	return len(decoded) == Datagram3HashSize
}

// Error definitions for Datagram3Session.
var (
	// ErrDatagram3SendNotImplemented indicates DATAGRAM3 SEND is not available
	// because no DatagramConn has been configured. The DatagramConn must be set
	// via SetDatagramConn() after the I2CP session is established.
	ErrDatagram3SendNotImplemented = errors.New("DATAGRAM3 SEND not available: DatagramConn not configured")

	// ErrInvalidHashLength indicates the hash is not the expected 44-byte base64 size.
	ErrInvalidHashLength = errors.New("invalid hash length: expected 44-byte base64 (32 bytes binary)")

	// ErrInvalidHashFormat indicates the hash could not be base64-decoded.
	ErrInvalidHashFormat = errors.New("invalid hash format: not valid base64")
)

// Verify Datagram3SessionImpl implements DatagramSession interface.
var _ DatagramSession = (*Datagram3SessionImpl)(nil)
