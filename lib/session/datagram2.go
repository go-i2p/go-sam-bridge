// Package session implements SAM v3.0-3.3 session management.
// This file implements Datagram2SessionImpl for DATAGRAM2 session handling
// per SAM 3.3 specification for authenticated, repliable datagrams with
// replay protection and offline signature support.
package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Datagram2SessionImpl implements the DatagramSession interface for DATAGRAM2 style.
// It embeds *BaseSession and provides enhanced datagram functionality.
//
// Per SAMv3.md and PLAN.md Phase 5:
//   - Authenticated and repliable datagrams (like DATAGRAM)
//   - Replay protection via nonce/timestamp tracking
//   - Offline signature support for offline-signed destinations
//   - Same SAM API as DATAGRAM - only I2CP format differs
//
// DATAGRAM2 is intended to replace repliable datagrams for new applications
// that don't require backward compatibility. The main advantages are:
//   - Replay protection not present in DATAGRAM
//   - Offline signature support (DATAGRAM does not support this)
type Datagram2SessionImpl struct {
	*BaseSession

	mu sync.RWMutex

	// Forwarding configuration for incoming datagrams
	forwardHost string
	forwardPort int
	forwardAddr net.Addr

	// Receive channel for incoming datagrams (non-forwarding mode)
	receiveChan chan ReceivedDatagram

	// PacketConn for sending/receiving UDP datagrams
	udpConn net.PacketConn

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// receiveWg waits for receive goroutines to complete
	receiveWg sync.WaitGroup

	// Replay protection: track seen nonces to prevent replay attacks
	// Map of nonce -> expiration time for cleanup
	seenNonces   map[uint64]time.Time
	nonceExpiry  time.Duration
	cleanupMu    sync.Mutex
	cleanupTimer *time.Timer

	// offlineSignature stores the offline signature data if provided
	offlineSignature []byte
}

// DefaultDatagram2NonceExpiry is the default time to keep nonces for replay protection.
// Nonces older than this are cleaned up to prevent unbounded memory growth.
const DefaultDatagram2NonceExpiry = 10 * time.Minute

// MaxDatagram2Size is the maximum payload size for DATAGRAM2.
// Same as DATAGRAM - ~31KB for reliability per SAM specification.
const MaxDatagram2Size = 31744

// NewDatagram2Session creates a new DATAGRAM2 session for authenticated,
// repliable datagrams with replay protection.
//
// Parameters:
//   - id: Unique session identifier (nickname)
//   - dest: I2P destination for this session
//   - conn: Control connection (session dies when this closes)
//   - cfg: Session configuration (port settings, etc.)
//
// Per SAM specification, the session starts in Creating state
// and must be activated after setup completes.
func NewDatagram2Session(
	id string,
	dest *Destination,
	conn net.Conn,
	cfg *SessionConfig,
) *Datagram2SessionImpl {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure we have a config with valid defaults
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}

	d := &Datagram2SessionImpl{
		BaseSession: NewBaseSession(id, StyleDatagram2, dest, conn, cfg),
		receiveChan: make(chan ReceivedDatagram, 100),
		ctx:         ctx,
		cancel:      cancel,
		seenNonces:  make(map[uint64]time.Time),
		nonceExpiry: DefaultDatagram2NonceExpiry,
	}

	// Start nonce cleanup goroutine
	d.startNonceCleanup()

	return d
}

// Send transmits an authenticated, repliable datagram to the specified destination.
// Implements DatagramSession.Send per SAM specification.
//
// Parameters:
//   - dest: Base64-encoded I2P destination or .i2p hostname
//   - data: Datagram payload (minimum 1 byte, max MaxDatagram2Size)
//   - opts: Send options (FromPort, ToPort)
//
// Returns error if:
//   - Session is not active
//   - Data is empty or too large
//   - Destination lookup fails
//   - Send operation fails
//
// Note: From a SAM perspective, DATAGRAM2 SEND is identical to DATAGRAM SEND.
// The difference is in the underlying I2CP format which includes a nonce for
// replay protection and supports offline signatures.
func (d *Datagram2SessionImpl) Send(dest string, data []byte, opts DatagramSendOptions) error {
	d.mu.RLock()
	if d.Status() != StatusActive {
		d.mu.RUnlock()
		return ErrSessionNotActive
	}
	d.mu.RUnlock()

	// Validate payload size
	if len(data) == 0 {
		return ErrEmptyPayload
	}
	if len(data) > MaxDatagram2Size {
		return ErrPayloadTooLarge
	}

	// TODO: Integrate with go-datagrams library for actual I2P datagram sending.
	// The go-datagrams library should handle:
	// - Nonce generation for replay protection
	// - Offline signature creation if configured
	// - I2CP protocol 17 (repliable datagram) formatting
	//
	// For now, return a stub error indicating not yet implemented.
	return ErrDatagram2SendNotImplemented
}

// Receive returns a channel for incoming datagrams.
// Implements DatagramSession.Receive.
//
// Each received datagram includes source destination, ports, and data.
// Datagrams with replayed nonces are automatically discarded.
func (d *Datagram2SessionImpl) Receive() <-chan ReceivedDatagram {
	return d.receiveChan
}

// ForwardingAddr returns the UDP address for forwarding, if configured.
// Implements DatagramSession.ForwardingAddr.
func (d *Datagram2SessionImpl) ForwardingAddr() net.Addr {
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
func (d *Datagram2SessionImpl) SetForwarding(host string, port int) error {
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
func (d *Datagram2SessionImpl) IsForwarding() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.forwardAddr != nil
}

// SetOfflineSignature sets the offline signature data for this session.
// Offline signatures allow transient keys while keeping long-term identity keys offline.
//
// Per SAMv3.md, DATAGRAM2 supports offline signatures (DATAGRAM does not).
func (d *Datagram2SessionImpl) SetOfflineSignature(sig []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.offlineSignature = make([]byte, len(sig))
	copy(d.offlineSignature, sig)
}

// OfflineSignature returns the offline signature data, or nil if not set.
func (d *Datagram2SessionImpl) OfflineSignature() []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.offlineSignature == nil {
		return nil
	}
	sig := make([]byte, len(d.offlineSignature))
	copy(sig, d.offlineSignature)
	return sig
}

// CheckReplay checks if a nonce has been seen before (replay attack).
// Returns true if the nonce is a replay (should be rejected).
//
// Per SAMv3.md, DATAGRAM2 provides replay protection not present in DATAGRAM.
func (d *Datagram2SessionImpl) CheckReplay(nonce uint64) bool {
	d.cleanupMu.Lock()
	defer d.cleanupMu.Unlock()

	if _, exists := d.seenNonces[nonce]; exists {
		return true // Replay detected
	}

	// Record the nonce with expiration time
	d.seenNonces[nonce] = time.Now().Add(d.nonceExpiry)
	return false
}

// DeliverDatagram handles an incoming datagram, checking for replay and
// delivering to the receive channel or forwarding address.
//
// Parameters:
//   - dg: The received datagram
//   - nonce: The nonce from the datagram (for replay protection)
//
// Returns true if the datagram was delivered, false if it was a replay.
func (d *Datagram2SessionImpl) DeliverDatagram(dg ReceivedDatagram, nonce uint64) bool {
	// Check for replay
	if d.CheckReplay(nonce) {
		return false
	}

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
func (d *Datagram2SessionImpl) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Status() == StatusClosed {
		return nil
	}

	// Cancel context to stop background goroutines
	d.cancel()

	// Stop cleanup timer
	if d.cleanupTimer != nil {
		d.cleanupTimer.Stop()
	}

	// Close UDP connection if open
	if d.udpConn != nil {
		d.udpConn.Close()
		d.udpConn = nil
	}

	// Close receive channel
	close(d.receiveChan)

	// Wait for goroutines to finish
	d.receiveWg.Wait()

	// Close base session
	return d.BaseSession.Close()
}

// startNonceCleanup starts a background goroutine to clean up expired nonces.
func (d *Datagram2SessionImpl) startNonceCleanup() {
	d.cleanupTimer = time.AfterFunc(d.nonceExpiry/2, func() {
		d.cleanupExpiredNonces()
	})
}

// cleanupExpiredNonces removes expired nonces from the tracking map.
func (d *Datagram2SessionImpl) cleanupExpiredNonces() {
	d.cleanupMu.Lock()
	defer d.cleanupMu.Unlock()

	now := time.Now()
	for nonce, expiry := range d.seenNonces {
		if now.After(expiry) {
			delete(d.seenNonces, nonce)
		}
	}

	// Reschedule if session is still active
	d.mu.RLock()
	status := d.Status()
	d.mu.RUnlock()

	if status != StatusClosed {
		d.cleanupTimer = time.AfterFunc(d.nonceExpiry/2, func() {
			d.cleanupExpiredNonces()
		})
	}
}

// Error definitions for Datagram2Session.
var (
	// ErrDatagram2SendNotImplemented indicates the send operation is not yet implemented.
	// TODO: Implement with go-datagrams library integration.
	ErrDatagram2SendNotImplemented = errors.New("DATAGRAM2 send not implemented: pending go-datagrams integration")

	// ErrEmptyPayload indicates the datagram payload is empty.
	ErrEmptyPayload = errors.New("datagram payload cannot be empty")

	// ErrPayloadTooLarge indicates the datagram payload exceeds maximum size.
	ErrPayloadTooLarge = errors.New("datagram payload exceeds maximum size")

	// ErrInvalidForwardingPort indicates an invalid forwarding port.
	ErrInvalidForwardingPort = errors.New("forwarding port must be 1-65535")
)

// Verify Datagram2SessionImpl implements DatagramSession interface.
var _ DatagramSession = (*Datagram2SessionImpl)(nil)
