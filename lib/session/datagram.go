// Package session implements SAM v3.0-3.3 session management.
// This file implements DatagramSessionImpl for DATAGRAM session handling
// per SAM 3.0 DATAGRAM SEND/RECEIVED commands for repliable authenticated datagrams.
package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/go-i2p/go-datagrams"
)

// DatagramSessionImpl implements the DatagramSession interface.
// It embeds *BaseSession and provides repliable datagram functionality.
//
// Per PLAN.md Phase 4 and SAM 3.0 specification:
//   - Supports DATAGRAM SEND for sending repliable datagrams
//   - Supports receiving repliable datagrams via channel or forwarding
//   - Repliable datagrams include sender's destination and signature
//   - FROM_PORT/TO_PORT options supported per SAM 3.2+
//   - Uses UDP port 7655 for datagram transmission
//
// Repliable datagrams (DATAGRAM) differ from anonymous datagrams (RAW) in that
// they include the sender's destination and are signed, enabling replies.
type DatagramSessionImpl struct {
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

	// datagramConn is the go-datagrams connection for sending datagrams.
	// This wraps an I2CP session and handles protocol-specific envelope formatting.
	datagramConn *datagrams.DatagramConn

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// receiveWg waits for receive goroutines to complete
	receiveWg sync.WaitGroup
}

// NewDatagramSession creates a new DATAGRAM session for repliable datagrams.
//
// Parameters:
//   - id: Unique session identifier (nickname)
//   - dest: I2P destination for this session
//   - conn: Control connection (session dies when this closes)
//   - cfg: Session configuration (port settings, etc.)
//
// Per SAM 3.0 specification, the session starts in Creating state
// and must be activated after setup completes.
func NewDatagramSession(
	id string,
	dest *Destination,
	conn net.Conn,
	cfg *SessionConfig,
) *DatagramSessionImpl {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure we have a config with valid defaults
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}

	return &DatagramSessionImpl{
		BaseSession: NewBaseSession(id, StyleDatagram, dest, conn, cfg),
		receiveChan: make(chan ReceivedDatagram, 100),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Send transmits a repliable datagram to the specified destination.
// Implements SAM DATAGRAM SEND command per SAM 3.0 specification.
//
// Parameters:
//   - dest: Base64-encoded I2P destination or .i2p hostname
//   - data: Datagram payload (minimum 1 byte, max ~31KB for reliability)
//   - opts: Send options (FromPort, ToPort, and SAM 3.3 options)
//
// Returns error if:
//   - Session is not active
//   - Data is empty or too large
//   - Destination lookup fails
//   - Send operation fails
//
// Per SAM specification, DATAGRAM SEND on bridge socket is supported.
// As of SAM 3.2, FROM_PORT and TO_PORT options are supported.
// As of SAM 3.3, SEND_TAGS, TAG_THRESHOLD, EXPIRES, SEND_LEASESET options
// are supported and passed via opts. When go-i2cp integration is complete,
// these will be passed to SendMessageExpires() with BuildSendMessageFlags().
func (d *DatagramSessionImpl) Send(dest string, data []byte, opts DatagramSendOptions) error {
	d.mu.RLock()
	if d.Status() != StatusActive {
		d.mu.RUnlock()
		return ErrSessionNotActive
	}
	datagramConn := d.datagramConn
	d.mu.RUnlock()

	// Validate data
	if len(data) == 0 {
		return errors.New("data cannot be empty")
	}
	if len(data) > MaxDatagramSize {
		return errors.New("data exceeds maximum datagram size")
	}

	// Validate ports if specified
	if opts.FromPort < 0 || opts.FromPort > 65535 {
		return ErrInvalidPort
	}
	if opts.ToPort < 0 || opts.ToPort > 65535 {
		return ErrInvalidPort
	}

	// Check if datagramConn is configured
	if datagramConn == nil {
		return ErrDatagramSendNotImplemented
	}

	// Determine destination port (use ToPort if specified, otherwise 0)
	toPort := uint16(opts.ToPort)

	// Send the datagram using go-datagrams
	// DATAGRAM uses ProtocolDatagram1 (17) for repliable authenticated datagrams
	err := datagramConn.SendTo(data, dest, toPort)
	if err != nil {
		return fmt.Errorf("failed to send datagram: %w", err)
	}

	return nil
}

// Receive returns a channel for incoming repliable datagrams.
// Each received datagram includes source destination, ports, and data.
// Implements DatagramSession.Receive() per SAM 3.0 specification.
//
// The channel is buffered and will drop datagrams if not consumed.
// The channel is closed when the session is closed.
func (d *DatagramSessionImpl) Receive() <-chan ReceivedDatagram {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.receiveChan
}

// SetForwarding configures UDP forwarding for incoming datagrams.
// When set, incoming datagrams are forwarded to host:port instead of
// being delivered through the Receive() channel.
//
// Parameters:
//   - host: Hostname or IP to forward datagrams to (default "127.0.0.1")
//   - port: Port to forward datagrams to
//
// Per SAM specification, when PORT is set in SESSION CREATE, datagrams
// are forwarded. Forwarded datagrams are prepended with:
//
//	$destination\n
//	[datagram data]
func (d *DatagramSessionImpl) SetForwarding(host string, port int) error {
	if d.Status() != StatusActive && d.Status() != StatusCreating {
		return ErrSessionNotActive
	}

	if port < 0 || port > 65535 {
		return ErrInvalidPort
	}

	if host == "" {
		host = "127.0.0.1"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.forwardHost = host
	d.forwardPort = port

	return nil
}

// ForwardingAddr returns the UDP address for forwarding, if configured.
// Returns nil if forwarding is not configured.
func (d *DatagramSessionImpl) ForwardingAddr() net.Addr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.forwardAddr
}

// IsForwarding returns true if forwarding is configured.
func (d *DatagramSessionImpl) IsForwarding() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.forwardPort > 0
}

// deliverDatagram handles an incoming repliable datagram by either forwarding
// it to the configured host:port or delivering it through the Receive channel.
//
// This method is called by the UDP listener when a datagram arrives
// for this session.
func (d *DatagramSessionImpl) deliverDatagram(dg ReceivedDatagram) {
	d.mu.RLock()
	forwarding := d.forwardPort > 0
	d.mu.RUnlock()

	if forwarding {
		d.forwardDatagram(dg)
		return
	}

	// Deliver to receive channel (non-blocking, drop if full)
	select {
	case d.receiveChan <- dg:
	default:
		// Channel full, drop datagram
		// This is expected behavior per SAM spec - datagrams are unreliable
	}
}

// forwardDatagram sends a received datagram to the configured forwarding address.
// Prepends the source destination as per SAM specification.
func (d *DatagramSessionImpl) forwardDatagram(dg ReceivedDatagram) {
	d.mu.RLock()
	host := d.forwardHost
	port := d.forwardPort
	udpConn := d.udpConn
	d.mu.RUnlock()

	if host == "" || port == 0 || udpConn == nil {
		return
	}

	// Resolve forwarding address
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return
	}

	// Prepend source destination line: $destination\n
	// Per SAM specification, forwarded datagrams include source destination
	header := dg.Source + "\n"
	payload := append([]byte(header), dg.Data...)

	// Send to forwarding address (best effort, ignore errors per SAM spec)
	_, _ = udpConn.WriteTo(payload, addr)
}

// SetUDPConn sets the UDP connection for forwarding.
// This should be called during session setup when forwarding is enabled.
func (d *DatagramSessionImpl) SetUDPConn(conn net.PacketConn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.udpConn = conn
}

// SetDatagramConn sets the go-datagrams connection for sending datagrams.
// This should be called during session setup after the I2CP session is established.
// The DatagramConn should be created with ProtocolDatagram1 for DATAGRAM sessions.
func (d *DatagramSessionImpl) SetDatagramConn(conn *datagrams.DatagramConn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.datagramConn = conn
}

// DatagramConn returns the go-datagrams connection, or nil if not configured.
func (d *DatagramSessionImpl) DatagramConn() *datagrams.DatagramConn {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.datagramConn
}

// Close terminates the session and releases all resources.
// Overrides BaseSession.Close to perform DATAGRAM-specific cleanup.
func (d *DatagramSessionImpl) Close() error {
	d.mu.Lock()
	status := d.Status()
	if status == StatusClosed || status == StatusClosing {
		d.mu.Unlock()
		return nil
	}
	d.mu.Unlock()

	// Cancel context to stop all goroutines
	d.cancel()

	// Wait for receive goroutines to finish
	d.receiveWg.Wait()

	// Close receive channel
	d.mu.Lock()
	if d.receiveChan != nil {
		close(d.receiveChan)
		d.receiveChan = nil
	}
	// Close UDP connection if we own it
	if d.udpConn != nil {
		d.udpConn.Close()
		d.udpConn = nil
	}
	// Close datagram connection if we own it
	if d.datagramConn != nil {
		d.datagramConn.Close()
		d.datagramConn = nil
	}
	d.mu.Unlock()

	// Close base session (control connection) - this sets status to CLOSED
	return d.BaseSession.Close()
}

// MaxDatagramSize is the maximum size for repliable datagrams per SAM specification.
// Repliable datagrams can be up to 31744 bytes due to signature overhead.
// For reliability, staying under 11KB is recommended.
const MaxDatagramSize = 31744

// ErrDatagramSendNotImplemented indicates DATAGRAM SEND is not available
// because no DatagramConn has been configured. The DatagramConn must be set
// via SetDatagramConn() after the I2CP session is established.
var ErrDatagramSendNotImplemented = errors.New("DATAGRAM SEND not available: DatagramConn not configured")

// Ensure DatagramSessionImpl implements DatagramSession interface.
var _ DatagramSession = (*DatagramSessionImpl)(nil)
