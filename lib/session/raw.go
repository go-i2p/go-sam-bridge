// Package session implements SAM v3.0-3.3 session management.
// This file implements RawSessionImpl for RAW session handling
// per SAM 3.1 RAW SEND/RECEIVED commands for anonymous datagrams.
package session

import (
	"context"
	"errors"
	"net"
	"sync"
)

// RawSessionImpl implements the RawSession interface.
// It embeds *BaseSession and provides anonymous datagram (RAW) functionality.
//
// Per PLAN.md Phase 3 and SAM 3.1 specification:
//   - Supports RAW SEND for sending anonymous datagrams
//   - Supports receiving anonymous datagrams via channel or forwarding
//   - PROTOCOL option (default 18, range 0-255 excluding 6, 17, 19, 20)
//   - HEADER option enables FROM_PORT/TO_PORT/PROTOCOL header on forwarding
//   - Uses UDP port 7655 for datagram transmission
//
// Anonymous datagrams (RAW) differ from repliable datagrams (DATAGRAM) in that
// they do not include the sender's destination or signature, providing anonymity
// at the cost of non-repliability.
type RawSessionImpl struct {
	*BaseSession

	mu sync.RWMutex

	// Protocol is the I2CP protocol number for this RAW session.
	// Default is 18; valid range 0-255 excluding 6, 17, 19, 20.
	protocol int

	// headerEnabled enables header prepending for forwarded datagrams.
	// When true, forwarded datagrams include FROM_PORT/TO_PORT/PROTOCOL line.
	headerEnabled bool

	// Forwarding configuration for incoming datagrams
	forwardHost string
	forwardPort int
	forwardAddr net.Addr

	// Receive channel for incoming raw datagrams (non-forwarding mode)
	receiveChan chan ReceivedRawDatagram

	// PacketConn for sending/receiving UDP datagrams
	udpConn net.PacketConn

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// receiveWg waits for receive goroutines to complete
	receiveWg sync.WaitGroup
}

// NewRawSession creates a new RAW session for anonymous datagrams.
//
// Parameters:
//   - id: Unique session identifier (nickname)
//   - dest: I2P destination for this session
//   - conn: Control connection (session dies when this closes)
//   - cfg: Session configuration (protocol, header settings, etc.)
//
// Per SAM 3.1 specification, the session starts in Creating state
// and must be activated after setup completes.
func NewRawSession(
	id string,
	dest *Destination,
	conn net.Conn,
	cfg *SessionConfig,
) *RawSessionImpl {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure we have a config with valid defaults
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}

	// Use protocol from config or default
	protocol := cfg.Protocol
	if protocol == 0 {
		protocol = DefaultRawProtocol
	}

	return &RawSessionImpl{
		BaseSession:   NewBaseSession(id, StyleRaw, dest, conn, cfg),
		protocol:      protocol,
		headerEnabled: cfg.HeaderEnabled,
		receiveChan:   make(chan ReceivedRawDatagram, 100),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Protocol returns the I2CP protocol number for this RAW session.
// Default is 18; valid range 0-255 excluding 6, 17, 19, 20.
// Implements RawSession.Protocol() per SAM 3.1 specification.
func (r *RawSessionImpl) Protocol() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.protocol
}

// HeaderEnabled returns true if HEADER=true was specified.
// When true, forwarded datagrams include FROM_PORT/TO_PORT/PROTOCOL header.
// Implements RawSession.HeaderEnabled() per SAM 3.2 specification.
func (r *RawSessionImpl) HeaderEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.headerEnabled
}

// Send transmits an anonymous raw datagram to the specified destination.
// Implements SAM RAW SEND command per SAM 3.1 specification.
//
// Parameters:
//   - dest: Base64-encoded I2P destination or .i2p hostname
//   - data: Datagram payload (minimum 1 byte, max ~11KB recommended for reliability)
//   - opts: Send options (FromPort, ToPort, Protocol override)
//
// Returns error if:
//   - Session is not active
//   - Data is empty or too large
//   - Destination lookup fails
//   - Send operation fails
//
// Per SAM specification, RAW SEND on bridge socket was added in SAM 3.1.
// As of SAM 3.2, FROM_PORT, TO_PORT, and PROTOCOL options are supported.
func (r *RawSessionImpl) Send(dest string, data []byte, opts RawSendOptions) error {
	r.mu.RLock()
	if r.Status() != StatusActive {
		r.mu.RUnlock()
		return ErrSessionNotActive
	}
	r.mu.RUnlock()

	// Validate data
	if len(data) == 0 {
		return errors.New("data cannot be empty")
	}
	if len(data) > MaxRawDatagramSize {
		return errors.New("data exceeds maximum raw datagram size")
	}

	// Determine protocol to use (opts override session default)
	protocol := opts.Protocol
	if protocol == 0 {
		protocol = r.Protocol()
	}

	// Validate protocol is not disallowed
	if isDisallowedProtocol(protocol) {
		return ErrInvalidProtocol
	}

	// TODO: Integrate with go-datagrams library to actually send the datagram.
	// This requires:
	// 1. Resolving the destination (base64 or hostname)
	// 2. Constructing the raw datagram with proper I2CP framing
	// 3. Sending via I2CP session
	//
	// For now, return ErrNotImplemented to indicate the stub.
	// This will be fully implemented when integrating go-datagrams.
	return ErrRawSendNotImplemented
}

// Receive returns a channel for incoming raw datagrams.
// Each received datagram includes FromPort, ToPort, Protocol, and Data.
// Implements RawSession.Receive() per SAM 3.1 specification.
//
// The channel is buffered and will drop datagrams if not consumed.
// The channel is closed when the session is closed.
func (r *RawSessionImpl) Receive() <-chan ReceivedRawDatagram {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.receiveChan
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
// are forwarded. When HEADER=true, forwarded datagrams are prepended with:
//
//	FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n
func (r *RawSessionImpl) SetForwarding(host string, port int) error {
	if r.Status() != StatusActive && r.Status() != StatusCreating {
		return ErrSessionNotActive
	}

	if port < 0 || port > 65535 {
		return ErrInvalidPort
	}

	if host == "" {
		host = "127.0.0.1"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.forwardHost = host
	r.forwardPort = port

	return nil
}

// ForwardingAddr returns the UDP address for forwarding, if configured.
// Returns nil if forwarding is not configured.
func (r *RawSessionImpl) ForwardingAddr() net.Addr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.forwardAddr
}

// IsForwarding returns true if forwarding is configured.
func (r *RawSessionImpl) IsForwarding() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.forwardPort > 0
}

// deliverDatagram handles an incoming raw datagram by either forwarding
// it to the configured host:port or delivering it through the Receive channel.
//
// This method is called by the UDP listener when a datagram arrives
// for this session.
func (r *RawSessionImpl) deliverDatagram(dg ReceivedRawDatagram) {
	r.mu.RLock()
	forwarding := r.forwardPort > 0
	headerEnabled := r.headerEnabled
	r.mu.RUnlock()

	if forwarding {
		r.forwardDatagram(dg, headerEnabled)
		return
	}

	// Deliver to receive channel (non-blocking, drop if full)
	select {
	case r.receiveChan <- dg:
	default:
		// Channel full, drop datagram
		// This is expected behavior per SAM spec - datagrams are unreliable
	}
}

// forwardDatagram sends a received datagram to the configured forwarding address.
// If headerEnabled is true, prepends the header line.
func (r *RawSessionImpl) forwardDatagram(dg ReceivedRawDatagram, headerEnabled bool) {
	r.mu.RLock()
	host := r.forwardHost
	port := r.forwardPort
	udpConn := r.udpConn
	r.mu.RUnlock()

	if host == "" || port == 0 || udpConn == nil {
		return
	}

	// Resolve forwarding address
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, formatPort(port)))
	if err != nil {
		return
	}

	var payload []byte
	if headerEnabled {
		// Prepend header line: FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n
		header := formatRawHeader(dg.FromPort, dg.ToPort, dg.Protocol)
		payload = append([]byte(header), dg.Data...)
	} else {
		payload = dg.Data
	}

	// Send to forwarding address (best effort, ignore errors per SAM spec)
	_, _ = udpConn.WriteTo(payload, addr)
}

// SetUDPConn sets the UDP connection for forwarding.
// This should be called during session setup when forwarding is enabled.
func (r *RawSessionImpl) SetUDPConn(conn net.PacketConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.udpConn = conn
}

// Close terminates the session and releases all resources.
// Overrides BaseSession.Close to perform RAW-specific cleanup.
func (r *RawSessionImpl) Close() error {
	r.mu.Lock()
	status := r.Status()
	if status == StatusClosed || status == StatusClosing {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	// Cancel context to stop all goroutines
	r.cancel()

	// Wait for receive goroutines to finish
	r.receiveWg.Wait()

	// Close receive channel
	r.mu.Lock()
	if r.receiveChan != nil {
		close(r.receiveChan)
		r.receiveChan = nil
	}
	// Close UDP connection if we own it
	if r.udpConn != nil {
		r.udpConn.Close()
		r.udpConn = nil
	}
	r.mu.Unlock()

	// Close base session (control connection) - this sets status to CLOSED
	return r.BaseSession.Close()
}

// formatPort converts port number to string.
func formatPort(port int) string {
	return string(rune('0'+port/10000)) +
		string(rune('0'+(port/1000)%10)) +
		string(rune('0'+(port/100)%10)) +
		string(rune('0'+(port/10)%10)) +
		string(rune('0'+port%10))
}

// formatRawHeader creates the header line for forwarded raw datagrams.
// Format: "FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n"
func formatRawHeader(fromPort, toPort, protocol int) string {
	return "FROM_PORT=" + itoa(fromPort) +
		" TO_PORT=" + itoa(toPort) +
		" PROTOCOL=" + itoa(protocol) + "\n"
}

// itoa converts an integer to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	var buf [20]byte
	i := len(buf)

	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	if negative {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}

// MaxRawDatagramSize is the maximum size for raw datagrams per SAM specification.
// Raw datagrams can be up to 32768 bytes, but 11KB is recommended for reliability.
const MaxRawDatagramSize = 32768

// ErrRawSendNotImplemented indicates RAW SEND is not yet fully implemented.
// This is a placeholder until go-datagrams integration is complete.
var ErrRawSendNotImplemented = errors.New("RAW SEND not fully implemented: awaiting go-datagrams integration")

// Ensure RawSessionImpl implements RawSession interface.
var _ RawSession = (*RawSessionImpl)(nil)
