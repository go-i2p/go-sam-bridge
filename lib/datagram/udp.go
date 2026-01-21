// Package datagram implements UDP datagram handling for SAM port 7655.
// This file provides the UDP listener for receiving datagrams from SAM clients
// per SAMv3.md specification.
//
// Per SAM 3.0-3.3 specification, datagrams sent through port 7655 have a first line
// containing: version nickname destination [options...] followed by the payload.
package datagram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// Common errors for UDP datagram handling
var (
	ErrInvalidDatagram  = errors.New("invalid datagram format")
	ErrSessionNotFound  = errors.New("session not found")
	ErrInvalidVersion   = errors.New("invalid SAM version")
	ErrMissingNickname  = errors.New("missing session nickname")
	ErrMissingDest      = errors.New("missing destination")
	ErrDatagramTooSmall = errors.New("datagram too small")
	ErrListenerClosed   = errors.New("listener closed")
	ErrInvalidPort      = errors.New("invalid port value")
	ErrInvalidProtocol  = errors.New("invalid protocol value")
)

// DefaultUDPPort is the default UDP port for SAM datagrams per specification.
const DefaultUDPPort = 7655

// MaxDatagramSize is the maximum size of a UDP datagram.
// I2P datagrams will never be larger than 65536 per SAMv3.md.
const MaxDatagramSize = 65536

// DatagramHeader contains parsed header information from incoming datagrams.
// Per SAMv3.md, the first line format is:
// 3.x $nickname $destination [FROM_PORT=nnn] [TO_PORT=nnn] [PROTOCOL=nnn] [options...]
type DatagramHeader struct {
	// Version is the SAM version (e.g., "3.0", "3.1", "3.2", "3.3").
	// As of SAM 3.2, any "3.x" is allowed.
	Version string

	// Nickname is the session ID that will be used for sending.
	Nickname string

	// Destination is the target I2P destination (Base64, hostname, or b32).
	Destination string

	// FromPort overrides session default source port (SAM 3.2+).
	FromPort int

	// ToPort overrides session default destination port (SAM 3.2+).
	ToPort int

	// Protocol overrides session default protocol for RAW sessions (SAM 3.2+).
	Protocol int

	// SendTags is the number of session tags to send (SAM 3.3+).
	SendTags int

	// TagThreshold is the low session tag threshold (SAM 3.3+).
	TagThreshold int

	// Expires is the expiration in seconds from now (SAM 3.3+).
	Expires int

	// SendLeaseSet controls whether to send our leaseset (SAM 3.3+).
	SendLeaseSet *bool
}

// UDPListener listens for UDP datagrams on port 7655 and routes them
// to the appropriate session for sending over I2P.
//
// Per SAMv3.md:
//   - Clients send datagrams with header line followed by payload
//   - First line is discarded by SAM before sending payload to destination
//   - Session must exist and match the nickname in the header
type UDPListener struct {
	mu sync.RWMutex

	// conn is the UDP connection for receiving datagrams.
	// Uses net.PacketConn interface per project networking guidelines.
	conn net.PacketConn

	// registry provides access to sessions by nickname.
	registry session.Registry

	// addr is the listening address.
	addr string

	// ctx controls the listener lifecycle.
	ctx    context.Context
	cancel context.CancelFunc

	// wg tracks running goroutines.
	wg sync.WaitGroup

	// closed indicates if the listener has been closed.
	closed bool

	// onDatagram is called for each valid datagram received (for testing/metrics).
	onDatagram func(header *DatagramHeader, payload []byte, from net.Addr)
}

// NewUDPListener creates a new UDP listener for SAM datagrams.
//
// Parameters:
//   - addr: The address to listen on (e.g., ":7655" or "127.0.0.1:7655")
//   - registry: Session registry for looking up sessions by nickname
//
// Per SAMv3.md, the default UDP port is 7655 and default bind is 127.0.0.1.
func NewUDPListener(addr string, registry session.Registry) *UDPListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDPListener{
		addr:     addr,
		registry: registry,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins listening for UDP datagrams.
// This method is non-blocking and starts a goroutine to handle incoming datagrams.
func (l *UDPListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return ErrListenerClosed
	}

	// Prevent double start
	if l.conn != nil {
		return fmt.Errorf("listener already started")
	}

	// Create UDP listener using net.ListenPacket for interface compliance
	conn, err := net.ListenPacket("udp", l.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", l.addr, err)
	}
	l.conn = conn

	// Start receive loop in background
	l.wg.Add(1)
	go l.receiveLoop()

	return nil
}

// receiveLoop continuously receives and processes UDP datagrams.
func (l *UDPListener) receiveLoop() {
	defer l.wg.Done()

	buf := make([]byte, MaxDatagramSize)
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		// Read datagram
		n, addr, err := l.conn.ReadFrom(buf)
		if err != nil {
			// Check if we're shutting down
			select {
			case <-l.ctx.Done():
				return
			default:
				// Log error but continue (connection may be temporarily unavailable)
				continue
			}
		}

		if n == 0 {
			continue
		}

		// Process datagram in the same goroutine for simplicity
		// (can be changed to worker pool if performance requires)
		l.handleDatagram(buf[:n], addr)
	}
}

// handleDatagram processes a received UDP datagram.
func (l *UDPListener) handleDatagram(data []byte, from net.Addr) {
	// Parse header line
	header, payload, err := ParseDatagramHeader(data)
	if err != nil {
		// Invalid datagram - silently drop per SAM behavior
		return
	}

	// Look up session by nickname
	sess := l.registry.Get(header.Nickname)
	if sess == nil {
		// Session not found - silently drop
		return
	}

	// Route to session based on style
	l.routeToSession(sess, header, payload)

	// Call callback if set (for testing/metrics)
	if l.onDatagram != nil {
		l.onDatagram(header, payload, from)
	}
}

// routeToSession routes the datagram to the appropriate session type.
func (l *UDPListener) routeToSession(sess session.Session, header *DatagramHeader, payload []byte) {
	switch sess.Style() {
	case session.StyleRaw:
		l.routeToRawSession(sess, header, payload)
	case session.StyleDatagram:
		l.routeToDatagramSession(sess, header, payload)
	default:
		// Session style doesn't support datagrams - drop
	}
}

// routeToRawSession routes the datagram to a RAW session for sending.
func (l *UDPListener) routeToRawSession(sess session.Session, header *DatagramHeader, payload []byte) {
	rawSess, ok := sess.(session.RawSession)
	if !ok {
		return
	}

	// Build send options from header
	opts := session.RawSendOptions{
		FromPort: header.FromPort,
		ToPort:   header.ToPort,
		Protocol: header.Protocol,
	}

	// Send the raw datagram
	// Error is silently ignored per SAM UDP behavior (no response channel)
	_ = rawSess.Send(header.Destination, payload, opts)
}

// routeToDatagramSession routes the datagram to a DATAGRAM session for sending.
// TODO: Implement when DatagramSession is available in Phase 4.
func (l *UDPListener) routeToDatagramSession(sess session.Session, header *DatagramHeader, payload []byte) {
	// Stub for Phase 4 - DATAGRAM sessions
	// Will be implemented when lib/session/datagram.go is complete
}

// Close stops the UDP listener and releases resources.
func (l *UDPListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	// Signal shutdown
	l.cancel()

	// Close connection
	if l.conn != nil {
		if err := l.conn.Close(); err != nil {
			return err
		}
	}

	// Wait for goroutines
	l.wg.Wait()

	return nil
}

// Addr returns the local address the listener is bound to.
// Returns nil if not started.
func (l *UDPListener) Addr() net.Addr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.conn == nil {
		return nil
	}
	return l.conn.LocalAddr()
}

// ParseDatagramHeader parses the header line from a UDP datagram.
//
// Per SAMv3.md, the first line format is:
//
//	3.x $nickname $destination [FROM_PORT=nnn] [TO_PORT=nnn] [PROTOCOL=nnn] \n
//	[payload data]
//
// The header line is '\n' terminated. Returns the parsed header
// and the remaining payload data.
func ParseDatagramHeader(data []byte) (*DatagramHeader, []byte, error) {
	if len(data) == 0 {
		return nil, nil, ErrDatagramTooSmall
	}

	// Find the newline that terminates the header
	newlineIdx := bytes.IndexByte(data, '\n')
	if newlineIdx == -1 {
		return nil, nil, ErrInvalidDatagram
	}

	// Split into header line and payload
	headerLine := string(data[:newlineIdx])
	payload := data[newlineIdx+1:]

	// Parse the header line
	header, err := parseHeaderLine(headerLine)
	if err != nil {
		return nil, nil, err
	}

	return header, payload, nil
}

// parseHeaderLine parses a single header line into a DatagramHeader.
func parseHeaderLine(line string) (*DatagramHeader, error) {
	// Tokenize by whitespace
	tokens := strings.Fields(line)
	if len(tokens) < 3 {
		return nil, ErrInvalidDatagram
	}

	header := &DatagramHeader{}

	// First token: version (must be 3.x format)
	header.Version = tokens[0]
	if !isValidSAMVersion(header.Version) {
		return nil, ErrInvalidVersion
	}

	// Second token: nickname (session ID)
	header.Nickname = tokens[1]
	if header.Nickname == "" {
		return nil, ErrMissingNickname
	}

	// Third token: destination
	header.Destination = tokens[2]
	if header.Destination == "" {
		return nil, ErrMissingDest
	}

	// Remaining tokens: key=value options
	for i := 3; i < len(tokens); i++ {
		if err := parseHeaderOption(header, tokens[i]); err != nil {
			return nil, err
		}
	}

	return header, nil
}

// isValidSAMVersion checks if the version string is a valid SAM 3.x version.
// Per SAM 3.2, any "3.x" format is allowed. Prior to 3.2, only "3.0" was valid.
func isValidSAMVersion(version string) bool {
	if len(version) < 3 {
		return false
	}
	// Must start with "3."
	if !strings.HasPrefix(version, "3.") {
		return false
	}
	// Rest must be numeric
	rest := version[2:]
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseHeaderOption parses a single KEY=VALUE option from the header.
func parseHeaderOption(header *DatagramHeader, token string) error {
	parts := strings.SplitN(token, "=", 2)
	if len(parts) != 2 {
		// Not a key=value pair, ignore
		return nil
	}

	key := strings.ToUpper(parts[0])
	value := parts[1]

	switch key {
	case "FROM_PORT":
		port, err := strconv.Atoi(value)
		if err != nil || port < 0 || port > 65535 {
			return ErrInvalidPort
		}
		header.FromPort = port

	case "TO_PORT":
		port, err := strconv.Atoi(value)
		if err != nil || port < 0 || port > 65535 {
			return ErrInvalidPort
		}
		header.ToPort = port

	case "PROTOCOL":
		proto, err := strconv.Atoi(value)
		if err != nil || proto < 0 || proto > 255 {
			return ErrInvalidProtocol
		}
		header.Protocol = proto

	case "SEND_TAGS":
		n, err := strconv.Atoi(value)
		if err == nil {
			header.SendTags = n
		}

	case "TAG_THRESHOLD":
		n, err := strconv.Atoi(value)
		if err == nil {
			header.TagThreshold = n
		}

	case "EXPIRES":
		n, err := strconv.Atoi(value)
		if err == nil {
			header.Expires = n
		}

	case "SEND_LEASESET":
		val := strings.ToLower(value) == "true"
		header.SendLeaseSet = &val
	}

	return nil
}

// FormatDatagramHeader formats a DatagramHeader back to the wire format.
// This is useful for testing and debugging.
func FormatDatagramHeader(h *DatagramHeader) string {
	var sb strings.Builder
	sb.WriteString(h.Version)
	sb.WriteString(" ")
	sb.WriteString(h.Nickname)
	sb.WriteString(" ")
	sb.WriteString(h.Destination)

	if h.FromPort != 0 {
		sb.WriteString(fmt.Sprintf(" FROM_PORT=%d", h.FromPort))
	}
	if h.ToPort != 0 {
		sb.WriteString(fmt.Sprintf(" TO_PORT=%d", h.ToPort))
	}
	if h.Protocol != 0 {
		sb.WriteString(fmt.Sprintf(" PROTOCOL=%d", h.Protocol))
	}
	if h.SendTags != 0 {
		sb.WriteString(fmt.Sprintf(" SEND_TAGS=%d", h.SendTags))
	}
	if h.TagThreshold != 0 {
		sb.WriteString(fmt.Sprintf(" TAG_THRESHOLD=%d", h.TagThreshold))
	}
	if h.Expires != 0 {
		sb.WriteString(fmt.Sprintf(" EXPIRES=%d", h.Expires))
	}
	if h.SendLeaseSet != nil {
		sb.WriteString(fmt.Sprintf(" SEND_LEASESET=%t", *h.SendLeaseSet))
	}

	return sb.String()
}
