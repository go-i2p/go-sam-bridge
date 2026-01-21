// Package datagram implements SAM v3.0-3.3 datagram handling.
// This file provides datagram forwarding to client UDP sockets.
package datagram

import (
	"fmt"
	"net"
	"sync"
)

// ForwarderConfig holds configuration for a datagram forwarder.
type ForwarderConfig struct {
	// Host is the target host to forward datagrams to.
	// Default: "127.0.0.1"
	Host string

	// Port is the target port to forward datagrams to.
	// Required: must be > 0
	Port int

	// HeaderEnabled controls whether to prepend header info.
	// When true (SAM 3.2+), forwarded datagrams include:
	// - RAW: "FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n"
	// - DATAGRAM: "$destination\n" is prepended by the bridge itself
	HeaderEnabled bool
}

// Forwarder handles forwarding of received datagrams to client UDP sockets.
// Per SAM specification, when PORT is set in SESSION CREATE, incoming
// datagrams are forwarded to the specified host:port instead of being
// delivered on the control socket.
//
// Thread-safe for concurrent use.
type Forwarder struct {
	mu sync.RWMutex

	config ForwarderConfig
	conn   net.PacketConn
	addr   net.Addr

	closed bool
}

// NewForwarder creates a new datagram forwarder with the given configuration.
// The forwarder will send datagrams to config.Host:config.Port.
//
// Parameters:
//   - config: Forwarding configuration with host, port, and header settings
//
// Returns nil if port is invalid (must be > 0).
func NewForwarder(config ForwarderConfig) *Forwarder {
	if config.Port <= 0 || config.Port > 65535 {
		return nil
	}

	if config.Host == "" {
		config.Host = "127.0.0.1"
	}

	return &Forwarder{
		config: config,
	}
}

// Start initializes the forwarder by resolving the target address
// and creating the UDP connection for sending.
//
// Returns error if address resolution fails or connection cannot be created.
func (f *Forwarder) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return ErrForwarderClosed
	}

	if f.conn != nil {
		return fmt.Errorf("forwarder already started")
	}

	// Resolve target address
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(f.config.Host, fmt.Sprintf("%d", f.config.Port)))
	if err != nil {
		return fmt.Errorf("failed to resolve forwarding address: %w", err)
	}
	f.addr = addr

	// Create UDP socket for sending
	// We bind to any local port (":0") for outbound datagrams
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to create forwarder socket: %w", err)
	}
	f.conn = conn

	return nil
}

// Close shuts down the forwarder and releases resources.
// Safe to call multiple times.
func (f *Forwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil
	}
	f.closed = true

	if f.conn != nil {
		err := f.conn.Close()
		f.conn = nil
		return err
	}

	return nil
}

// ForwardRaw forwards a raw datagram to the configured client address.
// If HeaderEnabled is true, prepends the header line per SAM 3.2 spec:
//
//	FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n
//	$payload
//
// Parameters:
//   - fromPort: Source I2CP port (0-65535)
//   - toPort: Destination I2CP port (0-65535)
//   - protocol: I2CP protocol number (0-255)
//   - payload: Datagram payload bytes
//
// Returns error if forwarder is not started or send fails.
// Per SAM specification, datagram delivery is best-effort;
// callers may choose to ignore errors.
func (f *Forwarder) ForwardRaw(fromPort, toPort, protocol int, payload []byte) error {
	f.mu.RLock()
	conn := f.conn
	addr := f.addr
	headerEnabled := f.config.HeaderEnabled
	closed := f.closed
	f.mu.RUnlock()

	if closed {
		return ErrForwarderClosed
	}

	if conn == nil || addr == nil {
		return ErrForwarderNotStarted
	}

	// Build the forwarded message
	var data []byte
	if headerEnabled {
		header := FormatRawHeader(fromPort, toPort, protocol)
		data = make([]byte, len(header)+len(payload))
		copy(data, header)
		copy(data[len(header):], payload)
	} else {
		data = payload
	}

	// Send to client (best effort, per SAM spec)
	_, err := conn.WriteTo(data, addr)
	return err
}

// ForwardDatagram forwards a repliable datagram to the configured client address.
// Prepends the source destination per SAM spec:
//
//	$destination\n
//	$payload
//
// Parameters:
//   - destination: Base64-encoded source destination
//   - payload: Datagram payload bytes
//
// Returns error if forwarder is not started or send fails.
func (f *Forwarder) ForwardDatagram(destination string, payload []byte) error {
	f.mu.RLock()
	conn := f.conn
	addr := f.addr
	closed := f.closed
	f.mu.RUnlock()

	if closed {
		return ErrForwarderClosed
	}

	if conn == nil || addr == nil {
		return ErrForwarderNotStarted
	}

	// Format: "$destination\n$payload"
	header := destination + "\n"
	data := make([]byte, len(header)+len(payload))
	copy(data, header)
	copy(data[len(header):], payload)

	_, err := conn.WriteTo(data, addr)
	return err
}

// ForwardDatagramWithPorts forwards a repliable datagram with port information.
// Used for SAM 3.2+ with FROM_PORT and TO_PORT.
//
// Format sent:
//
//	$destination FROM_PORT=nnn TO_PORT=nnn\n
//	$payload
//
// Parameters:
//   - destination: Base64-encoded source destination
//   - fromPort: Source I2CP port (0-65535)
//   - toPort: Destination I2CP port (0-65535)
//   - payload: Datagram payload bytes
func (f *Forwarder) ForwardDatagramWithPorts(destination string, fromPort, toPort int, payload []byte) error {
	f.mu.RLock()
	conn := f.conn
	addr := f.addr
	closed := f.closed
	f.mu.RUnlock()

	if closed {
		return ErrForwarderClosed
	}

	if conn == nil || addr == nil {
		return ErrForwarderNotStarted
	}

	// Format: "$destination FROM_PORT=nnn TO_PORT=nnn\n$payload"
	header := FormatDatagramHeaderWithPorts(destination, fromPort, toPort)
	data := make([]byte, len(header)+len(payload))
	copy(data, header)
	copy(data[len(header):], payload)

	_, err := conn.WriteTo(data, addr)
	return err
}

// SetConnection sets a custom PacketConn for the forwarder.
// This is useful for testing or when sharing a connection.
// Must be called before Start() or will replace the existing connection.
func (f *Forwarder) SetConnection(conn net.PacketConn, addr net.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conn = conn
	f.addr = addr
}

// IsStarted returns true if the forwarder has been started.
func (f *Forwarder) IsStarted() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.conn != nil && !f.closed
}

// Addr returns the target address for forwarding.
func (f *Forwarder) Addr() net.Addr {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.addr
}

// FormatRawHeader formats the header line for RAW datagram forwarding.
// Per SAM 3.2: "FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n"
func FormatRawHeader(fromPort, toPort, protocol int) string {
	return fmt.Sprintf("FROM_PORT=%d TO_PORT=%d PROTOCOL=%d\n", fromPort, toPort, protocol)
}

// FormatDatagramHeaderWithPorts formats the header for DATAGRAM forwarding with ports.
// Per SAM 3.2: "$destination FROM_PORT=nnn TO_PORT=nnn\n"
func FormatDatagramHeaderWithPorts(destination string, fromPort, toPort int) string {
	return fmt.Sprintf("%s FROM_PORT=%d TO_PORT=%d\n", destination, fromPort, toPort)
}

// Error definitions for forwarder.
var (
	// ErrForwarderClosed is returned when operations are attempted on a closed forwarder.
	ErrForwarderClosed = fmt.Errorf("forwarder is closed")

	// ErrForwarderNotStarted is returned when forwarding is attempted before Start().
	ErrForwarderNotStarted = fmt.Errorf("forwarder not started")
)
