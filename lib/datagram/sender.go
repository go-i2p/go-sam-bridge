// Package datagram implements UDP datagram handling for SAM port 7655.
// This file provides the DatagramSender interface and implementation for
// sending datagrams via go-datagrams library integration.

package datagram

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// DatagramSender provides the interface for sending datagrams over I2P.
// Implementations wrap go-datagrams for actual I2P network communication.
type DatagramSender interface {
	// SendDatagram sends a repliable datagram (DATAGRAM style).
	// The datagram includes sender destination and signature for reply capability.
	SendDatagram(dest string, payload []byte, opts DatagramSendOptions) error

	// SendRaw sends a raw datagram (RAW style).
	// Raw datagrams have no envelope overhead but cannot be replied to.
	SendRaw(dest string, payload []byte, opts RawSendOptions) error

	// Close releases resources.
	Close() error
}

// DatagramSendOptions contains options for sending repliable datagrams.
// These map to SAM 3.0-3.3 datagram options.
type DatagramSendOptions struct {
	// FromPort is the source port (SAM 3.2+).
	FromPort int

	// ToPort is the destination port (SAM 3.2+).
	ToPort int

	// SendTags is the number of session tags to send (SAM 3.3+).
	SendTags int

	// TagThreshold is the low session tag threshold (SAM 3.3+).
	TagThreshold int

	// Expires is the expiration in seconds from now (SAM 3.3+).
	Expires int

	// SendLeaseSet controls whether to send our leaseset (SAM 3.3+).
	SendLeaseSet *bool
}

// RawSendOptions contains options for sending raw datagrams.
// These map to SAM 3.1-3.3 RAW options.
type RawSendOptions struct {
	// FromPort is the source port (SAM 3.2+).
	FromPort int

	// ToPort is the destination port (SAM 3.2+).
	ToPort int

	// Protocol is the I2CP protocol number (SAM 3.2+).
	// Default is 18 (ProtocolRaw).
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

// I2CPDatagramSender implements DatagramSender using go-datagrams.
// This provides the bridge between SAM UDP port 7655 and I2P network.
//
// Per SAMv3.md: Datagrams sent through port 7655 are forwarded to I2P
// after stripping the header line.
//
// Integration with go-datagrams:
//   - Uses datagrams.DatagramConn for connection management
//   - Uses SendTo/SendToWithOptions for actual sending
//   - Supports all 4 datagram protocols (Raw, Datagram1, Datagram2, Datagram3)
type I2CPDatagramSender struct {
	mu sync.RWMutex

	// conn is the underlying go-datagrams connection.
	// This is an interface to allow testing without actual I2P router.
	conn DatagramConnection

	// protocol is the datagram protocol type (17, 18, 19, or 20).
	protocol uint8

	// localPort is the local port for outgoing datagrams.
	localPort uint16
}

// DatagramConnection is an interface representing go-datagrams DatagramConn.
// This abstraction allows for testing without actual I2P router.
type DatagramConnection interface {
	// SendTo sends a datagram to the destination.
	SendTo(payload []byte, destB64 string, port uint16) error

	// SendToWithOptions sends a datagram with SAM 3.3 options.
	SendToWithOptions(payload []byte, destB64 string, port uint16, opts *I2PDatagramOptions) error

	// Protocol returns the datagram protocol type.
	Protocol() uint8

	// Close closes the connection.
	Close() error
}

// I2PDatagramOptions represents go-datagrams Options struct.
// Maps to SAM 3.3 datagram sending options.
type I2PDatagramOptions struct {
	SendTags     int
	TagThreshold int
	Expires      int
	SendLeaseSet bool
}

// NewI2CPDatagramSender creates a new I2CPDatagramSender.
func NewI2CPDatagramSender(conn DatagramConnection) *I2CPDatagramSender {
	return &I2CPDatagramSender{
		conn:     conn,
		protocol: conn.Protocol(),
	}
}

// SendDatagram implements DatagramSender.SendDatagram.
// Sends a repliable datagram via go-datagrams.
func (s *I2CPDatagramSender) SendDatagram(dest string, payload []byte, opts DatagramSendOptions) error {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("datagram connection not available")
	}

	// Check if we need to use options (SAM 3.3+)
	if opts.SendTags > 0 || opts.TagThreshold > 0 || opts.Expires > 0 || opts.SendLeaseSet != nil {
		i2pOpts := &I2PDatagramOptions{
			SendTags:     opts.SendTags,
			TagThreshold: opts.TagThreshold,
			Expires:      opts.Expires,
		}
		if opts.SendLeaseSet != nil {
			i2pOpts.SendLeaseSet = *opts.SendLeaseSet
		}
		return conn.SendToWithOptions(payload, dest, uint16(opts.ToPort), i2pOpts)
	}

	return conn.SendTo(payload, dest, uint16(opts.ToPort))
}

// SendRaw implements DatagramSender.SendRaw.
// Sends a raw datagram via go-datagrams.
func (s *I2CPDatagramSender) SendRaw(dest string, payload []byte, opts RawSendOptions) error {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("datagram connection not available")
	}

	// Check if we need to use options (SAM 3.3+)
	if opts.SendTags > 0 || opts.TagThreshold > 0 || opts.Expires > 0 || opts.SendLeaseSet != nil {
		i2pOpts := &I2PDatagramOptions{
			SendTags:     opts.SendTags,
			TagThreshold: opts.TagThreshold,
			Expires:      opts.Expires,
		}
		if opts.SendLeaseSet != nil {
			i2pOpts.SendLeaseSet = *opts.SendLeaseSet
		}
		return conn.SendToWithOptions(payload, dest, uint16(opts.ToPort), i2pOpts)
	}

	return conn.SendTo(payload, dest, uint16(opts.ToPort))
}

// Close implements DatagramSender.Close.
func (s *I2CPDatagramSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// SessionDatagramManager manages DatagramSender instances per session.
// This enables per-session UDP binding as required by sam.udp.port option.
//
// Per SAMv3.md: The sam.udp.port option allows configuring per-session
// UDP datagram binding.
type SessionDatagramManager struct {
	mu sync.RWMutex

	// senders maps session ID to DatagramSender.
	senders map[string]DatagramSender

	// factory creates new DatagramSender instances.
	factory DatagramSenderFactory
}

// DatagramSenderFactory creates DatagramSender instances for sessions.
type DatagramSenderFactory interface {
	// Create creates a DatagramSender for the given session configuration.
	Create(ctx context.Context, sess session.Session, port int, protocol uint8) (DatagramSender, error)
}

// NewSessionDatagramManager creates a new SessionDatagramManager.
func NewSessionDatagramManager(factory DatagramSenderFactory) *SessionDatagramManager {
	return &SessionDatagramManager{
		senders: make(map[string]DatagramSender),
		factory: factory,
	}
}

// RegisterSession creates and registers a DatagramSender for a session.
// The port parameter comes from the sam.udp.port session option.
func (m *SessionDatagramManager) RegisterSession(ctx context.Context, sess session.Session, port int, protocol uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already registered
	if _, ok := m.senders[sess.ID()]; ok {
		return fmt.Errorf("session %s already registered", sess.ID())
	}

	// Create sender
	sender, err := m.factory.Create(ctx, sess, port, protocol)
	if err != nil {
		return fmt.Errorf("failed to create datagram sender: %w", err)
	}

	m.senders[sess.ID()] = sender
	return nil
}

// UnregisterSession removes and closes the DatagramSender for a session.
func (m *SessionDatagramManager) UnregisterSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sender, ok := m.senders[sessionID]
	if !ok {
		return nil
	}

	delete(m.senders, sessionID)
	return sender.Close()
}

// GetSender returns the DatagramSender for a session.
func (m *SessionDatagramManager) GetSender(sessionID string) DatagramSender {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.senders[sessionID]
}
