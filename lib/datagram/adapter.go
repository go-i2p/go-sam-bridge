// Package datagram provides adapters between go-datagrams and go-sam-bridge.
// This file implements the DatagramConnection interface from lib/datagram/sender.go
// using the actual go-datagrams library.
//
// Per SAMv3.md: Datagrams sent through port 7655 are forwarded to I2P
// after stripping the header line.
package datagram

import (
	"fmt"
	"sync"

	"github.com/go-i2p/go-datagrams"
)

// Adapter wraps go-datagrams' DatagramConn to implement the DatagramConnection interface.
// This bridges the gap between the abstract interface used by SAM handlers and
// the concrete go-datagrams implementation.
//
// Usage:
//
//	session := i2cpClient.CreateSession(ctx, ...)
//	conn, _ := datagrams.NewDatagramConnWithProtocol(session, port, protocol)
//	adapter := NewAdapter(conn)
//	sender := NewI2CPDatagramSender(adapter)
type Adapter struct {
	mu   sync.RWMutex
	conn *datagrams.DatagramConn
}

// NewAdapter creates a new datagram adapter wrapping the given DatagramConn.
// The conn must already be initialized and ready for use.
func NewAdapter(conn *datagrams.DatagramConn) (*Adapter, error) {
	if conn == nil {
		return nil, fmt.Errorf("datagram conn cannot be nil")
	}

	// Verify connection is not closed
	if conn.IsClosed() {
		return nil, fmt.Errorf("datagram conn is closed")
	}

	return &Adapter{conn: conn}, nil
}

// SendTo implements DatagramConnection.SendTo.
// Sends a datagram to the destination via go-datagrams.
func (a *Adapter) SendTo(payload []byte, destB64 string, port uint16) error {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("adapter not initialized")
	}

	if conn.IsClosed() {
		return fmt.Errorf("datagram conn is closed")
	}

	return conn.SendTo(payload, destB64, port)
}

// SendToWithOptions implements DatagramConnection.SendToWithOptions.
// Sends a datagram with SAM 3.3 options via go-datagrams.
//
// Per SAMv3.md: SAM 3.3 adds SEND_TAGS, TAG_THRESHOLD, EXPIRES, and SEND_LEASESET
// options for advanced session tag management.
//
// Note: The go-datagrams Options struct uses an I2P Mapping format for options.
// SAM 3.3 options are translated to Mapping key-value pairs.
func (a *Adapter) SendToWithOptions(payload []byte, destB64 string, port uint16, opts *I2PDatagramOptions) error {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("adapter not initialized")
	}

	if conn.IsClosed() {
		return fmt.Errorf("datagram conn is closed")
	}

	// If no options provided, use basic SendTo
	if opts == nil {
		return conn.SendTo(payload, destB64, port)
	}

	// Convert SAM options to go-datagrams Options (I2P Mapping format)
	// go-datagrams uses an I2P Mapping structure for options in Datagram2/3
	dgOpts := datagrams.EmptyOptions()

	// Add SAM 3.3 options as mapping entries
	if opts.SendTags > 0 {
		dgOpts.Set("SEND_TAGS", fmt.Sprintf("%d", opts.SendTags))
	}
	if opts.TagThreshold > 0 {
		dgOpts.Set("TAG_THRESHOLD", fmt.Sprintf("%d", opts.TagThreshold))
	}
	if opts.Expires > 0 {
		dgOpts.Set("EXPIRES", fmt.Sprintf("%d", opts.Expires))
	}
	if opts.SendLeaseSet {
		dgOpts.Set("SEND_LEASESET", "true")
	}

	return conn.SendToWithOptions(payload, destB64, port, dgOpts)
}

// Protocol implements DatagramConnection.Protocol.
// Returns the datagram protocol type (17, 18, 19, or 20).
//
// Protocol types per SAM spec:
//   - 17: Datagram1 (authenticated, repliable, legacy)
//   - 18: Raw (no authentication, not repliable)
//   - 19: Datagram2 (authenticated with replay prevention)
//   - 20: Datagram3 (repliable, minimal overhead)
func (a *Adapter) Protocol() uint8 {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	if conn == nil {
		return 0
	}
	return conn.Protocol()
}

// Close implements DatagramConnection.Close.
// Closes the underlying go-datagrams connection.
func (a *Adapter) Close() error {
	a.mu.Lock()
	conn := a.conn
	a.conn = nil
	a.mu.Unlock()

	if conn == nil {
		return nil
	}

	return conn.Close()
}

// Conn returns the underlying go-datagrams DatagramConn.
// This can be used when direct access is needed for advanced operations.
func (a *Adapter) Conn() *datagrams.DatagramConn {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.conn
}

// MaxPayloadSize returns the maximum payload size for this adapter's protocol type.
// This accounts for protocol-specific overhead in the I2NP message.
func (a *Adapter) MaxPayloadSize() int {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	if conn == nil {
		return 0
	}
	return conn.MaxPayloadSize()
}

// LocalAddr returns the local I2P address for this connection.
// The address includes the destination string and port.
func (a *Adapter) LocalAddr() string {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()

	if conn == nil {
		return ""
	}
	addr := conn.LocalAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

// Verify Adapter implements DatagramConnection at compile time.
var _ DatagramConnection = (*Adapter)(nil)
