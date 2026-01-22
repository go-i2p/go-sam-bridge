// Package streaming provides adapters between go-streaming and go-sam-bridge.
// This file implements the StreamManager interface from lib/handler/stream_impl.go
// using the actual go-streaming library.
//
// Per SAMv3.md: STREAM sessions provide virtual TCP-like connections over I2P.
package streaming

import (
	"context"
	"fmt"
	"net"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/go-i2p/go-streaming"
)

// Adapter wraps go-streaming's StreamManager to implement handler.StreamManager.
// This bridges the gap between the abstract interface used by SAM handlers and
// the concrete go-streaming implementation.
//
// Usage:
//
//	client := go_i2cp.NewClient(...)
//	client.Connect(ctx)
//	manager, _ := streaming.NewStreamManager(client)
//	manager.StartSession(ctx)
//	adapter := NewAdapter(manager)
//	streamingConnector.RegisterManager(sessionID, adapter)
type Adapter struct {
	manager *streaming.StreamManager
}

// NewAdapter creates a new streaming adapter wrapping the given StreamManager.
// The manager must already have an active session (StartSession called).
func NewAdapter(manager *streaming.StreamManager) (*Adapter, error) {
	if manager == nil {
		return nil, fmt.Errorf("stream manager cannot be nil")
	}

	// Verify session is active by checking destination
	if manager.Destination() == nil {
		return nil, fmt.Errorf("stream manager has no active session (call StartSession first)")
	}

	return &Adapter{manager: manager}, nil
}

// LookupDestination resolves a hostname or B32 address to an I2P destination.
// Returns the destination as interface{} to match the handler.StreamManager interface.
//
// Per SAMv3.md: Java I2P supports hostnames and b32 addresses for the $destination.
//
// The resolution is performed via I2CP HostLookupMessage to the router's naming service.
func (a *Adapter) LookupDestination(ctx context.Context, hostname string) (interface{}, error) {
	if a.manager == nil {
		return nil, fmt.Errorf("adapter not initialized")
	}

	dest, err := a.manager.LookupDestination(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("lookup failed for %q: %w", hostname, err)
	}

	return dest, nil
}

// Dial establishes an outbound stream connection to the destination.
// Returns a net.Conn for bidirectional communication.
//
// Per SAMv3.md: STREAM CONNECT establishes a virtual streaming connection.
//
// The dest parameter must be either:
//   - A *go_i2cp.Destination (from LookupDestination)
//   - A string (Base64-encoded destination, for direct connection)
func (a *Adapter) Dial(dest interface{}, port uint16, mtu int) (net.Conn, error) {
	if a.manager == nil {
		return nil, fmt.Errorf("adapter not initialized")
	}

	// Convert dest to *go_i2cp.Destination
	var i2pDest *go_i2cp.Destination
	switch d := dest.(type) {
	case *go_i2cp.Destination:
		i2pDest = d
	case string:
		// Base64 destination string - parse it
		parsed, err := parseDestinationFromBase64(d)
		if err != nil {
			return nil, fmt.Errorf("invalid destination format: %w", err)
		}
		i2pDest = parsed
	default:
		return nil, fmt.Errorf("unsupported destination type: %T", dest)
	}

	// Use DialWithManager for proper integration
	// localPort 0 = any port (let the library assign)
	conn, err := streaming.DialWithManager(a.manager, i2pDest, 0, port)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	return conn, nil
}

// Listen creates a StreamListener on the specified port.
// Returns a net.Listener for accepting incoming connections.
//
// Per SAMv3.md: STREAM ACCEPT waits for and accepts incoming connections.
func (a *Adapter) Listen(port uint16, mtu int) (net.Listener, error) {
	if a.manager == nil {
		return nil, fmt.Errorf("adapter not initialized")
	}

	listener, err := streaming.ListenWithManager(a.manager, port, mtu)
	if err != nil {
		return nil, fmt.Errorf("listen failed on port %d: %w", port, err)
	}

	return listener, nil
}

// Destination returns the local I2P destination for this session.
// Returns interface{} to match the handler.StreamManager interface.
func (a *Adapter) Destination() interface{} {
	if a.manager == nil {
		return nil
	}
	return a.manager.Destination()
}

// Close closes the stream manager and releases resources.
// After Close, no more connections can be established.
func (a *Adapter) Close() error {
	// Note: The StreamManager doesn't have a Close method directly.
	// The lifecycle is managed via the I2CP client.
	// We set the reference to nil to prevent further operations.
	a.manager = nil
	return nil
}

// Manager returns the underlying go-streaming StreamManager.
// This can be used when direct access is needed for advanced operations.
func (a *Adapter) Manager() *streaming.StreamManager {
	return a.manager
}

// parseDestinationFromBase64 parses a Base64-encoded I2P destination.
// This is used when the destination is passed as a string rather than
// a resolved *go_i2cp.Destination.
func parseDestinationFromBase64(b64 string) (*go_i2cp.Destination, error) {
	if b64 == "" {
		return nil, fmt.Errorf("empty destination string")
	}

	// Use go_i2cp's destination parsing with crypto context
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestinationFromBase64(b64, crypto)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	return dest, nil
}
