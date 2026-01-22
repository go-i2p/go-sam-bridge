// Package handler implements SAM command handlers per SAMv3.md specification.
// This file provides production implementations of StreamConnector, StreamAcceptor,
// and StreamForwarder using go-streaming for actual I2P stream connections.

package handler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// StreamingConnector implements StreamConnector using go-streaming.
// It establishes outbound I2P stream connections.
//
// Per SAMv3.md: STREAM CONNECT establishes a virtual streaming connection
// to the specified I2P destination.
//
// Integration with go-streaming:
//   - Uses streaming.StreamManager for I2CP session bridging
//   - Uses streaming.Dial() for connection establishment
//   - Returns net.Conn representing bidirectional stream
type StreamingConnector struct {
	mu sync.RWMutex

	// manager is the go-streaming StreamManager for I2CP integration.
	// This is set per-session when the session is created with I2CP integration.
	managers map[string]StreamManager

	// connectTimeout is the timeout for connection establishment.
	connectTimeout time.Duration

	// defaultMTU is the default MTU for stream connections.
	defaultMTU int
}

// StreamManager is an interface representing go-streaming's StreamManager.
// This abstraction allows for testing without actual I2P router.
type StreamManager interface {
	// LookupDestination resolves a hostname or B32 to a destination.
	LookupDestination(ctx context.Context, hostname string) (interface{}, error)

	// Dial establishes an outbound stream connection.
	Dial(dest interface{}, port uint16, mtu int) (net.Conn, error)

	// Listen creates a StreamListener on the specified port.
	Listen(port uint16, mtu int) (net.Listener, error)

	// Destination returns the local I2P destination.
	Destination() interface{}

	// Close closes the stream manager.
	Close() error
}

// NewStreamingConnector creates a new StreamingConnector.
func NewStreamingConnector() *StreamingConnector {
	return &StreamingConnector{
		managers:       make(map[string]StreamManager),
		connectTimeout: 60 * time.Second,
		defaultMTU:     1730, // Default per I2P streaming spec
	}
}

// RegisterManager registers a StreamManager for a session.
func (c *StreamingConnector) RegisterManager(sessionID string, manager StreamManager) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.managers[sessionID] = manager
}

// UnregisterManager removes a StreamManager for a session.
func (c *StreamingConnector) UnregisterManager(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.managers, sessionID)
}

// Connect implements StreamConnector.Connect.
// Establishes a stream connection to the destination.
//
// Per SAMv3.md: The destination can be:
//   - Base64-encoded full destination
//   - Base32 address (xxx.b32.i2p)
//   - Hostname (example.i2p)
func (c *StreamingConnector) Connect(sess session.Session, dest string, fromPort, toPort int) (net.Conn, error) {
	c.mu.RLock()
	manager, ok := c.managers[sess.ID()]
	c.mu.RUnlock()

	if !ok || manager == nil {
		return nil, fmt.Errorf("no stream manager registered for session %s", sess.ID())
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), c.connectTimeout)
	defer cancel()

	// Resolve destination if needed (hostname or B32)
	var resolvedDest interface{}
	if isHostnameOrB32(dest) {
		var err error
		resolvedDest, err = manager.LookupDestination(ctx, dest)
		if err != nil {
			return nil, fmt.Errorf("destination lookup failed: %w", err)
		}
	} else {
		// Assume it's a Base64 destination - pass through
		resolvedDest = dest
	}

	// Dial the destination
	conn, err := manager.Dial(resolvedDest, uint16(toPort), c.defaultMTU)
	if err != nil {
		return nil, fmt.Errorf("stream connect failed: %w", err)
	}

	return conn, nil
}

// isHostnameOrB32 checks if the destination needs resolution.
func isHostnameOrB32(dest string) bool {
	// B32 addresses end with .b32.i2p
	// Regular hostnames end with .i2p
	return len(dest) >= 4 && (dest[len(dest)-4:] == ".i2p")
}

// StreamingAcceptor implements StreamAcceptor using go-streaming.
// It accepts inbound I2P stream connections.
//
// Per SAMv3.md: STREAM ACCEPT waits for and accepts incoming connections.
type StreamingAcceptor struct {
	mu sync.RWMutex

	// listeners maps session ID to active listeners.
	listeners map[string]net.Listener

	// managers maps session ID to stream manager.
	managers map[string]StreamManager

	// acceptTimeout is the timeout for accept operations (0 = no timeout).
	acceptTimeout time.Duration

	// defaultPort is the default listening port.
	defaultPort uint16

	// defaultMTU is the default MTU for listeners.
	defaultMTU int
}

// NewStreamingAcceptor creates a new StreamingAcceptor.
func NewStreamingAcceptor() *StreamingAcceptor {
	return &StreamingAcceptor{
		listeners:   make(map[string]net.Listener),
		managers:    make(map[string]StreamManager),
		defaultPort: 0, // Use session's destination port
		defaultMTU:  1730,
	}
}

// RegisterManager registers a StreamManager for a session.
func (a *StreamingAcceptor) RegisterManager(sessionID string, manager StreamManager) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.managers[sessionID] = manager

	// Create listener for the session
	listener, err := manager.Listen(a.defaultPort, a.defaultMTU)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	a.listeners[sessionID] = listener

	return nil
}

// UnregisterManager removes a StreamManager for a session.
func (a *StreamingAcceptor) UnregisterManager(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if listener, ok := a.listeners[sessionID]; ok {
		listener.Close()
		delete(a.listeners, sessionID)
	}
	delete(a.managers, sessionID)
}

// Accept implements StreamAcceptor.Accept.
// Waits for and accepts an incoming stream connection.
//
// Per SAMv3.md: Returns the connection and remote destination info.
func (a *StreamingAcceptor) Accept(sess session.Session) (net.Conn, *AcceptInfo, error) {
	a.mu.RLock()
	listener, ok := a.listeners[sess.ID()]
	a.mu.RUnlock()

	if !ok || listener == nil {
		return nil, nil, fmt.Errorf("no listener for session %s", sess.ID())
	}

	// Accept with timeout if configured
	var conn net.Conn
	var err error

	if a.acceptTimeout > 0 {
		// Use a deadline for timeout
		if dl, ok := listener.(interface{ SetDeadline(time.Time) error }); ok {
			dl.SetDeadline(time.Now().Add(a.acceptTimeout))
			defer dl.SetDeadline(time.Time{})
		}
	}

	conn, err = listener.Accept()
	if err != nil {
		return nil, nil, fmt.Errorf("accept failed: %w", err)
	}

	// Extract connection info
	info := &AcceptInfo{
		Destination: "",
		FromPort:    0,
		ToPort:      0,
	}

	// Try to extract I2P-specific info from the connection's address
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		info.Destination = remoteAddr.String()
	}

	return conn, info, nil
}

// StreamingForwarder implements StreamForwarder for STREAM FORWARD.
// It sets up connection forwarding to a local host:port.
//
// Per SAMv3.md: STREAM FORWARD listens for incoming I2P connections
// and forwards them to a local address.
type StreamingForwarder struct {
	mu sync.RWMutex

	// forwarders tracks active forwarding listeners per session.
	forwarders map[string]*forwardState

	// managers maps session ID to stream manager.
	managers map[string]StreamManager
}

// forwardState tracks the state of a forwarding listener.
type forwardState struct {
	listener   net.Listener
	targetHost string
	targetPort int
	ssl        bool
	cancel     context.CancelFunc
}

// NewStreamingForwarder creates a new StreamingForwarder.
func NewStreamingForwarder() *StreamingForwarder {
	return &StreamingForwarder{
		forwarders: make(map[string]*forwardState),
		managers:   make(map[string]StreamManager),
	}
}

// RegisterManager registers a StreamManager for a session.
func (f *StreamingForwarder) RegisterManager(sessionID string, manager StreamManager) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.managers[sessionID] = manager
}

// UnregisterManager removes a StreamManager for a session.
func (f *StreamingForwarder) UnregisterManager(sessionID string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if state, ok := f.forwarders[sessionID]; ok {
		state.cancel()
		state.listener.Close()
		delete(f.forwarders, sessionID)
	}
	delete(f.managers, sessionID)
}

// Forward implements StreamForwarder.Forward.
// Sets up forwarding from I2P to a local host:port.
//
// Per SAMv3.md: When SSL=true, the connection to the local host uses TLS.
func (f *StreamingForwarder) Forward(sess session.Session, host string, port int, ssl bool) (net.Listener, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check for existing forwarder
	if _, ok := f.forwarders[sess.ID()]; ok {
		return nil, fmt.Errorf("forwarder already active for session %s", sess.ID())
	}

	manager, ok := f.managers[sess.ID()]
	if !ok || manager == nil {
		return nil, fmt.Errorf("no stream manager for session %s", sess.ID())
	}

	// Create I2P listener
	listener, err := manager.Listen(0, 1730)
	if err != nil {
		return nil, fmt.Errorf("failed to create I2P listener: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	state := &forwardState{
		listener:   listener,
		targetHost: host,
		targetPort: port,
		ssl:        ssl,
		cancel:     cancel,
	}
	f.forwarders[sess.ID()] = state

	// Start forwarding goroutine
	go f.forwardLoop(ctx, state)

	return listener, nil
}

// forwardLoop accepts connections and forwards them.
func (f *StreamingForwarder) forwardLoop(ctx context.Context, state *forwardState) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := state.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		go f.handleForward(ctx, conn, state)
	}
}

// handleForward handles a single forwarded connection.
func (f *StreamingForwarder) handleForward(ctx context.Context, i2pConn net.Conn, state *forwardState) {
	defer i2pConn.Close()

	// Connect to local target
	addr := fmt.Sprintf("%s:%d", state.targetHost, state.targetPort)
	var localConn net.Conn
	var err error

	if state.ssl {
		// Use TLS for local connection per SAM 3.2+ SSL option
		localConn, err = tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true, // Local connection, often self-signed
		})
	} else {
		localConn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		return // Silent failure per SAM spec
	}
	defer localConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(localConn, i2pConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(i2pConn, localConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish or context cancellation
	select {
	case <-done:
	case <-ctx.Done():
	}
}
