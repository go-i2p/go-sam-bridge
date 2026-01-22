// Package session implements SAM v3.0-3.3 session management.
// This file implements StreamSessionImpl for STREAM session handling
// per SAM 3.0 STREAM CONNECT, ACCEPT, FORWARD commands.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/go-i2p/go-streaming"
)

// ForwardConnectTimeout is the maximum time allowed to connect to the
// forwarding target when an incoming I2P connection arrives.
// Per SAMv3.md: "If it is accepted in less than 3 seconds, SAM will accept
// the connection from I2P, otherwise it rejects it."
const ForwardConnectTimeout = 3 * time.Second

// StreamSessionImpl implements the StreamSession interface.
// It embeds *BaseSession and integrates with go-streaming for I2P stream handling.
//
// Per PLAN.md section 1.7 and SAM 3.0 specification:
//   - Supports STREAM CONNECT for outbound connections
//   - Supports STREAM ACCEPT for inbound connections (concurrent ACCEPTs per SAM 3.2)
//   - Supports STREAM FORWARD for forwarding to host:port
//   - FORWARD and ACCEPT are mutually exclusive
type StreamSessionImpl struct {
	*BaseSession

	mu sync.RWMutex

	// I2CP integration
	i2cpSession *go_i2cp.Session

	// Streaming manager for packet routing
	streamManager *streaming.StreamManager

	// Listener for accepting incoming connections
	listener *streaming.StreamListener

	// Pending accept counter for SAM version-dependent behavior.
	// Prior to SAM 3.2, only one concurrent ACCEPT is allowed per session.
	// As of SAM 3.2, multiple concurrent ACCEPTs are allowed.
	pendingAccepts int

	// Forwarding configuration
	forwardingEnabled bool
	forwardHost       string
	forwardPort       int
	forwardStop       chan struct{}
	forwardWg         sync.WaitGroup

	// Active connections (for cleanup)
	activeConns   map[string]net.Conn
	activeConnsMu sync.RWMutex

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// NewStreamSession creates a new STREAM session.
//
// Parameters:
//   - id: Unique session identifier (nickname)
//   - dest: I2P destination for this session
//   - conn: Control connection (session dies when this closes)
//   - cfg: Session configuration
//   - i2cpSession: Underlying I2CP session
//   - manager: Stream manager for packet routing
//
// Per SAM 3.0 specification, the session starts in Creating state
// and must be activated after setup completes.
func NewStreamSession(
	id string,
	dest *Destination,
	conn net.Conn,
	cfg *SessionConfig,
	i2cpSession *go_i2cp.Session,
	manager *streaming.StreamManager,
) *StreamSessionImpl {
	ctx, cancel := context.WithCancel(context.Background())

	return &StreamSessionImpl{
		BaseSession:   NewBaseSession(id, StyleStream, dest, conn, cfg),
		i2cpSession:   i2cpSession,
		streamManager: manager,
		activeConns:   make(map[string]net.Conn),
		forwardStop:   make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Connect establishes an outbound stream to the specified destination.
// Implements SAM 3.0 STREAM CONNECT command.
//
// Parameters:
//   - dest: Base64-encoded I2P destination or .i2p hostname
//   - opts: Connection options (timeout, ports, etc.)
//
// Returns the established connection for bidirectional data transfer.
// The caller is responsible for closing the connection.
//
// Per SAM specification, on success returns:
//
//	STREAM STATUS RESULT=OK
//
// On failure returns one of:
//
//	STREAM STATUS RESULT=CANT_REACH_PEER
//	STREAM STATUS RESULT=I2P_ERROR MESSAGE="..."
//	STREAM STATUS RESULT=INVALID_KEY
//	STREAM STATUS RESULT=TIMEOUT
func (s *StreamSessionImpl) Connect(dest string, opts ConnectOptions) (net.Conn, error) {
	s.mu.RLock()
	if s.Status() != StatusActive {
		s.mu.RUnlock()
		return nil, ErrSessionNotActive
	}
	manager := s.streamManager
	s.mu.RUnlock()

	if manager == nil {
		return nil, errors.New("stream manager not initialized")
	}

	// Lookup destination if it's a hostname
	var i2pDest *go_i2cp.Destination
	var err error

	ctx := s.ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Try to parse as base64 destination first
	i2pDest, err = go_i2cp.NewDestinationFromBase64(dest, nil)
	if err != nil {
		// Not a base64 destination, try hostname lookup
		i2pDest, err = manager.LookupDestination(ctx, dest)
		if err != nil {
			return nil, fmt.Errorf("destination lookup failed: %w", err)
		}
	}

	// Determine ports
	localPort := uint16(opts.FromPort)
	remotePort := uint16(opts.ToPort)

	// Dial using the stream manager
	conn, err := streaming.DialWithManager(manager, i2pDest, localPort, remotePort)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	// Track the connection
	connID := fmt.Sprintf("%s:%d->%d", dest[:min(8, len(dest))], localPort, remotePort)
	s.activeConnsMu.Lock()
	s.activeConns[connID] = conn
	s.activeConnsMu.Unlock()

	return conn, nil
}

// Accept waits for and accepts an incoming stream connection.
// Implements SAM 3.0 STREAM ACCEPT command.
//
// Concurrent ACCEPTs are supported as of SAM 3.2.
//
// Parameters:
//   - opts: Accept options (SILENT mode, timeout)
//
// Returns:
//   - conn: The accepted connection for bidirectional data transfer
//   - peerDest: Base64-encoded destination of the connecting peer
//   - err: Error if accept failed
//
// Per SAM specification, on success returns:
//
//	STREAM STATUS RESULT=OK
//
// Followed by peer destination unless SILENT=true.
func (s *StreamSessionImpl) Accept(opts AcceptOptions) (net.Conn, string, error) {
	s.mu.Lock()
	if s.Status() != StatusActive {
		s.mu.Unlock()
		return nil, "", ErrSessionNotActive
	}

	if s.forwardingEnabled {
		s.mu.Unlock()
		return nil, "", errors.New("cannot ACCEPT when FORWARD is active")
	}

	// Create listener if not already created
	if s.listener == nil {
		if s.streamManager == nil {
			s.mu.Unlock()
			return nil, "", errors.New("stream manager not initialized")
		}

		// Use default port 0 if not specified
		localPort := uint16(0)
		if cfg := s.Config(); cfg != nil {
			localPort = uint16(cfg.FromPort)
		}

		listener, err := streaming.ListenWithManager(s.streamManager, localPort, streaming.DefaultMTU)
		if err != nil {
			s.mu.Unlock()
			return nil, "", fmt.Errorf("failed to create listener: %w", err)
		}
		s.listener = listener
	}
	listener := s.listener
	s.mu.Unlock()

	// Accept with optional timeout
	var conn net.Conn
	var err error

	if opts.Timeout > 0 {
		// Create a channel-based timeout
		done := make(chan struct{})
		go func() {
			conn, err = listener.Accept()
			close(done)
		}()

		select {
		case <-done:
			// Accept completed
		case <-time.After(opts.Timeout):
			return nil, "", errors.New("accept timeout")
		case <-s.ctx.Done():
			return nil, "", s.ctx.Err()
		}
	} else {
		conn, err = listener.Accept()
	}

	if err != nil {
		return nil, "", fmt.Errorf("accept failed: %w", err)
	}

	// Get peer destination
	peerDest := ""
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		peerDest = remoteAddr.String()
	}

	// Track the connection
	connID := fmt.Sprintf("incoming-%d", time.Now().UnixNano())
	s.activeConnsMu.Lock()
	s.activeConns[connID] = conn
	s.activeConnsMu.Unlock()

	return conn, peerDest, nil
}

// IncrementPendingAccepts atomically increments the pending accept counter.
// Used by the handler to track concurrent ACCEPT operations.
// Per SAM spec: Prior to 3.2, only one concurrent ACCEPT is allowed.
func (s *StreamSessionImpl) IncrementPendingAccepts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingAccepts++
}

// DecrementPendingAccepts atomically decrements the pending accept counter.
// Should be called when an ACCEPT completes (success or failure).
func (s *StreamSessionImpl) DecrementPendingAccepts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingAccepts > 0 {
		s.pendingAccepts--
	}
}

// PendingAcceptCount returns the current number of pending ACCEPT operations.
// Used to enforce pre-3.2 single-accept restriction.
func (s *StreamSessionImpl) PendingAcceptCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pendingAccepts
}

// Forward sets up forwarding of incoming connections to host:port.
// Implements SAM 3.0 STREAM FORWARD command.
//
// FORWARD and ACCEPT are mutually exclusive per SAM specification.
//
// Parameters:
//   - host: Target host for forwarding
//   - port: Target port for forwarding
//   - opts: Forwarding options (SILENT mode)
//
// The forwarding runs in background goroutines. Each incoming connection
// spawns a goroutine that forwards data bidirectionally.
func (s *StreamSessionImpl) Forward(host string, port int, opts ForwardOptions) error {
	s.mu.Lock()
	if s.Status() != StatusActive {
		s.mu.Unlock()
		return ErrSessionNotActive
	}

	if s.forwardingEnabled {
		s.mu.Unlock()
		return errors.New("forwarding already active")
	}

	if s.listener != nil {
		s.mu.Unlock()
		return errors.New("cannot FORWARD when ACCEPT has been used")
	}

	if s.streamManager == nil {
		s.mu.Unlock()
		return errors.New("stream manager not initialized")
	}

	// Create listener for incoming connections
	localPort := uint16(0)
	if cfg := s.Config(); cfg != nil {
		localPort = uint16(cfg.FromPort)
	}

	listener, err := streaming.ListenWithManager(s.streamManager, localPort, streaming.DefaultMTU)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.listener = listener
	s.forwardingEnabled = true
	s.forwardHost = host
	s.forwardPort = port
	s.forwardStop = make(chan struct{})
	s.mu.Unlock()

	// Start forwarding goroutine
	s.forwardWg.Add(1)
	go s.forwardLoop(listener, host, port, opts.Silent)

	return nil
}

// forwardLoop accepts incoming connections and forwards them to the target.
func (s *StreamSessionImpl) forwardLoop(listener net.Listener, host string, port int, silent bool) {
	defer s.forwardWg.Done()

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	for {
		select {
		case <-s.forwardStop:
			return
		case <-s.ctx.Done():
			return
		default:
		}

		// Accept incoming connection
		inConn, err := listener.Accept()
		if err != nil {
			// Check if we should stop
			select {
			case <-s.forwardStop:
				return
			case <-s.ctx.Done():
				return
			default:
				// Log error and continue
				continue
			}
		}

		// Connect to forward target
		// Per SAMv3.md: "If it is accepted in less than 3 seconds, SAM will accept
		// the connection from I2P, otherwise it rejects it."
		outConn, err := net.DialTimeout("tcp", target, ForwardConnectTimeout)
		if err != nil {
			inConn.Close()
			continue
		}

		// Start bidirectional forwarding
		s.forwardWg.Add(1)
		go s.forwardConnection(inConn, outConn)
	}
}

// forwardConnection forwards data between two connections bidirectionally.
func (s *StreamSessionImpl) forwardConnection(i2pConn, tcpConn net.Conn) {
	defer s.forwardWg.Done()
	defer i2pConn.Close()
	defer tcpConn.Close()

	// Track connection
	connID := fmt.Sprintf("forward-%d", time.Now().UnixNano())
	s.activeConnsMu.Lock()
	s.activeConns[connID] = i2pConn
	s.activeConnsMu.Unlock()

	defer func() {
		s.activeConnsMu.Lock()
		delete(s.activeConns, connID)
		s.activeConnsMu.Unlock()
	}()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(tcpConn, i2pConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(i2pConn, tcpConn)
		done <- struct{}{}
	}()

	// Wait for either direction to complete or context cancellation
	select {
	case <-done:
	case <-s.ctx.Done():
	}
}

// IsForwarding returns true if FORWARD is active on this session.
func (s *StreamSessionImpl) IsForwarding() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwardingEnabled
}

// Close terminates the session and releases all resources.
// Overrides BaseSession.Close to perform stream-specific cleanup.
func (s *StreamSessionImpl) Close() error {
	s.mu.Lock()
	status := s.Status()
	if status == StatusClosed || status == StatusClosing {
		s.mu.Unlock()
		return nil
	}
	// Don't set status here - let BaseSession.Close handle the state machine
	s.mu.Unlock()

	// Cancel context to stop all goroutines
	s.cancel()

	// Stop forwarding
	s.mu.Lock()
	if s.forwardingEnabled {
		close(s.forwardStop)
		s.forwardingEnabled = false
	}
	s.mu.Unlock()

	// Wait for forwarding goroutines to finish
	s.forwardWg.Wait()

	// Close all active connections
	s.activeConnsMu.Lock()
	for id, conn := range s.activeConns {
		conn.Close()
		delete(s.activeConns, id)
	}
	s.activeConnsMu.Unlock()

	// Close listener
	s.mu.Lock()
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
	s.mu.Unlock()

	// Close base session (control connection) - this sets status to CLOSED
	return s.BaseSession.Close()
}

// I2CPSession returns the underlying I2CP session.
func (s *StreamSessionImpl) I2CPSession() *go_i2cp.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.i2cpSession
}

// StreamManager returns the stream manager.
func (s *StreamSessionImpl) StreamManager() *streaming.StreamManager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streamManager
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure StreamSessionImpl implements StreamSession interface.
var _ StreamSession = (*StreamSessionImpl)(nil)
