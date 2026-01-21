package bridge

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// Server is the SAM bridge server that accepts client connections
// and processes SAM protocol commands.
type Server struct {
	config    *Config
	listener  net.Listener
	router    *handler.Router
	registry  session.Registry
	parser    *protocol.Parser
	authStore *AuthStore

	mu          sync.Mutex
	connections map[*Connection]struct{}
	closed      atomic.Bool

	// done is closed when the server shuts down.
	done chan struct{}
}

// NewServer creates a new SAM bridge server with the given configuration.
func NewServer(config *Config, registry session.Registry) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Initialize AuthStore from config
	authStore := NewAuthStoreFromConfig(config.Auth)

	return &Server{
		config:      config,
		registry:    registry,
		router:      handler.NewRouter(),
		parser:      protocol.NewParser(),
		authStore:   authStore,
		connections: make(map[*Connection]struct{}),
		done:        make(chan struct{}),
	}, nil
}

// Router returns the command router for handler registration.
func (s *Server) Router() *handler.Router {
	return s.router
}

// Registry returns the session registry.
func (s *Server) Registry() session.Registry {
	return s.registry
}

// Config returns the server configuration.
func (s *Server) Config() *Config {
	return s.config
}

// AuthStore returns the authentication store for handler registration.
// Implements handler.AuthManager interface for AUTH commands.
func (s *Server) AuthStore() *AuthStore {
	return s.authStore
}

// ListenAndServe starts listening on the configured address and serves clients.
// This method blocks until the server is closed.
func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}

	// Wrap with TLS if configured
	if s.config.TLSConfig != nil {
		listener = tls.NewListener(listener, s.config.TLSConfig)
	}

	return s.Serve(listener)
}

// Serve accepts connections on the listener and handles them.
// This method blocks until the server is closed.
func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil // Server was closed
			}
			// Check if it's a temporary error
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}

		// Check connection limits
		if !s.canAccept() {
			conn.Close()
			continue
		}

		go s.handleConnection(conn)
	}
}

// canAccept returns true if the server can accept a new connection.
func (s *Server) canAccept() bool {
	if s.config.Limits.MaxConnections == 0 {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections) < s.config.Limits.MaxConnections
}

// handleConnection processes a single client connection.
func (s *Server) handleConnection(conn net.Conn) {
	c := NewConnection(conn, s.config.Limits.ReadBufferSize)

	s.mu.Lock()
	s.connections[c] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.connections, c)
		s.mu.Unlock()
		c.Close()
	}()

	// Create handler context
	ctx := handler.NewContext(conn, s.registry)

	// Command loop
	for {
		if s.closed.Load() {
			return
		}

		// Check for PONG timeout (if we sent a PING and are waiting for PONG)
		if c.IsPongOverdue(s.config.Timeouts.PongTimeout) {
			s.sendPongTimeoutError(c)
			return
		}

		// Set read deadline based on state
		deadline := s.getDeadline(c)
		if !deadline.IsZero() {
			if err := c.SetReadDeadline(deadline); err != nil {
				return
			}
		}

		// Read command line
		line, err := s.readLine(c.Reader())
		if err != nil {
			// Handle timeout errors with proper SAM responses per SAM 3.2
			if s.isTimeoutError(err) {
				s.sendTimeoutError(c)
			}
			return
		}

		c.UpdateActivity()

		// Parse command
		cmd, err := s.parser.Parse(line)
		if err != nil {
			s.sendParseError(c, err)
			continue
		}

		// Handle PONG responses - clear pending PING
		if strings.EqualFold(cmd.Verb, "PONG") {
			c.ClearPendingPing()
			continue // PONG is handled, no response needed
		}

		// Handle the command
		response, err := s.dispatchCommand(ctx, c, cmd)
		if err != nil {
			return // Internal error, close connection
		}

		// Send response if any
		if response != nil {
			if err := s.sendResponse(c, response); err != nil {
				return
			}
		}

		// Update context state from connection
		if c.Version() != "" && ctx.Version == "" {
			ctx.Version = c.Version()
			ctx.HandshakeComplete = true
		}
		if c.IsAuthenticated() {
			ctx.Authenticated = true
		}
	}
}

// getDeadline returns the appropriate read deadline for the connection state.
func (s *Server) getDeadline(c *Connection) time.Time {
	var timeout time.Duration

	switch c.State() {
	case StateNew, StateHandshaking:
		timeout = s.config.Timeouts.Handshake
	default:
		timeout = s.config.Timeouts.Command
	}

	if timeout > 0 {
		return time.Now().Add(timeout)
	}
	return time.Time{}
}

// readLine reads a single line from the reader, enforcing max line length.
func (s *Server) readLine(reader *bufio.Reader) (string, error) {
	var line strings.Builder
	maxLen := s.config.Limits.MaxLineLength

	for {
		part, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}

		line.Write(part)

		if line.Len() > maxLen {
			return "", errors.New("line too long")
		}

		if !isPrefix {
			break
		}
	}

	return line.String(), nil
}

// dispatchCommand routes the command to the appropriate handler.
func (s *Server) dispatchCommand(
	ctx *handler.Context,
	c *Connection,
	cmd *protocol.Command,
) (*protocol.Response, error) {
	// Check handshake state
	if !ctx.HandshakeComplete && !isHandshakeCommand(cmd) {
		return protocol.NewResponse("HELLO").
			WithAction("REPLY").
			WithResult("I2P_ERROR").
			WithMessage("handshake not complete"), nil
	}

	// Check authentication if required (use AuthStore for runtime state)
	if s.authStore.IsAuthEnabled() && !ctx.Authenticated && !isAuthCommand(cmd) {
		return protocol.NewResponse(cmd.Verb).
			WithResult("I2P_ERROR").
			WithMessage("authentication required"), nil
	}

	// Route to handler
	h := s.router.Route(cmd)
	if h == nil {
		return protocol.NewResponse(cmd.Verb).
			WithResult("I2P_ERROR").
			WithMessage("unknown command"), nil
	}

	response, err := h.Handle(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// Update connection state based on command success
	s.updateConnectionState(c, cmd, response)

	return response, nil
}

// updateConnectionState updates connection state after successful commands.
func (s *Server) updateConnectionState(
	c *Connection,
	cmd *protocol.Command,
	response *protocol.Response,
) {
	if response == nil {
		return
	}

	// Check if response indicates success
	result := getOptionValue(response.Options, "RESULT")
	if result != "OK" {
		return
	}

	verb := strings.ToUpper(cmd.Verb)
	action := strings.ToUpper(cmd.Action)

	switch {
	case verb == "HELLO":
		version := getOptionValue(response.Options, "VERSION")
		if version != "" {
			c.SetVersion(version)
			c.SetState(StateReady)

			// Handle authentication from HELLO
			if user := cmd.Get("USER"); user != "" {
				if s.config.CheckPassword(user, cmd.Get("PASSWORD")) {
					c.SetAuthenticated(user)
				}
			}
		}

	case verb == "SESSION" && action == "CREATE":
		// Session was created, bind it to connection
		if id := getOptionValue(response.Options, "ID"); id != "" {
			c.BindSession(id)
		}
	}
}

// getOptionValue extracts a value from response options by key.
// Options are stored as "KEY=VALUE" strings.
func getOptionValue(options []string, key string) string {
	prefix := key + "="
	for _, opt := range options {
		if strings.HasPrefix(opt, prefix) {
			value := strings.TrimPrefix(opt, prefix)
			// Remove quotes if present
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			return value
		}
	}
	return ""
}

// isHandshakeCommand returns true if the command is a HELLO handshake.
func isHandshakeCommand(cmd *protocol.Command) bool {
	return strings.EqualFold(cmd.Verb, "HELLO")
}

// isAuthCommand returns true if the command is related to authentication.
// Per SAM 3.2, HELLO (with USER/PASSWORD) and AUTH commands can be used
// before authentication is established.
func isAuthCommand(cmd *protocol.Command) bool {
	verb := strings.ToUpper(cmd.Verb)
	return verb == "HELLO" || verb == "AUTH"
}

// sendParseError sends a protocol error response for parse failures.
func (s *Server) sendParseError(c *Connection, err error) error {
	response := protocol.NewResponse("HELLO").
		WithAction("REPLY").
		WithResult("I2P_ERROR").
		WithMessage("parse error: " + err.Error())
	return s.sendResponse(c, response)
}

// isTimeoutError checks if an error is a network timeout.
func (s *Server) isTimeoutError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// sendTimeoutError sends a timeout error response based on connection state.
// Per SAM 3.2:
//   - Before HELLO: HELLO REPLY RESULT=I2P_ERROR MESSAGE="..."
//   - After HELLO: SESSION STATUS RESULT=I2P_ERROR MESSAGE="..."
func (s *Server) sendTimeoutError(c *Connection) {
	var response *protocol.Response

	switch c.State() {
	case StateNew, StateHandshaking:
		// Timeout before HELLO is complete
		response = protocol.NewResponse("HELLO").
			WithAction("REPLY").
			WithResult("I2P_ERROR").
			WithMessage("connection timeout: HELLO not received")
	default:
		// Timeout after HELLO, before next command
		response = protocol.NewResponse("SESSION").
			WithAction("STATUS").
			WithResult("I2P_ERROR").
			WithMessage("connection timeout: no command received")
	}

	// Best effort - ignore write errors since we're closing anyway
	_ = s.sendResponse(c, response)
}

// sendPongTimeoutError sends a PONG timeout error response.
// Per SAM 3.2, PING/PONG is used for keepalive. If PONG is not received
// within the configured timeout, the connection is closed.
func (s *Server) sendPongTimeoutError(c *Connection) {
	response := protocol.NewResponse("SESSION").
		WithAction("STATUS").
		WithResult("I2P_ERROR").
		WithMessage("connection timeout: PONG not received")

	// Best effort - ignore write errors since we're closing anyway
	_ = s.sendResponse(c, response)
}

// sendResponse writes a response to the connection.
func (s *Server) sendResponse(c *Connection, response *protocol.Response) error {
	line := response.String()
	_, err := c.WriteLine(line)
	return err
}

// Close gracefully shuts down the server.
func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil // Already closed
	}

	close(s.done)

	s.mu.Lock()
	listener := s.listener
	connections := make([]*Connection, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()

	// Close listener first
	if listener != nil {
		listener.Close()
	}

	// Close all connections
	for _, c := range connections {
		c.Close()
	}

	return nil
}

// ConnectionCount returns the number of active connections.
func (s *Server) ConnectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections)
}

// Addr returns the listener address, or empty string if not listening.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Done returns a channel that is closed when the server shuts down.
func (s *Server) Done() <-chan struct{} {
	return s.done
}

// ReadLine reads a command line from a buffered reader.
// This is exported for testing and custom connection handling.
func ReadLine(reader *bufio.Reader, maxLen int) (string, error) {
	var line strings.Builder

	for {
		part, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}

		line.Write(part)

		if line.Len() > maxLen {
			return "", io.ErrShortBuffer
		}

		if !isPrefix {
			break
		}
	}

	return line.String(), nil
}

// SendPing sends a PING command to a connection for keepalive.
// Per SAM 3.2, PING/PONG is used for keepalive. The text is echoed back in PONG.
// This method sets the pending PING state on the connection.
func (s *Server) SendPing(c *Connection, text string) error {
	pingCmd := "PING"
	if text != "" {
		pingCmd += " " + text
	}

	c.SetPendingPing(text)

	_, err := c.WriteLine(pingCmd)
	return err
}
