package bridge

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// ConnectionState represents the current state of a client connection.
type ConnectionState int

const (
	// StateNew indicates a new connection awaiting HELLO handshake.
	StateNew ConnectionState = iota

	// StateHandshaking indicates HELLO received but not yet completed.
	StateHandshaking

	// StateReady indicates successful HELLO, ready for commands.
	StateReady

	// StateSessionBound indicates a session has been created and bound.
	StateSessionBound

	// StateClosed indicates the connection has been closed.
	StateClosed
)

// String returns a human-readable state name.
func (s ConnectionState) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateHandshaking:
		return "HANDSHAKING"
	case StateReady:
		return "READY"
	case StateSessionBound:
		return "SESSION_BOUND"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Connection represents a single SAM client connection.
// It manages connection state, authentication, and the bound session.
// All fields are protected by a mutex for concurrent access.
type Connection struct {
	mu sync.RWMutex

	// conn is the underlying network connection.
	conn net.Conn

	// reader is the buffered reader for the connection.
	reader *bufio.Reader

	// state is the current connection state.
	state ConnectionState

	// version is the negotiated SAM protocol version.
	version string

	// authenticated indicates if the client has authenticated.
	authenticated bool

	// username is the authenticated username (empty if not authenticated).
	username string

	// sessionID is the bound session ID (empty if no session bound).
	sessionID string

	// createdAt is when the connection was established.
	createdAt time.Time

	// lastActivity is the time of the last command received.
	lastActivity time.Time

	// remoteAddr is the client's remote address (cached for logging after close).
	remoteAddr string

	// pendingPing tracks an outstanding PING awaiting PONG response.
	// Nil when no PING is pending.
	pendingPing *PendingPing
}

// PendingPing tracks an outstanding PING command awaiting PONG.
// Per SAM 3.2, PING/PONG is used for keepalive.
type PendingPing struct {
	// Text is the arbitrary text sent with the PING.
	Text string

	// SentAt is when the PING was sent.
	SentAt time.Time
}

// NewConnection creates a new Connection for the given net.Conn.
func NewConnection(conn net.Conn, bufferSize int) *Connection {
	now := time.Now()
	return &Connection{
		conn:         conn,
		reader:       bufio.NewReaderSize(conn, bufferSize),
		state:        StateNew,
		createdAt:    now,
		lastActivity: now,
		remoteAddr:   conn.RemoteAddr().String(),
	}
}

// Conn returns the underlying net.Conn.
func (c *Connection) Conn() net.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// Reader returns the buffered reader.
func (c *Connection) Reader() *bufio.Reader {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reader
}

// State returns the current connection state.
func (c *Connection) State() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// SetState updates the connection state.
func (c *Connection) SetState(state ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
}

// Version returns the negotiated SAM protocol version.
func (c *Connection) Version() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// SetVersion sets the negotiated SAM protocol version.
func (c *Connection) SetVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = version
}

// IsAuthenticated returns true if the client has authenticated.
func (c *Connection) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authenticated
}

// SetAuthenticated marks the connection as authenticated with the given username.
func (c *Connection) SetAuthenticated(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authenticated = true
	c.username = username
}

// Username returns the authenticated username.
func (c *Connection) Username() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.username
}

// SessionID returns the bound session ID.
func (c *Connection) SessionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionID
}

// BindSession binds a session to this connection.
func (c *Connection) BindSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = sessionID
	c.state = StateSessionBound
}

// UnbindSession unbinds the session from this connection.
func (c *Connection) UnbindSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = ""
	if c.state == StateSessionBound {
		c.state = StateReady
	}
}

// CreatedAt returns when the connection was established.
func (c *Connection) CreatedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.createdAt
}

// LastActivity returns the time of the last activity.
func (c *Connection) LastActivity() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastActivity
}

// UpdateActivity updates the last activity timestamp.
func (c *Connection) UpdateActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastActivity = time.Now()
}

// RemoteAddr returns the client's remote address.
func (c *Connection) RemoteAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remoteAddr
}

// IdleDuration returns how long the connection has been idle.
func (c *Connection) IdleDuration() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.lastActivity)
}

// Age returns how long the connection has been open.
func (c *Connection) Age() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.createdAt)
}

// Close closes the underlying connection and updates state.
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateClosed
	return c.conn.Close()
}

// IsClosed returns true if the connection is closed.
func (c *Connection) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == StateClosed
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Connection) SetReadDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *Connection) SetWriteDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.SetWriteDeadline(t)
}

// Write writes data to the underlying connection.
func (c *Connection) Write(data []byte) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.Write(data)
}

// WriteString writes a string to the underlying connection.
func (c *Connection) WriteString(s string) (int, error) {
	return c.Write([]byte(s))
}

// WriteLine writes a string with CRLF terminator to the connection.
// Per SAM spec, responses are terminated with newline.
func (c *Connection) WriteLine(s string) (int, error) {
	return c.Write([]byte(s + "\n"))
}

// SetPendingPing records that a PING has been sent and is awaiting PONG.
// Per SAM 3.2, PING/PONG is used for keepalive.
func (c *Connection) SetPendingPing(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingPing = &PendingPing{
		Text:   text,
		SentAt: time.Now(),
	}
}

// GetPendingPing returns the pending PING if one is outstanding.
// Returns nil if no PING is pending.
func (c *Connection) GetPendingPing() *PendingPing {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pendingPing
}

// ClearPendingPing clears any pending PING after PONG is received.
func (c *Connection) ClearPendingPing() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingPing = nil
}

// IsPongOverdue returns true if a PING is pending and the timeout has elapsed.
// timeout should be the configured PongTimeout duration.
func (c *Connection) IsPongOverdue(timeout time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.pendingPing == nil || timeout <= 0 {
		return false
	}
	return time.Since(c.pendingPing.SentAt) > timeout
}
