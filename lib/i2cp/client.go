// Package i2cp provides I2CP client integration for the SAM bridge.
// This package wraps the go-i2cp library to provide session management
// and tunnel operations required by the SAM protocol.
//
// The I2CP (I2P Control Protocol) is the low-level protocol used to
// communicate with the I2P router for creating sessions, sending messages,
// and managing tunnel lifecycles.
//
// See PLAN.md section 1.7 for integration requirements.
// See SAMv3.md for how SAM sessions map to I2CP sessions.
package i2cp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// Ensure interface is not nil at compile time
var _ = (*go_i2cp.Client)(nil)

// Client wraps the go-i2cp client to provide a SAM-friendly interface.
// It manages the connection to the I2P router and session lifecycle.
//
// Thread-safety: All methods are safe for concurrent use.
// The Client maintains a single connection to the I2P router and
// multiplexes all SAM sessions over it.
type Client struct {
	mu sync.RWMutex

	// i2cpClient is the underlying go-i2cp client.
	i2cpClient *go_i2cp.Client

	// config holds the I2CP connection configuration.
	config *ClientConfig

	// connected indicates if we have an active router connection.
	connected bool

	// sessions tracks active I2CP sessions by SAM session ID.
	sessions map[string]*I2CPSession

	// callbacks holds the client-level callbacks.
	callbacks *ClientCallbacks
}

// ClientConfig holds configuration for connecting to the I2P router.
type ClientConfig struct {
	// RouterAddr is the I2CP router address (default: 127.0.0.1:7654).
	RouterAddr string

	// Username is the optional I2CP username for authentication.
	Username string

	// Password is the optional I2CP password for authentication.
	Password string

	// TLSEnabled enables TLS for the I2CP connection.
	TLSEnabled bool

	// TLSInsecure allows insecure TLS connections (for testing).
	TLSInsecure bool

	// ConnectTimeout is the timeout for connecting to the router.
	ConnectTimeout time.Duration

	// SessionTimeout is the timeout for session creation.
	SessionTimeout time.Duration
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
// Uses standard I2CP port 7654 on localhost.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		RouterAddr:     "127.0.0.1:7654",
		ConnectTimeout: 30 * time.Second,
		SessionTimeout: 60 * time.Second,
	}
}

// ClientCallbacks holds callbacks for client-level events.
type ClientCallbacks struct {
	// OnConnected is called when the router connection is established.
	OnConnected func()

	// OnDisconnected is called when the router connection is lost.
	OnDisconnected func(err error)

	// OnRouterInfo is called when router info is received.
	OnRouterInfo func(version string)
}

// NewClient creates a new I2CP client with the given configuration.
// The client is not connected until Connect() is called.
//
// Per PLAN.md section 1.7: The client wrapper provides connection to
// the I2P router and session creation capabilities.
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}

	return &Client{
		config:   config,
		sessions: make(map[string]*I2CPSession),
	}
}

// Connect establishes a connection to the I2P router.
// This must be called before creating any sessions.
//
// The connection process:
//  1. Parse router address and configure go-i2cp properties
//  2. Create go-i2cp client with callbacks
//  3. Establish TCP/TLS connection to router
//  4. Start I2CP message processing
//
// Returns an error if the connection fails or times out.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil // Already connected
	}

	// Parse host and port from RouterAddr
	host, port, err := net.SplitHostPort(c.config.RouterAddr)
	if err != nil {
		return fmt.Errorf("invalid router address %q: %w", c.config.RouterAddr, err)
	}

	// Create go-i2cp client with our callbacks
	callbacks := &go_i2cp.ClientCallBacks{
		OnConnect:    c.onConnect,
		OnDisconnect: c.onDisconnect,
	}

	i2cpClient := go_i2cp.NewClient(callbacks)

	// Configure I2CP properties
	i2cpClient.SetProperty("i2cp.tcp.host", host)
	i2cpClient.SetProperty("i2cp.tcp.port", port)

	if c.config.Username != "" {
		i2cpClient.SetProperty("i2cp.username", c.config.Username)
	}
	if c.config.Password != "" {
		i2cpClient.SetProperty("i2cp.password", c.config.Password)
	}
	if c.config.TLSEnabled {
		i2cpClient.SetProperty("i2cp.SSL", "true")
	}
	if c.config.TLSInsecure {
		i2cpClient.SetProperty("i2cp.SSL.insecure", "true")
	}

	// Apply timeout to context if not already set
	connectCtx := ctx
	if c.config.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		connectCtx, cancel = context.WithTimeout(ctx, c.config.ConnectTimeout)
		defer cancel()
	}

	// Connect to the I2P router
	if err := i2cpClient.Connect(connectCtx); err != nil {
		return fmt.Errorf("failed to connect to I2P router at %s: %w", c.config.RouterAddr, err)
	}

	// Start the I2CP message processing loop in a background goroutine
	go func() {
		// ProcessIO takes a context; use background since connection is already established
		_ = i2cpClient.ProcessIO(context.Background())
	}()

	c.i2cpClient = i2cpClient
	c.connected = true

	return nil
}

// Close closes the connection to the I2P router and all sessions.
// Safe to call multiple times.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	// Close all active sessions
	for id, sess := range c.sessions {
		if err := sess.Close(); err != nil {
			// Log but continue closing other sessions
			_ = err // Suppress unused error
		}
		delete(c.sessions, id)
	}

	// Close the I2CP client
	if c.i2cpClient != nil {
		c.i2cpClient.Close()
		c.i2cpClient = nil
	}

	c.connected = false
	return nil
}

// IsConnected returns true if connected to the I2P router.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// I2CPClient returns the underlying go-i2cp client.
// This allows direct access for advanced operations.
// Returns nil if not connected.
func (c *Client) I2CPClient() *go_i2cp.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.i2cpClient
}

// GetSession returns the I2CP session for the given SAM session ID.
// Returns nil if no session exists with that ID.
func (c *Client) GetSession(samSessionID string) *I2CPSession {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessions[samSessionID]
}

// RegisterSession registers an I2CP session with a SAM session ID.
// This allows looking up sessions by their SAM identifier.
func (c *Client) RegisterSession(samSessionID string, sess *I2CPSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[samSessionID] = sess
}

// UnregisterSession removes an I2CP session registration.
func (c *Client) UnregisterSession(samSessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, samSessionID)
}

// RouterVersion returns the connected router's version string.
// Returns empty string if not connected or version unknown.
func (c *Client) RouterVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.i2cpClient == nil {
		return ""
	}
	v := c.i2cpClient.RouterVersion()
	return v.String()
}

// onConnect is called when the I2CP connection is established.
// Matches go-i2cp ClientCallBacks.OnConnect signature.
func (c *Client) onConnect(client *go_i2cp.Client) {
	if c.callbacks != nil && c.callbacks.OnConnected != nil {
		c.callbacks.OnConnected()
	}
}

// onDisconnect is called when the I2CP connection is lost.
// Matches go-i2cp ClientCallBacks.OnDisconnect signature.
func (c *Client) onDisconnect(client *go_i2cp.Client, reason string, opaque *interface{}) {
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()

	if c.callbacks != nil && c.callbacks.OnDisconnected != nil {
		var err error
		if reason != "" {
			err = fmt.Errorf("disconnected: %s", reason)
		}
		c.callbacks.OnDisconnected(err)
	}
}

// SetCallbacks sets the client callbacks.
// Should be called before Connect().
func (c *Client) SetCallbacks(callbacks *ClientCallbacks) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callbacks = callbacks
}
