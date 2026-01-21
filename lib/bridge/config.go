// Package bridge implements the SAM bridge server per SAMv3.md specification.
// The bridge accepts TCP connections from SAM clients and processes SAM protocol
// commands, dispatching them to appropriate handlers.
package bridge

import (
	"crypto/tls"
	"time"
)

// Default configuration values per SAMv3.md specification.
const (
	// DefaultListenAddr is the default SAM bridge TCP listen address.
	// Per SAM spec, the standard SAM port is 7656.
	DefaultListenAddr = ":7656"

	// DefaultI2CPAddr is the default I2CP router address.
	// Per I2CP spec, the standard I2CP port is 7654.
	DefaultI2CPAddr = "127.0.0.1:7654"

	// DefaultDatagramPort is the default UDP port for datagram forwarding.
	// Per SAM spec, the standard datagram port is 7655.
	DefaultDatagramPort = 7655

	// DefaultHandshakeTimeout is the maximum time allowed for HELLO handshake.
	// Per SAM 3.2, servers may implement timeouts for HELLO.
	DefaultHandshakeTimeout = 30 * time.Second

	// DefaultCommandTimeout is the maximum time allowed between commands.
	// Per SAM 3.2, servers may implement timeouts for subsequent commands.
	DefaultCommandTimeout = 60 * time.Second

	// DefaultPongTimeout is the maximum time to wait for PONG after PING.
	// Per SAM 3.2, PING/PONG is used for keepalive.
	DefaultPongTimeout = 30 * time.Second

	// DefaultReadBufferSize is the default buffer size for reading commands.
	DefaultReadBufferSize = 8192

	// DefaultMaxLineLength is the maximum allowed command line length.
	// This prevents memory exhaustion from malicious clients.
	DefaultMaxLineLength = 65536
)

// Config holds the SAM bridge server configuration.
// All fields have sensible defaults that can be overridden.
type Config struct {
	// ListenAddr is the TCP address to listen on (e.g., ":7656", "127.0.0.1:7656").
	ListenAddr string

	// I2CPAddr is the I2CP router address for tunnel management.
	I2CPAddr string

	// DatagramPort is the UDP port for datagram forwarding (0 to disable).
	DatagramPort int

	// TLSConfig enables TLS on the control socket if non-nil.
	// Per SAM 3.2, optional SSL/TLS support may be offered.
	TLSConfig *tls.Config

	// Auth holds authentication configuration.
	// Per SAM 3.2, optional authorization with USER/PASSWORD is supported.
	Auth AuthConfig

	// Timeouts holds connection timeout settings.
	Timeouts TimeoutConfig

	// Limits holds connection limits and buffer sizes.
	Limits LimitConfig
}

// AuthConfig holds authentication settings per SAM 3.2.
type AuthConfig struct {
	// Required indicates if authentication is required for all connections.
	// When true, clients must provide USER/PASSWORD in HELLO.
	Required bool

	// Users maps usernames to passwords for authentication.
	// Empty map with Required=false disables authentication.
	Users map[string]string
}

// TimeoutConfig holds timeout settings for connections.
type TimeoutConfig struct {
	// Handshake is the maximum time to wait for HELLO after connection.
	// Per SAM 3.2, servers may implement timeouts for HELLO.
	Handshake time.Duration

	// Command is the maximum time to wait between commands after HELLO.
	// Per SAM 3.2, servers may implement timeouts for subsequent commands.
	Command time.Duration

	// Idle is the maximum time a connection can be idle (0 = no limit).
	Idle time.Duration

	// PongTimeout is the maximum time to wait for PONG after sending PING.
	// Per SAM 3.2, PING/PONG is used for keepalive.
	// If a PONG is not received within this duration, the connection may be closed.
	PongTimeout time.Duration
}

// LimitConfig holds buffer and connection limits.
type LimitConfig struct {
	// ReadBufferSize is the buffer size for reading commands.
	ReadBufferSize int

	// MaxLineLength is the maximum allowed command line length.
	MaxLineLength int

	// MaxConnections is the maximum number of concurrent connections (0 = no limit).
	MaxConnections int

	// MaxSessionsPerClient is the maximum sessions per client IP (0 = no limit).
	MaxSessionsPerClient int
}

// DefaultConfig returns a Config with default values per SAMv3.md.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:   DefaultListenAddr,
		I2CPAddr:     DefaultI2CPAddr,
		DatagramPort: DefaultDatagramPort,
		TLSConfig:    nil,
		Auth: AuthConfig{
			Required: false,
			Users:    make(map[string]string),
		},
		Timeouts: TimeoutConfig{
			Handshake:   DefaultHandshakeTimeout,
			Command:     DefaultCommandTimeout,
			Idle:        0, // No idle timeout by default
			PongTimeout: DefaultPongTimeout,
		},
		Limits: LimitConfig{
			ReadBufferSize:       DefaultReadBufferSize,
			MaxLineLength:        DefaultMaxLineLength,
			MaxConnections:       0, // No limit
			MaxSessionsPerClient: 0, // No limit
		},
	}
}

// Validate checks the configuration for errors and returns an error if invalid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return &ConfigError{Field: "ListenAddr", Message: "cannot be empty"}
	}
	if c.I2CPAddr == "" {
		return &ConfigError{Field: "I2CPAddr", Message: "cannot be empty"}
	}
	if c.DatagramPort < 0 || c.DatagramPort > 65535 {
		return &ConfigError{Field: "DatagramPort", Message: "must be 0-65535"}
	}
	if c.Timeouts.Handshake < 0 {
		return &ConfigError{Field: "Timeouts.Handshake", Message: "cannot be negative"}
	}
	if c.Timeouts.Command < 0 {
		return &ConfigError{Field: "Timeouts.Command", Message: "cannot be negative"}
	}
	if c.Limits.ReadBufferSize <= 0 {
		return &ConfigError{Field: "Limits.ReadBufferSize", Message: "must be positive"}
	}
	if c.Limits.MaxLineLength <= 0 {
		return &ConfigError{Field: "Limits.MaxLineLength", Message: "must be positive"}
	}
	return nil
}

// WithListenAddr returns a copy of the config with the listen address set.
func (c *Config) WithListenAddr(addr string) *Config {
	newCfg := *c
	newCfg.ListenAddr = addr
	return &newCfg
}

// WithI2CPAddr returns a copy of the config with the I2CP address set.
func (c *Config) WithI2CPAddr(addr string) *Config {
	newCfg := *c
	newCfg.I2CPAddr = addr
	return &newCfg
}

// WithTLS returns a copy of the config with TLS enabled.
func (c *Config) WithTLS(tlsConfig *tls.Config) *Config {
	newCfg := *c
	newCfg.TLSConfig = tlsConfig
	return &newCfg
}

// WithAuth returns a copy of the config with authentication configured.
func (c *Config) WithAuth(required bool, users map[string]string) *Config {
	newCfg := *c
	newCfg.Auth.Required = required
	newCfg.Auth.Users = users
	return &newCfg
}

// AddUser adds a user to the authentication configuration.
// This modifies the config in place.
func (c *Config) AddUser(username, password string) {
	if c.Auth.Users == nil {
		c.Auth.Users = make(map[string]string)
	}
	c.Auth.Users[username] = password
}

// RemoveUser removes a user from the authentication configuration.
// This modifies the config in place.
func (c *Config) RemoveUser(username string) {
	delete(c.Auth.Users, username)
}

// HasUser checks if a user exists in the authentication configuration.
func (c *Config) HasUser(username string) bool {
	_, ok := c.Auth.Users[username]
	return ok
}

// CheckPassword verifies the password for a user.
// Returns true if the user exists and the password matches.
func (c *Config) CheckPassword(username, password string) bool {
	storedPassword, ok := c.Auth.Users[username]
	return ok && storedPassword == password
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "config error: " + e.Field + " " + e.Message
}
