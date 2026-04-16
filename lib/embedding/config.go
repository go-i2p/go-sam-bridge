// Package embedding provides an embeddable API for third-party Go applications
// to initialize and run a SAM bridge server with minimal setup code.
package embedding

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/bridge"
	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/i2cp"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/logger"
)

// Default configuration values.
const (
	// DefaultListenAddr is the standard SAM port per SAMv3.md.
	DefaultListenAddr = ":7656"

	// DefaultI2CPAddr is the standard I2CP port per I2CP spec.
	DefaultI2CPAddr = "127.0.0.1:7654"

	// DefaultDatagramPort is the standard SAM UDP port per SAMv3.md.
	DefaultDatagramPort = 7655

	// DefaultEmbeddedRouterTimeout is the maximum time to wait for the embedded router.
	DefaultEmbeddedRouterTimeout = 60 * time.Second
)

// HandlerRegistrarFunc is a function that registers handlers with a router.
// It receives the router and dependencies for custom handler setup.
type HandlerRegistrarFunc func(router *handler.Router, deps *Dependencies)

// Config holds the complete configuration for an embedded SAM bridge.
// It extends bridge.Config with I2CP and embedding-specific settings.
type Config struct {
	// ListenAddr is the SAM TCP listen address (default ":7656").
	ListenAddr string

	// I2CPAddr is the I2CP router address (default "127.0.0.1:7654").
	I2CPAddr string

	// DatagramPort is the UDP port for datagram forwarding (default 7655).
	DatagramPort int

	// I2CPUsername for I2CP authentication (optional).
	I2CPUsername string

	// I2CPPassword for I2CP authentication (optional).
	I2CPPassword string

	// TLSConfig enables TLS on the control socket if non-nil.
	TLSConfig *tls.Config

	// AuthUsers maps usernames to passwords for SAM authentication.
	// Empty map disables authentication.
	AuthUsers map[string]string

	// Listener is a custom net.Listener for the SAM server.
	// If nil, the bridge creates its own listener on ListenAddr.
	Listener net.Listener

	// Registry is a custom session registry.
	// If nil, a default registry is created.
	Registry session.Registry

	// I2CPProvider is a custom I2CP session provider.
	// If nil, the bridge creates one using I2CPAddr.
	I2CPProvider session.I2CPSessionProvider

	// DestinationResolver resolves I2P hostnames and .b32.i2p addresses.
	// The I2CP server provides hosts.txt resolution by default, so this
	// resolver typically delegates to the I2CP client.
	// If nil, NAMING LOOKUP returns KEY_NOT_FOUND for hostnames.
	DestinationResolver handler.DestinationResolver

	// Logger is a custom logger instance.
	// If nil, a default logger is created.
	Logger *logger.Logger

	// I2CPClient is the I2CP client for I2CP-backed sessions.
	// When provided alongside I2CPProvider, DefaultHandlerRegistrar uses it to
	// wire StreamManagers for STREAM sessions and DatagramConns for datagram sessions.
	// If nil, streaming and datagram send paths will not be functional.
	I2CPClient *i2cp.Client

	// HandlerRegistrar is a custom function to register handlers.
	// If nil, DefaultHandlerRegistrar is used.
	HandlerRegistrar HandlerRegistrarFunc

	// Debug enables debug logging.
	Debug bool

	// EmbeddedRouterTimeout is the maximum time to wait for the embedded router to become ready.
	// Default is 60 seconds.
	EmbeddedRouterTimeout time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
// All fields can be overridden via functional options.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:            DefaultListenAddr,
		I2CPAddr:              DefaultI2CPAddr,
		DatagramPort:          DefaultDatagramPort,
		AuthUsers:             make(map[string]string),
		Debug:                 false,
		EmbeddedRouterTimeout: DefaultEmbeddedRouterTimeout,
	}
}

// Validate checks that the configuration is valid.
// Returns an error if any required fields are missing or invalid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" && c.Listener == nil {
		return ErrMissingListenAddr
	}
	if c.I2CPAddr == "" && c.I2CPProvider == nil {
		return ErrMissingI2CPAddr
	}
	return nil
}

// toBridgeConfig converts embedding.Config to bridge.Config.
func (c *Config) toBridgeConfig() *bridge.Config {
	// Start with default bridge config to get proper defaults
	cfg := bridge.DefaultConfig()

	// Override with embedding config values
	cfg.ListenAddr = c.ListenAddr
	cfg.I2CPAddr = c.I2CPAddr
	cfg.DatagramPort = c.DatagramPort
	cfg.TLSConfig = c.TLSConfig

	// Copy auth users if any
	if len(c.AuthUsers) > 0 {
		cfg.Auth.Required = true
		cfg.Auth.Users = make(map[string]string, len(c.AuthUsers))
		for k, v := range c.AuthUsers {
			cfg.Auth.Users[k] = v
		}
	}

	return cfg
}
