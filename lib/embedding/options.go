package embedding

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/i2cp"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/logger"
)

// Option is a functional option for configuring the Bridge.
type Option func(*Config)

// WithListenAddr sets the SAM TCP listen address.
// Default is ":7656" per SAMv3.md.
func WithListenAddr(addr string) Option {
	return func(c *Config) {
		c.ListenAddr = addr
	}
}

// WithI2CPAddr sets the I2CP router address.
// Default is "127.0.0.1:7654" per I2CP spec.
func WithI2CPAddr(addr string) Option {
	return func(c *Config) {
		c.I2CPAddr = addr
	}
}

// WithDatagramPort sets the UDP port for datagram forwarding.
// Default is 7655 per SAMv3.md.
func WithDatagramPort(port int) Option {
	return func(c *Config) {
		c.DatagramPort = port
	}
}

// WithListener sets a custom net.Listener for the SAM server.
// When provided, ListenAddr is ignored and the bridge uses this listener.
func WithListener(l net.Listener) Option {
	return func(c *Config) {
		c.Listener = l
	}
}

// WithRegistry sets a custom session registry.
// When provided, the bridge uses this registry instead of creating its own.
func WithRegistry(r session.Registry) Option {
	return func(c *Config) {
		c.Registry = r
	}
}

// WithI2CPProvider sets a custom I2CP session provider.
// When provided, the bridge uses this provider instead of creating its own.
func WithI2CPProvider(p session.I2CPSessionProvider) Option {
	return func(c *Config) {
		c.I2CPProvider = p
	}
}

// WithI2CPClient sets the I2CP client for use by DefaultHandlerRegistrar.
// When provided, the default registrar wires StreamManagers for STREAM sessions
// and DatagramConns for DATAGRAM/RAW/DATAGRAM2/DATAGRAM3 sessions.
// Typically called alongside WithI2CPProvider when both are derived from the same client.
func WithI2CPClient(client *i2cp.Client) Option {
	return func(c *Config) {
		c.I2CPClient = client
	}
}

// WithDestinationResolver sets the resolver for NAMING LOOKUP commands.
// The I2CP server provides hosts.txt resolution by default, so this
// resolver typically wraps the I2CP client's LookupDestination call.
func WithDestinationResolver(r handler.DestinationResolver) Option {
	return func(c *Config) {
		c.DestinationResolver = r
	}
}

// WithLogger sets a custom logger instance.
// When provided, the bridge uses this logger instead of creating its own.
func WithLogger(l *logger.Logger) Option {
	return func(c *Config) {
		c.Logger = l
	}
}

// WithTLS enables TLS on the SAM control socket.
// Per SAM 3.2, optional SSL/TLS support may be offered.
func WithTLS(cfg *tls.Config) Option {
	return func(c *Config) {
		c.TLSConfig = cfg
	}
}

// WithAuth sets the SAM authentication users.
// Per SAM 3.2, optional authorization with USER/PASSWORD is supported.
func WithAuth(users map[string]string) Option {
	return func(c *Config) {
		c.AuthUsers = make(map[string]string, len(users))
		for k, v := range users {
			c.AuthUsers[k] = v
		}
	}
}

// WithI2CPCredentials sets I2CP authentication credentials.
func WithI2CPCredentials(username, password string) Option {
	return func(c *Config) {
		c.I2CPUsername = username
		c.I2CPPassword = password
	}
}

// WithHandlerRegistrar sets a custom handler registration function.
// This allows embedders to customize which handlers are registered
// or add custom handlers to the router.
func WithHandlerRegistrar(fn HandlerRegistrarFunc) Option {
	return func(c *Config) {
		c.HandlerRegistrar = fn
	}
}

// WithDebug enables debug logging.
func WithDebug(enabled bool) Option {
	return func(c *Config) {
		c.Debug = enabled
	}
}

// WithEmbeddedRouterTimeout sets the maximum time to wait for the embedded router to become ready.
// Default is 60 seconds.
func WithEmbeddedRouterTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.EmbeddedRouterTimeout = timeout
	}
}
