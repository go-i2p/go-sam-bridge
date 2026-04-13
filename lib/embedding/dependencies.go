package embedding

import (
	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/i2cp"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/sirupsen/logrus"
)

// Dependencies bundles shared resources used by handlers.
// This struct is passed to handler registrar functions to allow
// access to common dependencies without tight coupling.
type Dependencies struct {
	// Registry manages all active sessions.
	Registry session.Registry

	// I2CPProvider creates I2CP sessions for SAM sessions.
	I2CPProvider session.I2CPSessionProvider

	// DestManager handles I2P destination creation and management.
	DestManager destination.Manager

	// DestResolver resolves I2P hostnames and .b32.i2p addresses via I2CP.
	// The I2CP server provides hosts.txt resolution by default.
	DestResolver handler.DestinationResolver

	// I2CPClient is the I2CP client used to create streaming and datagram connections.
	// When non-nil, DefaultHandlerRegistrar wires StreamManagers for STREAM sessions
	// and DatagramConns for DATAGRAM/RAW/DATAGRAM2/DATAGRAM3 sessions.
	I2CPClient *i2cp.Client

	// DatagramPort is the local UDP port for datagram sessions (default 7655).
	DatagramPort int

	// Logger is the structured logger for all components.
	Logger *logrus.Logger
}

// newDependencies creates a Dependencies struct from the configuration.
// It initializes any nil dependencies with their default implementations.
func newDependencies(cfg *Config) *Dependencies {
	deps := &Dependencies{
		Registry:     cfg.Registry,
		I2CPProvider: cfg.I2CPProvider,
		DestManager:  destination.NewManager(),
		DestResolver: cfg.DestinationResolver,
		I2CPClient:   cfg.I2CPClient,
		DatagramPort: cfg.DatagramPort,
		Logger:       cfg.Logger,
	}

	// Create default registry if not provided
	if deps.Registry == nil {
		deps.Registry = session.NewRegistry()
	}

	// Create default logger if not provided
	if deps.Logger == nil {
		deps.Logger = logrus.New()
		if cfg.Debug {
			deps.Logger.SetLevel(logrus.DebugLevel)
		} else {
			deps.Logger.SetLevel(logrus.InfoLevel)
		}
	}

	return deps
}
