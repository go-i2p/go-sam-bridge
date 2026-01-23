package embedding

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/embedded"
	"github.com/go-i2p/go-sam-bridge/lib/bridge"
)

// Lifecycle defines the interface for controlling a Bridge.
type Lifecycle interface {
	// Start begins serving SAM connections. Non-blocking.
	// Returns an error if the bridge cannot start.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the bridge.
	// The context can be used to set a timeout for shutdown.
	Stop(ctx context.Context) error

	// Wait blocks until the bridge has stopped.
	// Returns any error that caused the shutdown.
	Wait() error

	// Running returns true if the bridge is actively serving.
	Running() bool
}

// Bridge is an embeddable SAM bridge server.
// It implements the Lifecycle interface for easy integration.
type Bridge struct {
	config         *Config
	deps           *Dependencies
	server         *bridge.Server
	embeddedRouter embedded.EmbeddedRouter

	mu       sync.Mutex
	running  atomic.Bool
	done     chan struct{}
	err      error
	cancelFn context.CancelFunc
}

// Ensure Bridge implements Lifecycle.
var _ Lifecycle = (*Bridge)(nil)

// New creates a new Bridge with the given options.
// Options are applied to a default configuration.
// Returns an error if configuration is invalid.
func New(opts ...Option) (*Bridge, error) {
	// Start with default configuration
	cfg := DefaultConfig()

	// Apply all options
	for _, opt := range opts {
		opt(cfg)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create dependencies
	deps := newDependencies(cfg)

	// Create bridge server
	bridgeConfig := cfg.toBridgeConfig()
	server, err := bridge.NewServer(bridgeConfig, deps.Registry)
	if err != nil {
		return nil, err
	}

	// Register handlers
	registrar := cfg.HandlerRegistrar
	if registrar == nil {
		registrar = DefaultHandlerRegistrar()
	}
	registrar(server.Router(), deps)

	// Register auth handlers if enabled
	authStore := server.AuthStore()
	if authStore != nil && authStore.IsAuthEnabled() {
		RegisterAuthHandlers(server.Router(), authStore, deps)
	}

	// check if something is already listening on I2CPAddr, if it is not, create an embedded router
	var embeddedRouter embedded.EmbeddedRouter
	if checkPortAvailable(bridgeConfig.I2CPAddr) {
		routercfg := config.DefaultRouterConfig()
		routercfg.I2CP.Address = bridgeConfig.I2CPAddr
		var routerErr error
		embeddedRouter, routerErr = embedded.NewStandardEmbeddedRouter(routercfg)
		if routerErr != nil {
			return nil, routerErr
		}
		if routerErr = embeddedRouter.Configure(routercfg); routerErr != nil {
			return nil, routerErr
		}
	}
	return &Bridge{
		config:         cfg,
		deps:           deps,
		server:         server,
		embeddedRouter: embeddedRouter,
		done:           make(chan struct{}),
	}, nil
}

// Start begins serving SAM connections.
// The context is used for cancellation - when cancelled, the bridge stops.
// This method is non-blocking and returns immediately after starting.
func (b *Bridge) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Only start embedded router if we created one (port was available during New())
	if b.embeddedRouter != nil {
		if err := b.embeddedRouter.Start(); err != nil {
			return err
		}
		// Wait for embedded router to start listening
		for checkPortAvailable(b.config.I2CPAddr) {
			time.Sleep(500 * time.Millisecond)
		}
		b.deps.Logger.Info("Embedded router started")
	}

	if b.running.Load() {
		return ErrBridgeAlreadyRunning
	}

	// Create a cancellable context for shutdown
	ctx, cancel := context.WithCancel(ctx)
	b.cancelFn = cancel

	// Start the server in a goroutine
	go func() {
		var err error
		if b.config.Listener != nil {
			// Use custom listener
			err = b.server.Serve(b.config.Listener)
		} else {
			// Create listener from address
			err = b.server.ListenAndServe()
		}

		// Store error and signal done
		b.mu.Lock()
		b.err = err
		b.running.Store(false)
		b.mu.Unlock()

		close(b.done)
	}()

	b.running.Store(true)

	// Watch for context cancellation
	go func() {
		<-ctx.Done()
		b.Stop(context.Background())
	}()

	b.deps.Logger.WithField("addr", b.config.ListenAddr).Info("SAM bridge started")

	return nil
}

// Stop gracefully shuts down the bridge.
// The context can be used to set a timeout for shutdown operations.
func (b *Bridge) Stop(ctx context.Context) error {
	b.mu.Lock()
	if !b.running.Load() {
		b.mu.Unlock()
		return nil // Already stopped
	}
	b.mu.Unlock()

	b.deps.Logger.Info("Stopping SAM bridge...")

	// Cancel the start context
	if b.cancelFn != nil {
		b.cancelFn()
	}

	// Close the server
	if err := b.server.Close(); err != nil {
		b.deps.Logger.WithError(err).Warn("Error closing server")
	}

	// Close all sessions
	if err := b.deps.Registry.Close(); err != nil {
		b.deps.Logger.WithError(err).Warn("Error closing sessions")
	}

	b.deps.Logger.Info("SAM bridge stopped")

	// Stop embedded router if we started one
	if b.embeddedRouter != nil {
		if err := b.embeddedRouter.Stop(); err != nil {
			b.deps.Logger.WithError(err).Warn("Error stopping embedded router")
		}
		b.deps.Logger.Info("Embedded router stopped")
	}

	return nil
}

// Wait blocks until the bridge has stopped.
// Returns any error that caused the shutdown.
func (b *Bridge) Wait() error {
	<-b.done
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// Running returns true if the bridge is actively serving.
func (b *Bridge) Running() bool {
	return b.running.Load()
}

// Server returns the underlying bridge.Server.
// This allows advanced access to the server's Router and other internals.
func (b *Bridge) Server() *bridge.Server {
	return b.server
}

// Dependencies returns the bridge's dependencies.
// This allows access to the registry, logger, etc.
func (b *Bridge) Dependencies() *Dependencies {
	return b.deps
}

// Config returns the bridge's configuration.
// This is a read-only view; modifying the returned config has no effect.
func (b *Bridge) Config() *Config {
	return b.config
}
