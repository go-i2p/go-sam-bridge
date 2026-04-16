// Package embedding provides an embeddable API for initializing and running
// a SAM (Simple Anonymous Messaging) bridge server in third-party Go applications.
//
// The embedding package enables applications to integrate SAM bridge functionality
// with minimal setup code, using functional options for configuration and
// context-aware lifecycle management.
//
// # Basic Usage
//
// Create and start a bridge with default settings:
//
//	bridge, err := embedding.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	if err := bridge.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Wait for interrupt
//	sig := make(chan os.Signal, 1)
//	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
//	<-sig
//
//	bridge.Stop(context.Background())
//
// # Configuration with Options
//
// Use functional options to customize the bridge:
//
//	bridge, err := embedding.New(
//	    embedding.WithListenAddr(":7656"),
//	    embedding.WithI2CPAddr("127.0.0.1:7654"),
//	    embedding.WithLogger(myLogger),
//	    embedding.WithDebug(true),
//	)
//
// # Available Options
//
//   - WithListenAddr: Set SAM TCP listen address (default ":7656")
//   - WithI2CPAddr: Set I2CP router address (default "127.0.0.1:7654")
//   - WithDatagramPort: Set UDP datagram port (default 7655)
//   - WithListener: Provide custom net.Listener
//   - WithRegistry: Provide custom session.Registry
//   - WithI2CPProvider: Provide custom I2CP session provider
//   - WithLogger: Provide custom *logger.Logger (github.com/go-i2p/logger)
//   - WithTLS: Enable TLS with custom config
//   - WithAuth: Set SAM authentication users
//   - WithI2CPCredentials: Set I2CP authentication
//   - WithHandlerRegistrar: Custom handler registration
//   - WithDebug: Enable debug logging
//
// # Custom Handlers
//
// Register custom handlers alongside or instead of default handlers:
//
//	customRegistrar := func(router *handler.Router, deps *embedding.Dependencies) {
//	    // Register default handlers first
//	    embedding.DefaultHandlerRegistrar()(router, deps)
//
//	    // Add custom handler
//	    router.Register("CUSTOM COMMAND", myHandler)
//	}
//
//	bridge, err := embedding.New(
//	    embedding.WithHandlerRegistrar(customRegistrar),
//	)
//
// # Lifecycle Management
//
// The Bridge implements the Lifecycle interface:
//
//   - Start(ctx): Begin serving (non-blocking)
//   - Stop(ctx): Graceful shutdown
//   - Wait(): Block until stopped
//   - Running(): Check if bridge is active
//
// Context cancellation in Start() triggers automatic shutdown.
//
// # Thread Safety
//
// Bridge methods are safe for concurrent use. The bridge uses atomic operations
// and mutexes to protect shared state during lifecycle transitions.
//
// # SAM Protocol Version
//
// This implementation supports SAM protocol versions 3.0 through 3.3.
// See SAMv3.md in the project root for the complete protocol specification.
package embedding
