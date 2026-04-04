package embedding

import (
	"github.com/go-i2p/go-sam-bridge/lib/bridge"
	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// DefaultHandlerRegistrar returns a HandlerRegistrarFunc that registers
// all standard SAM command handlers. This is the default handler setup
// used when no custom HandlerRegistrar is provided.
//
// This registers handlers for:
//   - HELLO VERSION (handshake)
//   - SESSION CREATE/ADD/REMOVE
//   - STREAM CONNECT/ACCEPT/FORWARD
//   - DATAGRAM SEND
//   - RAW SEND
//   - NAMING LOOKUP
//   - DEST GENERATE
//   - PING
//   - QUIT/STOP/EXIT
//   - HELP
//   - AUTH ENABLE/DISABLE/ADD/REMOVE (if authentication enabled)
func DefaultHandlerRegistrar() HandlerRegistrarFunc {
	return func(router *handler.Router, deps *Dependencies) {
		log := deps.Logger

		// Register HELLO handler (must be first command per SAMv3.md)
		helloConfig := handler.DefaultHelloConfig()
		helloHandler := handler.NewHelloHandler(helloConfig)
		router.Register("HELLO VERSION", helloHandler)
		log.Debug("Registered HELLO VERSION handler")

		// Create STREAM handlers
		streamConnector := handler.NewStreamingConnector()
		streamAcceptor := handler.NewStreamingAcceptor()
		streamForwarder := handler.NewStreamingForwarder()

		// Register SESSION handler with I2CP provider for tunnel waiting
		sessionHandler := handler.NewSessionHandler(deps.DestManager)
		if deps.I2CPProvider != nil {
			sessionHandler.SetI2CPProvider(deps.I2CPProvider)
		}

		// Set session created callback to wire StreamManager per session
		sessionHandler.SetSessionCreatedCallback(createStreamManagerCallback(
			deps, streamConnector, streamAcceptor, streamForwarder,
		))

		router.Register("SESSION CREATE", sessionHandler)
		router.Register("SESSION ADD", sessionHandler)
		router.Register("SESSION REMOVE", sessionHandler)
		log.Debug("Registered SESSION handlers")

		// Register STREAM handlers
		streamHandler := handler.NewStreamHandler(streamConnector, streamAcceptor, streamForwarder)
		router.Register("STREAM CONNECT", streamHandler)
		router.Register("STREAM ACCEPT", streamHandler)
		router.Register("STREAM FORWARD", streamHandler)
		log.Debug("Registered STREAM handlers")

		// Register DATAGRAM handler
		handler.RegisterDatagramHandler(router)
		log.Debug("Registered DATAGRAM handler")

		// Register RAW handler
		rawHandler := handler.NewRawHandler()
		router.Register("RAW SEND", rawHandler)
		log.Debug("Registered RAW handler")

		// Register NAMING handler
		namingHandler := handler.NewNamingHandler(deps.DestManager)
		if deps.DestResolver != nil {
			namingHandler.SetDestinationResolver(deps.DestResolver)
		}
		router.Register("NAMING LOOKUP", namingHandler)
		log.Debug("Registered NAMING handler")

		// Register DEST handler
		destHandler := handler.NewDestHandler(deps.DestManager)
		router.Register("DEST GENERATE", destHandler)
		log.Debug("Registered DEST handler")

		// Register PING handler
		handler.RegisterPingHandler(router)
		log.Debug("Registered PING handler")

		// Register utility handlers (QUIT, HELP, etc.)
		handler.RegisterUtilityHandlers(router)
		handler.RegisterHelpHandler(router)
		log.Debug("Registered utility handlers")

		log.WithField("count", router.Count()).Info("All SAM command handlers registered")
	}
}

// RegisterAuthHandlers adds authentication handlers to a router.
// Call this separately when authentication is enabled.
func RegisterAuthHandlers(router *handler.Router, authStore *bridge.AuthStore, deps *Dependencies) {
	handler.RegisterAuthHandlers(router, authStore)
	deps.Logger.Debug("Registered AUTH handlers")
}

// createStreamManagerCallback creates a session callback that wires
// StreamManager for STREAM sessions. This is internal and not exported.
func createStreamManagerCallback(
	deps *Dependencies,
	connector handler.StreamConnector,
	acceptor handler.StreamAcceptor,
	forwarder handler.StreamForwarder,
) handler.SessionCreatedCallback {
	return func(sess session.Session, i2cpHandle session.I2CPSessionHandle) {
		// Only create StreamManager for STREAM sessions with I2CP integration
		if sess.Style() != session.StyleStream || i2cpHandle == nil {
			return
		}

		// StreamManager creation would happen here if we had access to go-streaming
		// For now, this is a placeholder that can be extended when I2CP integration is available
		deps.Logger.WithField("sessionID", sess.ID()).Debug("STREAM session created")
	}
}
