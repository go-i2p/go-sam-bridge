package embedding

import (
	"github.com/go-i2p/go-datagrams"
	"github.com/go-i2p/go-sam-bridge/lib/bridge"
	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/i2cp"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	samstreaming "github.com/go-i2p/go-sam-bridge/lib/streaming"
	gostreaming "github.com/go-i2p/go-streaming"
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
		} else if deps.I2CPClient != nil {
			// Auto-create resolver from I2CP client when available (Gap 9)
			if resolver, err := i2cp.NewClientDestinationResolverAdapter(deps.I2CPClient, 0); err == nil {
				namingHandler.SetDestinationResolver(resolver)
				log.Debug("Auto-wired I2CP destination resolver to NAMING handler")
			}
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
// StreamManager for STREAM sessions and DatagramConn for datagram/raw sessions.
// This is internal and not exported.
func createStreamManagerCallback(
	deps *Dependencies,
	connector *handler.StreamingConnector,
	acceptor *handler.StreamingAcceptor,
	forwarder *handler.StreamingForwarder,
) handler.SessionCreatedCallback {
	return func(sess session.Session, i2cpHandle session.I2CPSessionHandle) {
		if i2cpHandle == nil || deps.I2CPClient == nil {
			deps.Logger.WithFields(map[string]interface{}{
				"sessionID": sess.ID(),
				"style":     sess.Style(),
			}).Warn("Session created without I2CP transport: STREAM/DATAGRAM/RAW send not available until I2CP is connected")
			return
		}

		i2cpSess, ok := i2cpHandle.(*i2cp.I2CPSession)
		if !ok {
			deps.Logger.WithField("sessionID", sess.ID()).Warn("Cannot wire session: unexpected I2CP session type")
			return
		}

		switch sess.Style() {
		case session.StyleStream:
			wireStreamManager(deps, i2cpSess, sess.ID(), connector, acceptor, forwarder)
		case session.StyleDatagram, session.StyleRaw, session.StyleDatagram2, session.StyleDatagram3:
			wireDatagramConn(deps, i2cpSess, sess)
		}
	}
}

// wireStreamManager creates and registers a StreamManager for a STREAM session.
func wireStreamManager(
	deps *Dependencies,
	i2cpSess *i2cp.I2CPSession,
	sessionID string,
	connector *handler.StreamingConnector,
	acceptor *handler.StreamingAcceptor,
	forwarder *handler.StreamingForwarder,
) {
	underlyingSession := i2cpSess.Session()
	underlyingClient := deps.I2CPClient.I2CPClient()
	if underlyingSession == nil || underlyingClient == nil {
		deps.Logger.WithField("sessionID", sessionID).Warn("Cannot create StreamManager: no underlying I2CP session/client")
		return
	}

	streamManager, err := gostreaming.NewStreamManagerFromSession(underlyingClient, underlyingSession)
	if err != nil {
		deps.Logger.WithField("sessionID", sessionID).WithError(err).Warn("Failed to create StreamManager from session")
		return
	}

	adapter, err := samstreaming.NewAdapter(streamManager)
	if err != nil {
		deps.Logger.WithField("sessionID", sessionID).WithError(err).Warn("Failed to create StreamManager adapter")
		return
	}

	connector.RegisterManager(sessionID, adapter)
	if err := acceptor.RegisterManager(sessionID, adapter); err != nil {
		deps.Logger.WithField("sessionID", sessionID).WithError(err).Warn("Failed to register acceptor StreamManager")
	}
	forwarder.RegisterManager(sessionID, adapter)

	deps.Logger.WithField("sessionID", sessionID).Debug("Registered StreamManager for STREAM session")
}

// wireDatagramConn creates and sets a DatagramConn for a datagram/raw session.
func wireDatagramConn(deps *Dependencies, i2cpSess *i2cp.I2CPSession, sess session.Session) {
	setter, ok := sess.(session.DatagramConnSetter)
	if !ok {
		return
	}

	underlyingSession := i2cpSess.Session()
	if underlyingSession == nil {
		deps.Logger.WithField("sessionID", sess.ID()).Warn("Cannot create DatagramConn: no underlying I2CP session")
		return
	}

	localPort := uint16(deps.DatagramPort)
	protocol := datagramProtocolForStyle(sess.Style())

	conn, err := datagrams.NewDatagramConnWithProtocol(underlyingSession, localPort, protocol)
	if err != nil {
		deps.Logger.WithField("sessionID", sess.ID()).WithError(err).Warn("Failed to create DatagramConn for session")
		return
	}

	setter.SetDatagramConn(conn)
	deps.Logger.WithField("sessionID", sess.ID()).WithField("style", sess.Style()).Debug("Wired DatagramConn for datagram session")
}

// datagramProtocolForStyle returns the I2CP protocol number for the given SAM session style.
func datagramProtocolForStyle(style session.Style) uint8 {
	switch style {
	case session.StyleRaw:
		return datagrams.ProtocolRaw
	case session.StyleDatagram2:
		return datagrams.ProtocolDatagram2
	case session.StyleDatagram3:
		return datagrams.ProtocolDatagram3
	default: // StyleDatagram
		return datagrams.ProtocolDatagram1
	}
}
