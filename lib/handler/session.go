// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// DefaultTunnelBuildTimeout is the default timeout for tunnel building.
// Per SAMv3.md: "the router builds tunnels before responding with SESSION STATUS.
// This could take several seconds."
const DefaultTunnelBuildTimeout = 60 * time.Second

// SessionHandler handles SESSION CREATE commands per SAM 3.0-3.3.
// Creates new SAM sessions with I2P destinations.
type SessionHandler struct {
	destManager        destination.Manager
	i2cpProvider       session.I2CPSessionProvider
	tunnelBuildTimeout time.Duration
	onSessionCreated   SessionCreatedCallback
}

// SessionCreatedCallback is called after a session is successfully created.
// This can be used to wire additional components like StreamManager.
// The callback receives the session and the I2CP handle (may be nil if no I2CP provider).
type SessionCreatedCallback func(sess session.Session, i2cpHandle session.I2CPSessionHandle)

// NewSessionHandler creates a new SESSION handler with the given destination manager.
func NewSessionHandler(destManager destination.Manager) *SessionHandler {
	return &SessionHandler{
		destManager:        destManager,
		tunnelBuildTimeout: DefaultTunnelBuildTimeout,
	}
}

// SetI2CPProvider sets the I2CP session provider for creating I2CP sessions.
// ISSUE-003: When set, SESSION CREATE will wait for tunnels before responding.
func (h *SessionHandler) SetI2CPProvider(provider session.I2CPSessionProvider) {
	h.i2cpProvider = provider
}

// SetTunnelBuildTimeout sets the timeout for waiting for tunnels to build.
// Default is 60 seconds per SAM specification guidance.
func (h *SessionHandler) SetTunnelBuildTimeout(timeout time.Duration) {
	h.tunnelBuildTimeout = timeout
}

// SetSessionCreatedCallback sets the callback called after a session is successfully created.
// This enables wiring additional components like StreamManager per session.
func (h *SessionHandler) SetSessionCreatedCallback(cb SessionCreatedCallback) {
	h.onSessionCreated = cb
}

// Handle processes a SESSION command.
// Per SAMv3.md, SESSION commands manage SAM sessions.
// Dispatches to handleCreate, handleAdd, or handleRemove based on action.
func (h *SessionHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	switch cmd.Action {
	case protocol.ActionCreate:
		return h.handleCreate(ctx, cmd)
	case protocol.ActionAdd:
		return h.handleAdd(ctx, cmd)
	case protocol.ActionRemove:
		return h.handleRemove(ctx, cmd)
	default:
		return sessionError("unknown SESSION action: " + cmd.Action), nil
	}
}

// handleCreate processes a SESSION CREATE command.
// Per SAMv3.md, SESSION CREATE establishes a new SAM session.
//
// Request: SESSION CREATE STYLE=STREAM ID=$nickname DESTINATION={$privkey,TRANSIENT} [options...]
// Response: SESSION STATUS RESULT=OK DESTINATION=$privkey
//
//	SESSION STATUS RESULT=DUPLICATED_ID
//	SESSION STATUS RESULT=DUPLICATED_DEST
//	SESSION STATUS RESULT=INVALID_KEY
//	SESSION STATUS RESULT=I2P_ERROR MESSAGE="..."
func (h *SessionHandler) handleCreate(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Validate preconditions
	if resp := h.validateCreatePreconditions(ctx); resp != nil {
		return resp, nil
	}

	// Parse and validate required parameters
	style, id, resp := h.parseCreateRequiredParams(cmd)
	if resp != nil {
		return resp, nil
	}

	// Validate style-specific option restrictions
	if err := validateStyleOptions(style, cmd); err != nil {
		return sessionError(err.Error()), nil
	}

	// Parse destination
	dest, privKeyBase64, resp := h.parseCreateDestination(cmd)
	if resp != nil {
		return resp, nil
	}

	// Parse session configuration options
	config, err := h.parseConfig(cmd, style)
	if err != nil {
		return sessionError(err.Error()), nil
	}

	// Create the session based on style
	newSession, err := h.createSession(id, style, dest, ctx.Conn, config, cmd)
	if err != nil {
		return sessionError(err.Error()), nil
	}

	// Setup I2CP session and wait for tunnels
	i2cpHandle, resp := h.setupI2CPSession(ctx, id, config, newSession)
	if resp != nil {
		return resp, nil
	}

	// Register and finalize session
	if resp := h.registerAndFinalizeSession(ctx, newSession, i2cpHandle); resp != nil {
		return resp, nil
	}

	return sessionOK(privKeyBase64), nil
}

// validateCreatePreconditions checks handshake and session state.
func (h *SessionHandler) validateCreatePreconditions(ctx *Context) *protocol.Response {
	if !ctx.HandshakeComplete {
		return sessionError("handshake not complete")
	}
	if ctx.Session != nil {
		return sessionError("session already bound to this connection")
	}
	return nil
}

// parseCreateRequiredParams validates and extracts STYLE and ID.
func (h *SessionHandler) parseCreateRequiredParams(cmd *protocol.Command) (session.Style, string, *protocol.Response) {
	style := session.Style(cmd.Get("STYLE"))
	if !style.IsValid() {
		return "", "", sessionError("invalid or missing STYLE")
	}

	id := cmd.Get("ID")
	if id == "" {
		return "", "", sessionError("missing ID")
	}

	if containsWhitespace(id) {
		return "", "", sessionError("ID may not contain whitespace")
	}
	return style, id, nil
}

// parseCreateDestination parses DESTINATION option (TRANSIENT or existing key).
func (h *SessionHandler) parseCreateDestination(cmd *protocol.Command) (*session.Destination, string, *protocol.Response) {
	destSpec := cmd.Get("DESTINATION")
	if destSpec == "" {
		return nil, "", sessionError("missing DESTINATION")
	}

	var dest *session.Destination
	var privKeyBase64 string
	var err error

	if destSpec == "TRANSIENT" {
		dest, privKeyBase64, err = h.createTransientDest(cmd)
	} else {
		dest, privKeyBase64, err = h.parseExistingDest(destSpec)
	}

	if err != nil {
		return nil, "", sessionInvalidKey(err.Error())
	}
	return dest, privKeyBase64, nil
}

// setupI2CPSession creates I2CP session and waits for tunnels if provider is set.
func (h *SessionHandler) setupI2CPSession(ctx *Context, id string, config *session.SessionConfig, newSession session.Session) (session.I2CPSessionHandle, *protocol.Response) {
	if h.i2cpProvider == nil || !h.i2cpProvider.IsConnected() {
		return nil, nil
	}

	handle, err := h.createI2CPSession(ctx.Ctx, id, config)
	if err != nil {
		newSession.Close()
		return nil, sessionI2PError(fmt.Sprintf("failed to create I2P session: %v", err))
	}

	// Associate I2CP session with the SAM session
	if baseSession, ok := newSession.(*session.BaseSession); ok {
		baseSession.SetI2CPSession(handle)
	}

	// Wait for tunnels to be built before returning success
	tunnelCtx, cancel := context.WithTimeout(ctx.Ctx, h.tunnelBuildTimeout)
	defer cancel()

	if err := handle.WaitForTunnels(tunnelCtx); err != nil {
		newSession.Close()
		return nil, sessionI2PError(fmt.Sprintf("tunnel build failed: %v", err))
	}
	return handle, nil
}

// registerAndFinalizeSession registers the session and binds it to the context.
func (h *SessionHandler) registerAndFinalizeSession(ctx *Context, newSession session.Session, i2cpHandle session.I2CPSessionHandle) *protocol.Response {
	if ctx.Registry != nil {
		if err := ctx.Registry.Register(newSession); err != nil {
			newSession.Close()
			if err == util.ErrDuplicateID {
				return sessionDuplicatedID()
			}
			if err == util.ErrDuplicateDest {
				return sessionDuplicatedDest()
			}
			return sessionError(err.Error())
		}
	}

	// Bind session to connection context
	ctx.BindSession(newSession)

	// Start datagram/raw receivers for non-forwarding sessions
	// Per SAMv3.md: When no PORT is specified, incoming datagrams are delivered
	// on the control socket as DATAGRAM RECEIVED or RAW RECEIVED messages.
	switch newSession.Style() {
	case session.StyleDatagram, session.StyleDatagram2, session.StyleDatagram3:
		ctx.StartDatagramReceiver()
	case session.StyleRaw:
		ctx.StartRawReceiver()
	}

	// Invoke session created callback
	if h.onSessionCreated != nil {
		h.onSessionCreated(newSession, i2cpHandle)
	}
	return nil
}

// createTransientDest generates a new transient destination.
// Per SAMv3.md: "Offline signatures may not be created with DESTINATION=TRANSIENT"
func (h *SessionHandler) createTransientDest(cmd *protocol.Command) (*session.Destination, string, error) {
	// Per SAMv3.md: reject offline signatures with TRANSIENT destination
	if hasOfflineSignatureOptions(cmd) {
		return nil, "", &sessionErr{msg: "offline signatures may not be created with DESTINATION=TRANSIENT"}
	}

	// Parse signature type (default is 0 per spec, but 7 is recommended)
	sigType, err := parseSignatureType(cmd)
	if err != nil {
		return nil, "", err
	}

	// Validate signature type
	if !destination.IsValidSignatureType(sigType) {
		return nil, "", &sessionErr{msg: "unsupported signature type"}
	}

	// Generate the destination
	dest, privKey, err := h.destManager.Generate(sigType)
	if err != nil {
		return nil, "", err
	}

	// Encode to Base64
	privKeyBase64, err := h.destManager.Encode(dest, privKey)
	if err != nil {
		return nil, "", err
	}

	// Extract public key bytes for session.Destination
	pubKeyBase64, err := h.destManager.EncodePublic(dest)
	if err != nil {
		return nil, "", err
	}

	sessionDest := &session.Destination{
		PublicKey:     []byte(pubKeyBase64),
		PrivateKey:    privKey,
		SignatureType: sigType,
	}

	return sessionDest, privKeyBase64, nil
}

// parseExistingDest parses an existing private key destination.
// Per SAM 3.3, this also detects and parses offline signatures.
// If the signing private key is all zeros, the offline signature section follows.
func (h *SessionHandler) parseExistingDest(privKeyBase64 string) (*session.Destination, string, error) {
	result, err := h.destManager.ParseWithOffline(privKeyBase64)
	if err != nil {
		return nil, "", err
	}

	// Get public key for hash
	pubKeyBase64, err := h.destManager.EncodePublic(result.Destination)
	if err != nil {
		return nil, "", err
	}

	sessionDest := &session.Destination{
		PublicKey:     []byte(pubKeyBase64),
		PrivateKey:    result.PrivateKey,
		SignatureType: result.SignatureType,
	}

	// Copy offline signature if present
	if result.OfflineSignature != nil {
		sessionDest.OfflineSignature = &session.ParsedOfflineSignature{
			Expires:             result.OfflineSignature.Expires.Unix(),
			TransientSigType:    result.OfflineSignature.TransientSigType,
			TransientPublicKey:  result.OfflineSignature.TransientPublicKey,
			Signature:           result.OfflineSignature.Signature,
			TransientPrivateKey: result.OfflineSignature.TransientPrivateKey,
		}
	}

	return sessionDest, privKeyBase64, nil
}

// createSession creates a style-specific session implementation.
// Returns the appropriate session type (BaseSession, RawSessionImpl, DatagramSessionImpl, etc.)
// based on the STYLE parameter.
//
// Per SAM specification:
//   - STYLE=STREAM: Creates StreamSessionImpl for STREAM CONNECT/ACCEPT/FORWARD
//   - STYLE=RAW: Creates RawSessionImpl with PROTOCOL/HEADER options
//   - STYLE=DATAGRAM: Creates DatagramSessionImpl with PORT/HOST forwarding options
//   - STYLE=DATAGRAM2: Creates Datagram2SessionImpl with replay protection
//   - STYLE=DATAGRAM3: Creates Datagram3SessionImpl (unauthenticated)
//   - STYLE=PRIMARY: Creates PrimarySessionImpl for multiplexed subsessions
//   - STYLE=MASTER: Alias for PRIMARY (pre-0.9.47 compatibility)
func (h *SessionHandler) createSession(
	id string,
	style session.Style,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (session.Session, error) {
	switch style {
	case session.StyleStream:
		return h.createStreamSession(id, dest, conn, config, cmd)
	case session.StyleRaw:
		return h.createRawSession(id, dest, conn, config, cmd)
	case session.StyleDatagram:
		return h.createDatagramSession(id, dest, conn, config, cmd)
	case session.StyleDatagram2:
		return h.createDatagram2Session(id, dest, conn, config, cmd)
	case session.StyleDatagram3:
		return h.createDatagram3Session(id, dest, conn, config, cmd)
	case session.StylePrimary, session.StyleMaster:
		return h.createPrimarySession(id, dest, conn, config, cmd)
	default:
		return nil, fmt.Errorf("unsupported session style: %s", style)
	}
}

// createStreamSession creates a StreamSessionImpl for STYLE=STREAM.
// Handles STREAM-specific options: FORWARD/HOST/PORT for forwarding mode.
//
// Per SAM 3.0 specification:
//   - STREAM sessions support CONNECT, ACCEPT, and FORWARD commands
//   - FORWARD is mutually exclusive with ACCEPT
//   - PORT/HOST options are NOT valid at SESSION CREATE time
//   - Forwarding is configured via STREAM FORWARD command later
//   - The session is created without I2CP components; these can be wired
//     later via the SessionCreatedCallback
//
// Per SAM 3.2 specification:
//   - Multiple concurrent ACCEPTs are allowed
func (h *SessionHandler) createStreamSession(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.StreamSessionImpl, error) {
	// Create the stream session without I2CP (can be wired later via callback)
	// Note: PORT/HOST are validated to be absent by validateStyleOptions()
	// Forwarding configuration is set via STREAM FORWARD command, not SESSION CREATE
	streamSession := session.NewStreamSessionBasic(id, dest, conn, config)

	// Activate the session
	streamSession.Activate()

	return streamSession, nil
}

// createPrimarySession creates a PrimarySessionImpl for STYLE=PRIMARY or STYLE=MASTER.
// PRIMARY sessions support multiplexed subsessions that share a single destination.
//
// Per SAM 3.3 specification:
//   - PRIMARY sessions connect to the router and build tunnels
//   - Once active, subsessions can be added via SESSION ADD
//   - All subsessions share the same destination
//   - Routing is based on LISTEN_PORT/LISTEN_PROTOCOL
//   - PORT, HOST, FROM_PORT, TO_PORT, PROTOCOL, etc. are NOT valid at SESSION CREATE
//     (these apply only to subsessions added via SESSION ADD)
//
// STYLE=MASTER is the pre-0.9.47 name for PRIMARY (for compatibility).
func (h *SessionHandler) createPrimarySession(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.PrimarySessionImpl, error) {
	// Create the primary session
	// Note: PORT, HOST, FROM_PORT, etc. are validated to be absent by validateStyleOptions()
	primarySession := session.NewPrimarySession(id, dest, conn, config)

	// Activate the session
	primarySession.Activate()

	return primarySession, nil
}

// createRawSession creates a RawSessionImpl for STYLE=RAW.
// Handles RAW-specific options: PROTOCOL, HEADER, PORT, HOST.
//
// Per SAM 3.1/3.2 specification:
//   - PROTOCOL: I2CP protocol number (default 18, 0-255, excluding 6,17,19,20)
//   - HEADER: When true, forwarded datagrams include FROM_PORT/TO_PORT/PROTOCOL
//   - PORT: Forwarding port for incoming datagrams
//   - HOST: Forwarding host (default 127.0.0.1)
func (h *SessionHandler) createRawSession(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.RawSessionImpl, error) {
	// Create the raw session
	rawSession := session.NewRawSession(id, dest, conn, config)

	// Parse forwarding configuration (PORT/HOST)
	if portStr := cmd.Get("PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT for forwarding: %w", err)
		}

		host := cmd.Get("HOST")
		if host == "" {
			host = "127.0.0.1" // Default per SAM spec
		}

		if err := rawSession.SetForwarding(host, port); err != nil {
			return nil, fmt.Errorf("failed to set forwarding: %w", err)
		}
	}

	// Activate the session
	rawSession.Activate()

	return rawSession, nil
}

// createDatagramSession creates a DatagramSessionImpl for STYLE=DATAGRAM.
// Handles DATAGRAM-specific options: PORT, HOST for forwarding.
//
// Per SAM 3.0 specification:
//   - PORT: Forwarding port for incoming datagrams
//   - HOST: Forwarding host (default 127.0.0.1)
//
// Per SAM 3.3 specification:
//   - Offline signatures are NOT supported for DATAGRAM style
//     (only RAW, DATAGRAM2, and DATAGRAM3 support offline signatures)
//
// Repliable datagrams include the sender's destination and signature,
// enabling replies to the sender.
func (h *SessionHandler) createDatagramSession(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.DatagramSessionImpl, error) {
	// Per SAM spec: Offline signatures are not supported for DATAGRAM style
	if dest.OfflineSignature != nil {
		return nil, fmt.Errorf("offline signatures not supported for STYLE=DATAGRAM")
	}

	// Create the datagram session
	datagramSession := session.NewDatagramSession(id, dest, conn, config)

	// Parse forwarding configuration (PORT/HOST)
	if portStr := cmd.Get("PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT for forwarding: %w", err)
		}

		host := cmd.Get("HOST")
		if host == "" {
			host = "127.0.0.1" // Default per SAM spec
		}

		if err := datagramSession.SetForwarding(host, port); err != nil {
			return nil, fmt.Errorf("failed to set forwarding: %w", err)
		}
	}

	// Activate the session
	datagramSession.Activate()

	return datagramSession, nil
}

// createDatagram2Session creates a Datagram2SessionImpl for STYLE=DATAGRAM2.
// Handles DATAGRAM2-specific options: PORT, HOST for forwarding.
//
// Per SAM 3.3 specification, DATAGRAM2 provides:
//   - Authenticated, repliable datagrams (like DATAGRAM)
//   - Replay protection via nonce/timestamp tracking
//   - Offline signature support
//
// DATAGRAM2 is intended to replace repliable datagrams for new applications
// that don't require backward compatibility.
func (h *SessionHandler) createDatagram2Session(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.Datagram2SessionImpl, error) {
	// Create the datagram2 session
	dg2Session := session.NewDatagram2Session(id, dest, conn, config)

	// Parse forwarding configuration (PORT/HOST)
	if portStr := cmd.Get("PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT for forwarding: %w", err)
		}

		host := cmd.Get("HOST")
		if host == "" {
			host = "127.0.0.1" // Default per SAM spec
		}

		if err := dg2Session.SetForwarding(host, port); err != nil {
			return nil, fmt.Errorf("failed to set forwarding: %w", err)
		}
	}

	// Set offline signature if present in config
	// Per SAMv3.md, DATAGRAM2 supports offline signatures (DATAGRAM does not)
	if config.OfflineSignature != nil {
		dg2Session.SetOfflineSignature(config.OfflineSignature.Bytes())
	}

	// Activate the session
	dg2Session.SetStatus(session.StatusActive)

	return dg2Session, nil
}

// createDatagram3Session creates a Datagram3SessionImpl for STYLE=DATAGRAM3.
// Handles DATAGRAM3-specific options: PORT, HOST for forwarding.
//
// Per SAM 3.3 specification, DATAGRAM3 provides:
//   - Repliable but NOT authenticated datagrams
//   - Source is a 32-byte hash (44-byte base64)
//   - Client must do NAMING LOOKUP to get full destination for reply
//   - No replay protection (unauthenticated)
//   - Offline signature support (like DATAGRAM2, unlike legacy DATAGRAM)
//
// Security Note: Application designers should use extreme caution with DATAGRAM3
// and consider the security implications of unauthenticated datagrams.
func (h *SessionHandler) createDatagram3Session(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.Datagram3SessionImpl, error) {
	// Create the datagram3 session
	dg3Session := session.NewDatagram3Session(id, dest, conn, config)

	// Parse forwarding configuration (PORT/HOST)
	if portStr := cmd.Get("PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT for forwarding: %w", err)
		}

		host := cmd.Get("HOST")
		if host == "" {
			host = "127.0.0.1" // Default per SAM spec
		}

		if err := dg3Session.SetForwarding(host, port); err != nil {
			return nil, fmt.Errorf("failed to set forwarding: %w", err)
		}
	}

	// Set offline signature if present in config
	// Per SAMv3.md, DATAGRAM3 supports offline signatures (DATAGRAM does not)
	if config.OfflineSignature != nil {
		dg3Session.SetOfflineSignature(config.OfflineSignature.Bytes())
	}

	// Activate the session
	dg3Session.SetStatus(session.StatusActive)

	return dg3Session, nil
}

// parseConfig extracts session configuration from command options.
// Per SAM 3.2+, validates ports (0-65535) and protocol (0-255, excluding 6,17,19,20).
// The style parameter determines which options are valid.
// Unparsed i2cp.* and streaming.* options are stored for passthrough to I2CP.
// Returns an error if validation fails.
func (h *SessionHandler) parseConfig(cmd *protocol.Command, style session.Style) (*session.SessionConfig, error) {
	config := session.DefaultSessionConfig()
	parsedOptions := make(map[string]bool)

	// Parse tunnel configuration
	h.parseTunnelOptions(cmd, config, parsedOptions)

	// Parse port options (SAM 3.2+)
	if err := h.parseConfigPortOptions(cmd, config, parsedOptions); err != nil {
		return nil, err
	}

	// Parse RAW-specific options
	if err := h.parseConfigRawOptions(cmd, config, style, parsedOptions); err != nil {
		return nil, err
	}

	// Parse UDP options (Java I2P specific)
	if err := h.parseConfigUDPOptions(cmd, config, parsedOptions); err != nil {
		return nil, err
	}

	// Collect unparsed I2CP options for passthrough
	h.collectI2CPOptions(cmd, config, parsedOptions)

	return config, nil
}

// parseTunnelOptions extracts tunnel quantity and length options.
func (h *SessionHandler) parseTunnelOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) {
	if v := cmd.Get("inbound.quantity"); v != "" {
		parsed["inbound.quantity"] = true
		if qty, err := strconv.Atoi(v); err == nil && qty >= 0 {
			config.InboundQuantity = qty
		}
	}
	if v := cmd.Get("outbound.quantity"); v != "" {
		parsed["outbound.quantity"] = true
		if qty, err := strconv.Atoi(v); err == nil && qty >= 0 {
			config.OutboundQuantity = qty
		}
	}
	if v := cmd.Get("inbound.length"); v != "" {
		parsed["inbound.length"] = true
		if len, err := strconv.Atoi(v); err == nil && len >= 0 {
			config.InboundLength = len
		}
	}
	if v := cmd.Get("outbound.length"); v != "" {
		parsed["outbound.length"] = true
		if len, err := strconv.Atoi(v); err == nil && len >= 0 {
			config.OutboundLength = len
		}
	}
}

// parseConfigPortOptions extracts and validates FROM_PORT and TO_PORT (SAM 3.2+).
func (h *SessionHandler) parseConfigPortOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) error {
	if v := cmd.Get("FROM_PORT"); v != "" {
		parsed["FROM_PORT"] = true
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return fmt.Errorf("invalid FROM_PORT: %w", err)
		}
		config.FromPort = port
	}
	if v := cmd.Get("TO_PORT"); v != "" {
		parsed["TO_PORT"] = true
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return fmt.Errorf("invalid TO_PORT: %w", err)
		}
		config.ToPort = port
	}
	return nil
}

// parseConfigRawOptions extracts RAW-specific options (PROTOCOL, HEADER).
func (h *SessionHandler) parseConfigRawOptions(cmd *protocol.Command, config *session.SessionConfig, style session.Style, parsed map[string]bool) error {
	if v := cmd.Get("PROTOCOL"); v != "" {
		parsed["PROTOCOL"] = true
		if style != session.StyleRaw {
			return fmt.Errorf("PROTOCOL option is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(v)
		if err != nil {
			return fmt.Errorf("invalid PROTOCOL: %w", err)
		}
		config.Protocol = proto
	}

	if v := cmd.Get("HEADER"); v != "" {
		parsed["HEADER"] = true
		if style != session.StyleRaw {
			return fmt.Errorf("HEADER option is only valid for STYLE=RAW")
		}
		config.HeaderEnabled = (v == "true")
	}
	return nil
}

// parseConfigUDPOptions extracts sam.udp.host and sam.udp.port options (Java I2P specific).
func (h *SessionHandler) parseConfigUDPOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) error {
	if v := cmd.Get("sam.udp.host"); v != "" {
		parsed["sam.udp.host"] = true
		config.SamUDPHost = v
	}
	if v := cmd.Get("sam.udp.port"); v != "" {
		parsed["sam.udp.port"] = true
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return fmt.Errorf("invalid sam.udp.port: %w", err)
		}
		config.SamUDPPort = port
	}
	return nil
}

// collectI2CPOptions gathers unparsed i2cp.* and streaming.* options for I2CP passthrough.
func (h *SessionHandler) collectI2CPOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) {
	for key, value := range cmd.Options {
		if parsed[key] {
			continue
		}
		if isStandardSAMOption(key) {
			continue
		}
		if isI2CPOption(key) {
			config.I2CPOptions[key] = value
		}
	}
}

// containsWhitespace checks if a string contains any whitespace.
func containsWhitespace(s string) bool {
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			return true
		}
	}
	return false
}

// isStandardSAMOption returns true if the option is a standard SAM command option
// that should not be passed through to I2CP. These are options defined in the
// SAM specification that are handled by the SAM bridge itself.
func isStandardSAMOption(key string) bool {
	switch key {
	case "STYLE", "ID", "DESTINATION", "SIGNATURE_TYPE",
		"PORT", "HOST", "SILENT", "SSL",
		"LISTEN_PORT", "LISTEN_PROTOCOL",
		"SEND_TAGS", "TAG_THRESHOLD", "EXPIRES", "SEND_LEASESET":
		return true
	default:
		return false
	}
}

// isI2CPOption returns true if the option should be passed through to I2CP.
// This includes i2cp.*, streaming.*, inbound.*, outbound.*, and sam.* options
// per SAMv3.md specification.
func isI2CPOption(key string) bool {
	return strings.HasPrefix(key, "i2cp.") ||
		strings.HasPrefix(key, "streaming.") ||
		strings.HasPrefix(key, "inbound.") ||
		strings.HasPrefix(key, "outbound.") ||
		strings.HasPrefix(key, "sam.")
}

// hasOfflineSignatureOptions checks if the command contains offline signature options.
// Per SAMv3.md, offline signatures require specific options that cannot be used
// with DESTINATION=TRANSIENT.
func hasOfflineSignatureOptions(cmd *protocol.Command) bool {
	// Check for offline signature related options
	// The presence of these indicates an attempt to use offline signatures
	return cmd.Get("OFFLINE_SIGNATURE") != "" ||
		cmd.Get("OFFLINE_EXPIRES") != "" ||
		cmd.Get("TRANSIENT_KEY") != ""
}

// sessionOK returns a successful SESSION STATUS response.
// Per SAMv3.md line 343: SESSION STATUS RESULT=OK DESTINATION=$privkey
// The response includes only DESTINATION, not ID.
func sessionOK(destination string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultOK).
		WithDestination(destination)
}

// sessionDuplicatedID returns a DUPLICATED_ID response.
func sessionDuplicatedID() *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultDuplicatedID)
}

// handleAdd processes a SESSION ADD command.
// Per SAMv3.md, SESSION ADD creates a subsession on a PRIMARY session.
//
// Request: SESSION ADD STYLE=$style ID=$nickname [options...]
// Response: SESSION STATUS RESULT=OK DESTINATION=$privkey
//
//	SESSION STATUS RESULT=DUPLICATED_ID
//	SESSION STATUS RESULT=I2P_ERROR MESSAGE="..."
//
// SESSION ADD is only valid on a PRIMARY session's control socket.
// The subsession uses the destination from the PRIMARY session.
func (h *SessionHandler) handleAdd(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	primarySession, resp := h.validateAddPreconditions(ctx)
	if resp != nil {
		return resp, nil
	}

	style, id, resp := h.parseAddParams(cmd)
	if resp != nil {
		return resp, nil
	}

	return h.executeAddSubsession(ctx, primarySession, style, id, cmd)
}

// validateAddPreconditions validates context state for SESSION ADD.
func (h *SessionHandler) validateAddPreconditions(ctx *Context) (session.PrimarySession, *protocol.Response) {
	if !ctx.HandshakeComplete {
		return nil, sessionError("handshake not complete")
	}

	if ctx.Session == nil {
		return nil, sessionError("no session bound to this connection")
	}

	primarySession, ok := ctx.Session.(session.PrimarySession)
	if !ok {
		return nil, sessionError("SESSION ADD requires a PRIMARY session")
	}

	if ctx.Session.Status() != session.StatusActive {
		return nil, sessionError("session not active")
	}

	return primarySession, nil
}

// parseAddParams parses and validates SESSION ADD parameters.
func (h *SessionHandler) parseAddParams(cmd *protocol.Command) (session.Style, string, *protocol.Response) {
	style := session.Style(cmd.Get("STYLE"))
	if !style.IsValid() {
		return "", "", sessionError("invalid or missing STYLE")
	}

	if style.IsPrimary() {
		return "", "", sessionError("cannot create PRIMARY subsession")
	}

	id := cmd.Get("ID")
	if id == "" {
		return "", "", sessionError("missing ID")
	}

	if containsWhitespace(id) {
		return "", "", sessionError("ID may not contain whitespace")
	}

	if cmd.Get("DESTINATION") != "" {
		return "", "", sessionError("DESTINATION not allowed on SESSION ADD")
	}

	return style, id, nil
}

// executeAddSubsession adds the subsession to the primary session.
func (h *SessionHandler) executeAddSubsession(
	ctx *Context,
	primarySession session.PrimarySession,
	style session.Style,
	id string,
	cmd *protocol.Command,
) (*protocol.Response, error) {
	subOptions, err := h.parseSubsessionOptions(cmd, style)
	if err != nil {
		return sessionError(err.Error()), nil
	}

	if _, err := primarySession.AddSubsession(id, style, *subOptions); err != nil {
		if err == util.ErrDuplicateID || err == session.ErrDuplicateSubsessionID {
			return sessionDuplicatedID(), nil
		}
		return sessionError(err.Error()), nil
	}

	dest := ctx.Session.Destination()
	destBase64 := string(dest.PublicKey)

	return sessionOK(destBase64), nil
}

// handleRemove processes a SESSION REMOVE command.
// Per SAMv3.md, SESSION REMOVE closes and removes a subsession from a PRIMARY session.
//
// Request: SESSION REMOVE ID=$nickname
// Response: SESSION STATUS RESULT=OK
//
//	SESSION STATUS RESULT=I2P_ERROR MESSAGE="..."
//
// After removal, the subsession is closed and may not be used.
func (h *SessionHandler) handleRemove(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Require handshake completion
	if !ctx.HandshakeComplete {
		return sessionError("handshake not complete"), nil
	}

	// Must have a bound PRIMARY session
	if ctx.Session == nil {
		return sessionError("no session bound to this connection"), nil
	}

	// Verify session is a PRIMARY session
	primarySession, ok := ctx.Session.(session.PrimarySession)
	if !ok {
		return sessionError("SESSION REMOVE requires a PRIMARY session"), nil
	}

	// Parse ID
	id := cmd.Get("ID")
	if id == "" {
		return sessionError("missing ID"), nil
	}

	// No other options should be set per spec
	// (we don't enforce this strictly, just ignore them)

	// Remove the subsession
	if err := primarySession.RemoveSubsession(id); err != nil {
		return sessionError(err.Error()), nil
	}

	// Return OK with PRIMARY's destination
	dest := ctx.Session.Destination()
	destBase64 := string(dest.PublicKey)

	return sessionOK(destBase64), nil
}

// parseSubsessionOptions parses subsession options from SESSION ADD command.
// Per SAMv3.md, options include PORT, HOST, FROM_PORT, TO_PORT, PROTOCOL,
// LISTEN_PORT, LISTEN_PROTOCOL, HEADER.
func (h *SessionHandler) parseSubsessionOptions(cmd *protocol.Command, style session.Style) (*session.SubsessionOptions, error) {
	opts := &session.SubsessionOptions{}

	// Parse PORT and HOST (DATAGRAM*/RAW only)
	if err := h.parseSubsessionPortHost(cmd, opts, style); err != nil {
		return nil, err
	}

	// Parse traffic ports (FROM_PORT, TO_PORT)
	if err := h.parseSubsessionTrafficPorts(cmd, opts); err != nil {
		return nil, err
	}

	// Parse PROTOCOL (RAW only)
	if err := h.parseSubsessionProtocol(cmd, opts, style); err != nil {
		return nil, err
	}

	// Parse listen options (LISTEN_PORT, LISTEN_PROTOCOL)
	if err := h.parseSubsessionListenOptions(cmd, opts, style); err != nil {
		return nil, err
	}

	// Parse HEADER (RAW only)
	if err := h.parseSubsessionHeader(cmd, opts, style); err != nil {
		return nil, err
	}

	return opts, nil
}

// parseSubsessionPortHost extracts PORT and HOST options.
func (h *SessionHandler) parseSubsessionPortHost(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	if portStr := cmd.Get("PORT"); portStr != "" {
		if style == session.StyleStream {
			return fmt.Errorf("PORT is invalid for STYLE=STREAM")
		}
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid PORT: %w", err)
		}
		opts.Port = port
	}

	if host := cmd.Get("HOST"); host != "" {
		if style == session.StyleStream {
			return fmt.Errorf("HOST is invalid for STYLE=STREAM")
		}
		opts.Host = host
	} else if style != session.StyleStream {
		opts.Host = "127.0.0.1" // Default per SAM spec
	}
	return nil
}

// parseSubsessionTrafficPorts extracts FROM_PORT and TO_PORT options.
func (h *SessionHandler) parseSubsessionTrafficPorts(cmd *protocol.Command, opts *session.SubsessionOptions) error {
	if portStr := cmd.Get("FROM_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid FROM_PORT: %w", err)
		}
		opts.FromPort = port
	}

	if portStr := cmd.Get("TO_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid TO_PORT: %w", err)
		}
		opts.ToPort = port
	}
	return nil
}

// parseSubsessionProtocol extracts PROTOCOL option (RAW only).
func (h *SessionHandler) parseSubsessionProtocol(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	if protoStr := cmd.Get("PROTOCOL"); protoStr != "" {
		if style != session.StyleRaw {
			return fmt.Errorf("PROTOCOL is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(protoStr)
		if err != nil {
			return fmt.Errorf("invalid PROTOCOL: %w", err)
		}
		opts.Protocol = proto
	} else if style == session.StyleRaw {
		opts.Protocol = 18 // Default per SAM spec
	}
	return nil
}

// parseSubsessionListenOptions extracts LISTEN_PORT and LISTEN_PROTOCOL options.
func (h *SessionHandler) parseSubsessionListenOptions(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	// Parse LISTEN_PORT - default is FROM_PORT value
	if portStr := cmd.Get("LISTEN_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid LISTEN_PORT: %w", err)
		}
		// For STREAM, only FROM_PORT value or 0 is allowed
		if style == session.StyleStream && port != 0 && port != opts.FromPort {
			return fmt.Errorf("LISTEN_PORT must be 0 or FROM_PORT value for STYLE=STREAM")
		}
		opts.ListenPort = port
	} else {
		opts.ListenPort = opts.FromPort // Default per spec
	}

	// Parse LISTEN_PROTOCOL (RAW only) - default is PROTOCOL value; 6 is disallowed
	if protoStr := cmd.Get("LISTEN_PROTOCOL"); protoStr != "" {
		if style != session.StyleRaw {
			return fmt.Errorf("LISTEN_PROTOCOL is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(protoStr)
		if err != nil {
			return fmt.Errorf("invalid LISTEN_PROTOCOL: %w", err)
		}
		if proto == 6 {
			return fmt.Errorf("LISTEN_PROTOCOL=6 (streaming) is disallowed for RAW")
		}
		opts.ListenProtocol = proto
	} else if style == session.StyleRaw {
		opts.ListenProtocol = opts.Protocol // Default per spec
	}
	return nil
}

// parseSubsessionHeader extracts HEADER option (RAW only).
func (h *SessionHandler) parseSubsessionHeader(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	if headerStr := cmd.Get("HEADER"); headerStr != "" {
		if style != session.StyleRaw {
			return fmt.Errorf("HEADER is only valid for STYLE=RAW")
		}
		opts.HeaderEnabled = (headerStr == "true")
	}

	return nil
}

// sessionDuplicatedDest returns a DUPLICATED_DEST response.
func sessionDuplicatedDest() *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultDuplicatedDest)
}

// validateStyleOptions validates that style-specific option restrictions are followed.
// Per SAM spec:
//   - STREAM: PORT and HOST are invalid
//   - PRIMARY/MASTER: PORT, HOST, FROM_PORT, TO_PORT, PROTOCOL, LISTEN_PORT,
//     LISTEN_PROTOCOL, and HEADER are invalid (apply only to subsessions)
func validateStyleOptions(style session.Style, cmd *protocol.Command) error {
	switch style {
	case session.StyleStream:
		// Per SAM spec: PORT and HOST are invalid for STREAM
		if cmd.Get("PORT") != "" {
			return fmt.Errorf("PORT is invalid for STYLE=STREAM")
		}
		if cmd.Get("HOST") != "" {
			return fmt.Errorf("HOST is invalid for STYLE=STREAM")
		}

	case session.StylePrimary, session.StyleMaster:
		// Per SAM spec: These options only apply to subsessions, not PRIMARY
		disallowed := []string{
			"PORT", "HOST", "FROM_PORT", "TO_PORT",
			"PROTOCOL", "LISTEN_PORT", "LISTEN_PROTOCOL", "HEADER",
		}
		for _, opt := range disallowed {
			if cmd.Get(opt) != "" {
				return fmt.Errorf("%s is invalid for STYLE=PRIMARY", opt)
			}
		}
	}

	return nil
}

// sessionInvalidKey returns an INVALID_KEY response.
func sessionInvalidKey(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultInvalidKey).
		WithMessage(msg)
}

// sessionError returns an I2P_ERROR response.
func sessionError(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultI2PError).
		WithMessage(msg)
}

// sessionI2PError returns an I2P_ERROR response with additional context.
// Used for I2CP and tunnel-related errors.
// ISSUE-003: Provides detailed error messages for tunnel build failures.
func sessionI2PError(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultI2PError).
		WithMessage(msg)
}

// createI2CPSession creates an I2CP session using the configured provider.
// ISSUE-003: Implements tunnel allocation for SESSION CREATE.
func (h *SessionHandler) createI2CPSession(ctx context.Context, sessionID string, config *session.SessionConfig) (session.I2CPSessionHandle, error) {
	if h.i2cpProvider == nil {
		return nil, fmt.Errorf("no I2CP provider configured")
	}
	if !h.i2cpProvider.IsConnected() {
		return nil, fmt.Errorf("I2CP provider not connected")
	}
	return h.i2cpProvider.CreateSessionForSAM(ctx, sessionID, config)
}

// sessionErr is an error type for session handler errors.
type sessionErr struct {
	msg string
}

func (e *sessionErr) Error() string {
	return e.msg
}

// Ensure SessionHandler implements Handler interface
var _ Handler = (*SessionHandler)(nil)

// Verify interface compliance for net.Conn usage
var _ net.Conn = (net.Conn)(nil)
