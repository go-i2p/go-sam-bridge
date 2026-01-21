// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"fmt"
	"net"
	"strconv"

	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// SessionHandler handles SESSION CREATE commands per SAM 3.0-3.3.
// Creates new SAM sessions with I2P destinations.
type SessionHandler struct {
	destManager destination.Manager
}

// NewSessionHandler creates a new SESSION handler with the given destination manager.
func NewSessionHandler(destManager destination.Manager) *SessionHandler {
	return &SessionHandler{destManager: destManager}
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
	// Require handshake completion
	if !ctx.HandshakeComplete {
		return sessionError("handshake not complete"), nil
	}

	// Session already bound to this connection?
	if ctx.Session != nil {
		return sessionError("session already bound to this connection"), nil
	}

	// Parse required parameters
	style := session.Style(cmd.Get("STYLE"))
	if !style.IsValid() {
		return sessionError("invalid or missing STYLE"), nil
	}

	id := cmd.Get("ID")
	if id == "" {
		return sessionError("missing ID"), nil
	}

	// Validate ID contains no whitespace
	if containsWhitespace(id) {
		return sessionError("ID may not contain whitespace"), nil
	}

	// Parse destination
	destSpec := cmd.Get("DESTINATION")
	if destSpec == "" {
		return sessionError("missing DESTINATION"), nil
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
		return sessionInvalidKey(err.Error()), nil
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

	// Register the session
	if ctx.Registry != nil {
		if err := ctx.Registry.Register(newSession); err != nil {
			// Clean up session on registration failure
			newSession.Close()
			if err == util.ErrDuplicateID {
				return sessionDuplicatedID(), nil
			}
			if err == util.ErrDuplicateDest {
				return sessionDuplicatedDest(), nil
			}
			return sessionError(err.Error()), nil
		}
	}

	// Bind session to connection context
	ctx.BindSession(newSession)

	return sessionOK(privKeyBase64), nil
}

// createTransientDest generates a new transient destination.
func (h *SessionHandler) createTransientDest(cmd *protocol.Command) (*session.Destination, string, error) {
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
//   - STYLE=STREAM: Creates BaseSession (StreamSessionImpl when fully integrated)
//   - STYLE=RAW: Creates RawSessionImpl with PROTOCOL/HEADER options
//   - STYLE=DATAGRAM: Creates DatagramSessionImpl with PORT/HOST forwarding options
//   - STYLE=DATAGRAM2: Creates Datagram2SessionImpl with replay protection
//   - STYLE=DATAGRAM3: Creates Datagram3SessionImpl (unauthenticated)
//   - STYLE=PRIMARY: Creates BaseSession (PrimarySessionImpl when implemented)
func (h *SessionHandler) createSession(
	id string,
	style session.Style,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (session.Session, error) {
	switch style {
	case session.StyleRaw:
		return h.createRawSession(id, dest, conn, config, cmd)
	case session.StyleDatagram:
		return h.createDatagramSession(id, dest, conn, config, cmd)
	case session.StyleDatagram2:
		return h.createDatagram2Session(id, dest, conn, config, cmd)
	case session.StyleDatagram3:
		return h.createDatagram3Session(id, dest, conn, config, cmd)
	default:
		// For STREAM, PRIMARY - use BaseSession for now
		// These will be upgraded to specific implementations as completed
		baseSession := session.NewBaseSession(id, style, dest, conn, config)
		baseSession.SetStatus(session.StatusActive)
		return baseSession, nil
	}
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
// Repliable datagrams include the sender's destination and signature,
// enabling replies to the sender.
func (h *SessionHandler) createDatagramSession(
	id string,
	dest *session.Destination,
	conn net.Conn,
	config *session.SessionConfig,
	cmd *protocol.Command,
) (*session.DatagramSessionImpl, error) {
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

	// Activate the session
	dg3Session.SetStatus(session.StatusActive)

	return dg3Session, nil
}

// parseConfig extracts session configuration from command options.
// Per SAM 3.2+, validates ports (0-65535) and protocol (0-255, excluding 6,17,19,20).
// The style parameter determines which options are valid.
// Returns an error if validation fails.
func (h *SessionHandler) parseConfig(cmd *protocol.Command, style session.Style) (*session.SessionConfig, error) {
	config := session.DefaultSessionConfig()

	// Parse tunnel quantities
	if v := cmd.Get("inbound.quantity"); v != "" {
		if qty, err := strconv.Atoi(v); err == nil && qty >= 0 {
			config.InboundQuantity = qty
		}
	}
	if v := cmd.Get("outbound.quantity"); v != "" {
		if qty, err := strconv.Atoi(v); err == nil && qty >= 0 {
			config.OutboundQuantity = qty
		}
	}

	// Parse tunnel lengths
	if v := cmd.Get("inbound.length"); v != "" {
		if len, err := strconv.Atoi(v); err == nil && len >= 0 {
			config.InboundLength = len
		}
	}
	if v := cmd.Get("outbound.length"); v != "" {
		if len, err := strconv.Atoi(v); err == nil && len >= 0 {
			config.OutboundLength = len
		}
	}

	// Parse and validate ports (SAM 3.2+)
	if v := cmd.Get("FROM_PORT"); v != "" {
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid FROM_PORT: %w", err)
		}
		config.FromPort = port
	}
	if v := cmd.Get("TO_PORT"); v != "" {
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid TO_PORT: %w", err)
		}
		config.ToPort = port
	}

	// Parse and validate RAW-specific options
	// PROTOCOL is only valid for STYLE=RAW per SAM 3.2 specification
	if v := cmd.Get("PROTOCOL"); v != "" {
		if style != session.StyleRaw {
			return nil, fmt.Errorf("PROTOCOL option is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid PROTOCOL: %w", err)
		}
		config.Protocol = proto
	}

	// HEADER is only valid for STYLE=RAW per SAM 3.2 specification
	if v := cmd.Get("HEADER"); v != "" {
		if style != session.StyleRaw {
			return nil, fmt.Errorf("HEADER option is only valid for STYLE=RAW")
		}
		config.HeaderEnabled = (v == "true")
	}

	return config, nil
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

// sessionOK returns a successful SESSION STATUS response.
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
		return sessionError("SESSION ADD requires a PRIMARY session"), nil
	}

	// Verify session is active
	if ctx.Session.Status() != session.StatusActive {
		return sessionError("session not active"), nil
	}

	// Parse required parameters
	style := session.Style(cmd.Get("STYLE"))
	if !style.IsValid() {
		return sessionError("invalid or missing STYLE"), nil
	}

	// Validate style - cannot add PRIMARY/MASTER subsessions
	if style.IsPrimary() {
		return sessionError("cannot create PRIMARY subsession"), nil
	}

	id := cmd.Get("ID")
	if id == "" {
		return sessionError("missing ID"), nil
	}

	// Validate ID contains no whitespace
	if containsWhitespace(id) {
		return sessionError("ID may not contain whitespace"), nil
	}

	// DESTINATION is not allowed for SESSION ADD - uses PRIMARY's destination
	if cmd.Get("DESTINATION") != "" {
		return sessionError("DESTINATION not allowed on SESSION ADD"), nil
	}

	// Parse subsession options
	subOptions, err := h.parseSubsessionOptions(cmd, style)
	if err != nil {
		return sessionError(err.Error()), nil
	}

	// Add the subsession
	if _, err := primarySession.AddSubsession(id, style, *subOptions); err != nil {
		// Check for duplicate ID (from either util package or session package)
		if err == util.ErrDuplicateID || err == session.ErrDuplicateSubsessionID {
			return sessionDuplicatedID(), nil
		}
		return sessionError(err.Error()), nil
	}

	// Get destination from PRIMARY session for response
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

	// Parse PORT (required for DATAGRAM*/RAW, invalid for STREAM)
	if portStr := cmd.Get("PORT"); portStr != "" {
		if style == session.StyleStream {
			return nil, fmt.Errorf("PORT is invalid for STYLE=STREAM")
		}
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT: %w", err)
		}
		opts.Port = port
	}

	// Parse HOST (optional for DATAGRAM*/RAW, invalid for STREAM)
	if host := cmd.Get("HOST"); host != "" {
		if style == session.StyleStream {
			return nil, fmt.Errorf("HOST is invalid for STYLE=STREAM")
		}
		opts.Host = host
	} else if style != session.StyleStream {
		opts.Host = "127.0.0.1" // Default per SAM spec
	}

	// Parse FROM_PORT (outbound traffic)
	if portStr := cmd.Get("FROM_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid FROM_PORT: %w", err)
		}
		opts.FromPort = port
	}

	// Parse TO_PORT (outbound traffic)
	if portStr := cmd.Get("TO_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid TO_PORT: %w", err)
		}
		opts.ToPort = port
	}

	// Parse PROTOCOL (RAW only)
	if protoStr := cmd.Get("PROTOCOL"); protoStr != "" {
		if style != session.StyleRaw {
			return nil, fmt.Errorf("PROTOCOL is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(protoStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PROTOCOL: %w", err)
		}
		opts.Protocol = proto
	} else if style == session.StyleRaw {
		opts.Protocol = 18 // Default per SAM spec
	}

	// Parse LISTEN_PORT (inbound traffic)
	// Default is FROM_PORT value
	if portStr := cmd.Get("LISTEN_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid LISTEN_PORT: %w", err)
		}
		// For STREAM, only FROM_PORT value or 0 is allowed
		if style == session.StyleStream && port != 0 && port != opts.FromPort {
			return nil, fmt.Errorf("LISTEN_PORT must be 0 or FROM_PORT value for STYLE=STREAM")
		}
		opts.ListenPort = port
	} else {
		opts.ListenPort = opts.FromPort // Default per spec
	}

	// Parse LISTEN_PROTOCOL (RAW only)
	// Default is PROTOCOL value; 6 (streaming) is disallowed
	if protoStr := cmd.Get("LISTEN_PROTOCOL"); protoStr != "" {
		if style != session.StyleRaw {
			return nil, fmt.Errorf("LISTEN_PROTOCOL is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(protoStr)
		if err != nil {
			return nil, fmt.Errorf("invalid LISTEN_PROTOCOL: %w", err)
		}
		if proto == 6 {
			return nil, fmt.Errorf("LISTEN_PROTOCOL=6 (streaming) is disallowed for RAW")
		}
		opts.ListenProtocol = proto
	} else if style == session.StyleRaw {
		opts.ListenProtocol = opts.Protocol // Default per spec
	}

	// Parse HEADER (RAW only)
	if headerStr := cmd.Get("HEADER"); headerStr != "" {
		if style != session.StyleRaw {
			return nil, fmt.Errorf("HEADER is only valid for STYLE=RAW")
		}
		opts.HeaderEnabled = (headerStr == "true")
	}

	return opts, nil
}

// sessionDuplicatedDest returns a DUPLICATED_DEST response.
func sessionDuplicatedDest() *protocol.Response {
	return protocol.NewResponse(protocol.VerbSession).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultDuplicatedDest)
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
