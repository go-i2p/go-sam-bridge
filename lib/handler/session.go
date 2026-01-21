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

// Handle processes a SESSION CREATE command.
// Per SAMv3.md, SESSION CREATE establishes a new SAM session.
//
// Request: SESSION CREATE STYLE=STREAM ID=$nickname DESTINATION={$privkey,TRANSIENT} [options...]
// Response: SESSION STATUS RESULT=OK DESTINATION=$privkey
//
//	SESSION STATUS RESULT=DUPLICATED_ID
//	SESSION STATUS RESULT=DUPLICATED_DEST
//	SESSION STATUS RESULT=INVALID_KEY
//	SESSION STATUS RESULT=I2P_ERROR MESSAGE="..."
func (h *SessionHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
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
func (h *SessionHandler) parseExistingDest(privKeyBase64 string) (*session.Destination, string, error) {
	dest, privKey, err := h.destManager.Parse(privKeyBase64)
	if err != nil {
		return nil, "", err
	}

	// Get public key for hash
	pubKeyBase64, err := h.destManager.EncodePublic(dest)
	if err != nil {
		return nil, "", err
	}

	sessionDest := &session.Destination{
		PublicKey:     []byte(pubKeyBase64),
		PrivateKey:    privKey,
		SignatureType: 7, // TODO: extract from destination
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
