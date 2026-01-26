// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// StreamHandler handles STREAM CONNECT, ACCEPT, and FORWARD commands per SAM 3.0-3.3.
// These commands operate on existing STREAM sessions to establish virtual connections.
type StreamHandler struct {
	// Connector establishes outbound stream connections.
	Connector StreamConnector

	// Acceptor accepts inbound stream connections.
	Acceptor StreamAcceptor

	// Forwarder sets up connection forwarding.
	Forwarder StreamForwarder
}

// StreamConnector establishes outbound I2P stream connections.
// Implementations wrap go-streaming or similar I2P streaming libraries.
type StreamConnector interface {
	// Connect establishes a stream connection to the destination.
	// Returns a net.Conn representing the bidirectional stream.
	Connect(sess session.Session, dest string, fromPort, toPort int) (net.Conn, error)
}

// StreamAcceptor accepts inbound I2P stream connections.
// Implementations wrap go-streaming or similar I2P streaming libraries.
type StreamAcceptor interface {
	// Accept waits for and accepts an incoming stream connection.
	// Returns the connection and the remote destination info.
	Accept(sess session.Session) (net.Conn, *AcceptInfo, error)
}

// AcceptInfo contains information about an accepted connection.
type AcceptInfo struct {
	// Destination is the Base64-encoded destination of the connecting peer.
	Destination string
	// FromPort is the source port (SAM 3.2+).
	FromPort int
	// ToPort is the destination port (SAM 3.2+).
	ToPort int
}

// StreamForwarder sets up forwarding for incoming connections.
// Implementations handle the forwarding lifecycle.
type StreamForwarder interface {
	// Forward sets up forwarding to the specified host:port.
	// Returns a Listener that can be closed to stop forwarding.
	Forward(sess session.Session, host string, port int, ssl bool) (net.Listener, error)
}

// NewStreamHandler creates a new STREAM command handler.
func NewStreamHandler(connector StreamConnector, acceptor StreamAcceptor, forwarder StreamForwarder) *StreamHandler {
	return &StreamHandler{
		Connector: connector,
		Acceptor:  acceptor,
		Forwarder: forwarder,
	}
}

// Handle processes STREAM commands (CONNECT, ACCEPT, FORWARD).
// Per SAMv3.md, STREAM commands operate on existing STREAM sessions.
func (h *StreamHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Require handshake completion
	if !ctx.HandshakeComplete {
		return streamError("handshake not complete"), nil
	}

	switch cmd.Action {
	case protocol.ActionConnect:
		return h.handleConnect(ctx, cmd)
	case protocol.ActionAccept:
		return h.handleAccept(ctx, cmd)
	case protocol.ActionForward:
		return h.handleForward(ctx, cmd)
	default:
		return streamError("unknown STREAM action"), nil
	}
}

// handleConnect processes STREAM CONNECT command.
// Request: STREAM CONNECT ID=$nickname DESTINATION=$dest [SILENT={true,false}] [FROM_PORT=nnn] [TO_PORT=nnn]
// Response: STREAM STATUS RESULT=OK (if !SILENT) then socket becomes data pipe.
//
// Per SAMv3.md: "If SILENT=true is passed, the SAM bridge won't issue any other
// message on the socket. If the connection fails, the socket will be closed.
// If the connection succeeds, all remaining data passing through the current
// socket is forwarded from and to the connected I2P destination peer."
func (h *StreamHandler) handleConnect(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	params, resp := h.parseConnectParams(ctx, cmd)
	if resp != nil {
		return resp, nil
	}

	return h.executeConnect(params)
}

// connectParams holds parsed parameters for STREAM CONNECT.
type connectParams struct {
	sess     session.Session
	dest     string
	silent   bool
	fromPort int
	toPort   int
}

// parseConnectParams parses and validates STREAM CONNECT parameters.
func (h *StreamHandler) parseConnectParams(ctx *Context, cmd *protocol.Command) (*connectParams, *protocol.Response) {
	id := cmd.Get("ID")
	if id == "" {
		return nil, streamInvalidID("missing ID")
	}

	dest := cmd.Get("DESTINATION")
	if dest == "" {
		return nil, streamInvalidKey("missing DESTINATION")
	}

	sess := h.lookupSession(ctx, id)
	if sess == nil {
		return nil, streamInvalidID("session not found")
	}

	if sess.Style() != session.StyleStream {
		return nil, streamError("session is not STREAM style")
	}

	fromPort, err := protocol.ValidatePortString(cmd.Get("FROM_PORT"))
	if err != nil {
		return nil, streamError(fmt.Sprintf("invalid FROM_PORT: %v", err))
	}

	toPort, err := protocol.ValidatePortString(cmd.Get("TO_PORT"))
	if err != nil {
		return nil, streamError(fmt.Sprintf("invalid TO_PORT: %v", err))
	}

	return &connectParams{
		sess:     sess,
		dest:     dest,
		silent:   parseBool(cmd.Get("SILENT"), false),
		fromPort: fromPort,
		toPort:   toPort,
	}, nil
}

// executeConnect performs the actual connection.
func (h *StreamHandler) executeConnect(params *connectParams) (*protocol.Response, error) {
	if h.Connector == nil {
		return streamError("connector not available"), nil
	}

	conn, err := h.Connector.Connect(params.sess, params.dest, params.fromPort, params.toPort)
	if err != nil {
		if params.silent {
			return nil, util.NewSilentCloseError("connect", err)
		}
		return h.connectError(err), nil
	}

	if params.silent {
		_ = conn
		return nil, nil
	}

	_ = conn
	return streamOK(), nil
}

// handleAccept processes STREAM ACCEPT command.
// Request: STREAM ACCEPT ID=$nickname [SILENT={true,false}]
// Response: STREAM STATUS RESULT=OK, then $destination FROM_PORT=nnn TO_PORT=nnn
//
// Per SAMv3.md: "If SILENT=true is passed, after the connection was accepted,
// the SAM bridge won't issue any other message on the socket. If the connection
// failed, the socket will be closed."
//
// Per SAMv3.md: "As of SAM 3.2, multiple concurrent pending STREAM ACCEPTs are
// allowed on the same session ID. Prior to 3.2, concurrent accepts would fail
// with ALREADY_ACCEPTING."
func (h *StreamHandler) handleAccept(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	sess, resp := h.validateAcceptSession(ctx, cmd)
	if resp != nil {
		return resp, nil
	}

	silent := parseBool(cmd.Get("SILENT"), false)

	cleanup, resp := h.trackPendingAccept(ctx, sess)
	if resp != nil {
		return resp, nil
	}
	if cleanup != nil {
		defer cleanup()
	}

	return h.executeAccept(sess, silent)
}

// validateAcceptSession validates the session for ACCEPT operation.
func (h *StreamHandler) validateAcceptSession(ctx *Context, cmd *protocol.Command) (session.Session, *protocol.Response) {
	id := cmd.Get("ID")
	if id == "" {
		return nil, streamInvalidID("missing ID")
	}

	sess := h.lookupSession(ctx, id)
	if sess == nil {
		return nil, streamInvalidID("session not found")
	}

	if sess.Style() != session.StyleStream {
		return nil, streamError("session is not STREAM style")
	}

	return sess, nil
}

// trackPendingAccept manages concurrent accept tracking per SAM version.
// Returns a cleanup function and optional error response.
func (h *StreamHandler) trackPendingAccept(ctx *Context, sess session.Session) (func(), *protocol.Response) {
	streamSess, isStreamSession := sess.(session.StreamSession)
	if !isStreamSession {
		return nil, nil
	}

	if compareVersions(ctx.Version, "3.2") < 0 {
		if streamSess.PendingAcceptCount() > 0 {
			return nil, streamAlreadyAccepting()
		}
	}

	streamSess.IncrementPendingAccepts()
	return streamSess.DecrementPendingAccepts, nil
}

// executeAccept performs the actual accept operation.
func (h *StreamHandler) executeAccept(sess session.Session, silent bool) (*protocol.Response, error) {
	if h.Acceptor == nil {
		return streamError("acceptor not available"), nil
	}

	conn, info, err := h.Acceptor.Accept(sess)
	if err != nil {
		if silent {
			return nil, util.NewSilentCloseError("accept", err)
		}
		return streamError(err.Error()), nil
	}

	if silent {
		_ = conn
		return nil, nil
	}

	return h.buildAcceptResponse(conn, info)
}

// buildAcceptResponse creates the accept success response.
func (h *StreamHandler) buildAcceptResponse(conn net.Conn, info *AcceptInfo) (*protocol.Response, error) {
	_ = conn
	resp := streamOK()
	if info != nil {
		destLine := fmt.Sprintf("%s FROM_PORT=%d TO_PORT=%d", info.Destination, info.FromPort, info.ToPort)
		resp.WithAdditionalLine(destLine)
	}
	return resp, nil
}

// handleForward processes STREAM FORWARD command.
// Request: STREAM FORWARD ID=$nickname PORT=$port [HOST=$host] [SILENT={true,false}] [SSL={true,false}]
// Response: STREAM STATUS RESULT=OK (always sent, even if SILENT=true)
func (h *StreamHandler) handleForward(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Parse required parameters
	id := cmd.Get("ID")
	if id == "" {
		return streamInvalidID("missing ID"), nil
	}

	portStr := cmd.Get("PORT")
	if portStr == "" {
		return streamError("missing PORT"), nil
	}

	// Validate port (SAM 3.0+)
	port, err := protocol.ValidatePortString(portStr)
	if err != nil {
		return streamError(fmt.Sprintf("invalid PORT: %v", err)), nil
	}

	// Lookup session
	sess := h.lookupSession(ctx, id)
	if sess == nil {
		return streamInvalidID("session not found"), nil
	}

	// Validate session is STREAM style
	if sess.Style() != session.StyleStream {
		return streamError("session is not STREAM style"), nil
	}

	// Parse optional parameters
	host := cmd.Get("HOST")
	if host == "" {
		// Default to client's IP address
		host = extractHost(ctx.RemoteAddr())
	}

	ssl := parseBool(cmd.Get("SSL"), false)

	// Set up forwarding
	if h.Forwarder == nil {
		return streamError("forwarder not available"), nil
	}

	listener, err := h.Forwarder.Forward(sess, host, port, ssl)
	if err != nil {
		return streamError(err.Error()), nil
	}

	// FORWARD always returns a response, even with SILENT=true
	_ = listener
	return streamOK(), nil
}

// lookupSession finds a session by ID from context or registry.
// Per SAMv3.md, STREAM commands use the ID parameter to specify the session.
// For PRIMARY sessions, the ID refers to a subsession created via SESSION ADD.
// This function will:
// 1. Check if the ID matches the bound session on this connection
// 2. Check if the bound session is a PRIMARY and the ID matches a subsession
// 3. Look up in the global registry
func (h *StreamHandler) lookupSession(ctx *Context, id string) session.Session {
	// First check if session is bound to this connection
	if ctx.Session != nil {
		// Direct match with bound session
		if ctx.Session.ID() == id {
			return ctx.Session
		}

		// Check if bound session is a PRIMARY and id matches a subsession
		if primary, ok := ctx.Session.(session.PrimarySession); ok {
			if subsess := primary.Subsession(id); subsess != nil {
				return subsess
			}
		}
	}

	// Otherwise lookup in registry
	if ctx.Registry != nil {
		return ctx.Registry.Get(id)
	}

	return nil
}

// connectError returns an appropriate error response for connection failures.
// Per SAM spec, the RESULT value may be one of:
// - CANT_REACH_PEER: Remote peer is unreachable
// - TIMEOUT: Connection timed out
// - PEER_NOT_FOUND: Remote destination not found
// - INVALID_KEY: Destination key is malformed
// - I2P_ERROR: Other I2P-related errors
func (h *StreamHandler) connectError(err error) *protocol.Response {
	// Map specific error types to SAM result codes
	switch {
	case errors.Is(err, util.ErrTimeout):
		return streamTimeout(err.Error())
	case errors.Is(err, util.ErrPeerNotFound):
		return streamPeerNotFound(err.Error())
	case errors.Is(err, util.ErrLeasesetNotFound):
		return streamPeerNotFound(err.Error()) // Leaseset not found is similar to peer not found
	case errors.Is(err, util.ErrInvalidKey):
		return streamInvalidKey(err.Error())
	case errors.Is(err, util.ErrCantReachPeer):
		return streamCantReachPeer(err.Error())
	default:
		// Check for net timeout errors
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return streamTimeout(err.Error())
		}
		// Default to CANT_REACH_PEER for unknown errors
		return streamCantReachPeer(err.Error())
	}
}

// Helper functions

// parseBool parses a boolean string with a default value.
func parseBool(s string, defaultVal bool) bool {
	if s == "" {
		return defaultVal
	}
	switch s {
	case "true", "TRUE", "True", "1":
		return true
	case "false", "FALSE", "False", "0":
		return false
	default:
		return defaultVal
	}
}

// parseInt parses an integer string with a default value.
func parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// isValidPort checks if a port number is valid (0-65535).
func isValidPort(port int) bool {
	return port >= 0 && port <= 65535
}

// extractHost extracts the host from a host:port string.
// Handles IPv4 ("192.168.1.1:8080"), IPv6 ("[::1]:8080"), and plain hosts.
// Per SAMv3.md: "If not given, SAM takes the IP of the socket that issued the forward command"
func extractHost(addr string) string {
	if addr == "" {
		return "127.0.0.1"
	}

	// Handle net.Addr.String() formats properly
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present, check if it's an IPv6 address in brackets
		if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
			return addr[1 : len(addr)-1]
		}
		// Otherwise return as-is (plain hostname or IP)
		return addr
	}

	if host == "" {
		return "127.0.0.1"
	}

	// Handle IPv6 zone identifiers (e.g., "fe80::1%eth0")
	// Keep the zone as it may be needed for link-local addresses
	return host
}

// Response builders

// streamOK returns a successful STREAM STATUS response.
func streamOK() *protocol.Response {
	return protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultOK)
}

// streamInvalidID returns an INVALID_ID error response.
func streamInvalidID(msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultInvalidID)
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// streamInvalidKey returns an INVALID_KEY error response.
func streamInvalidKey(msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultInvalidKey)
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// streamCantReachPeer returns a CANT_REACH_PEER error response.
func streamCantReachPeer(msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultCantReachPeer)
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// streamPeerNotFound returns a PEER_NOT_FOUND error response.
// Per SAM spec, used when the remote destination cannot be found.
func streamPeerNotFound(msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultPeerNotFound)
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// streamTimeout returns a TIMEOUT error response.
// Per SAM spec, used when connection attempt times out.
func streamTimeout(msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultTimeout)
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// streamAlreadyAccepting returns an ALREADY_ACCEPTING error response.
// Per SAM spec (pre-3.2), used when a concurrent ACCEPT is attempted
// on the same session ID while another ACCEPT is pending.
func streamAlreadyAccepting() *protocol.Response {
	return protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultAlreadyAccepting).
		WithMessage("concurrent ACCEPT not allowed before SAM 3.2")
}

// streamError returns an I2P_ERROR response with the given message.
func streamError(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbStream).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultI2PError).
		WithMessage(msg)
}
