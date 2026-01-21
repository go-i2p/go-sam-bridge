// Package handler implements SAM command handlers per SAMv3.md specification.
// This file implements RAW SEND and RAW RECEIVED handling per SAM 3.1-3.3.
package handler

import (
	"fmt"
	"strconv"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// RawHandler handles RAW SEND commands per SAM 3.1-3.3 specification.
//
// RAW SEND is used to send anonymous datagrams directly via the SAM bridge socket.
// Unlike DATAGRAM SEND, RAW datagrams do not include sender destination or signature,
// providing anonymity at the cost of non-repliability.
//
// Per SAMv3.md:
//   - RAW SEND supported on bridge socket as of SAM 3.1
//   - FROM_PORT, TO_PORT options added in SAM 3.2
//   - PROTOCOL option added in SAM 3.2
//   - Does not support ID parameter (sends to most recently created RAW session)
type RawHandler struct{}

// NewRawHandler creates a new RAW command handler.
func NewRawHandler() *RawHandler {
	return &RawHandler{}
}

// Handle processes RAW commands (SEND).
//
// Per SAMv3.md, RAW commands operate on the most recently created RAW session
// for this connection (the ID parameter is not supported).
//
// Commands:
//   - RAW SEND DESTINATION=$dest SIZE=$size [FROM_PORT=nnn] [TO_PORT=nnn] [PROTOCOL=nnn] \n <data>
//
// Response on failure:
//   - RAW STATUS RESULT=I2P_ERROR MESSAGE="..."
func (h *RawHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Require handshake completion
	if !ctx.HandshakeComplete {
		return rawError("handshake not complete"), nil
	}

	switch cmd.Action {
	case protocol.ActionSend:
		return h.handleSend(ctx, cmd)
	default:
		return rawError("unknown RAW action: " + cmd.Action), nil
	}
}

// handleSend processes RAW SEND command.
//
// Request format per SAMv3.md:
//
//	RAW SEND DESTINATION=$dest SIZE=$size [FROM_PORT=nnn] [TO_PORT=nnn] [PROTOCOL=nnn] \n
//	<$size bytes of data>
//
// Response on success: none (datagram is queued for sending)
// Response on failure: RAW STATUS RESULT=... MESSAGE=...
//
// Per SAMv3.md:
//   - Sends to the most recently created RAW-style session
//   - FROM_PORT, TO_PORT, PROTOCOL override session defaults (SAM 3.2+)
//   - Does not support DATAGRAM2/DATAGRAM3 formats
func (h *RawHandler) handleSend(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Require bound session
	if ctx.Session == nil {
		return rawError("no session bound"), nil
	}

	// Per SAMv3.md: "v1/v2 datagram/raw sending/receiving are not supported
	// on a primary session or on subsessions"
	// RAW SEND is a V1/V2 command - reject on PRIMARY sessions
	if _, isPrimary := ctx.Session.(session.PrimarySession); isPrimary {
		return rawError("RAW SEND not supported on PRIMARY sessions; use UDP socket"), nil
	}

	// Verify session is RAW style
	rawSess, ok := ctx.Session.(session.RawSession)
	if !ok {
		return rawError("session is not STYLE=RAW"), nil
	}

	// Parse required DESTINATION
	dest := cmd.Get("DESTINATION")
	if dest == "" {
		return rawInvalidKey("missing DESTINATION"), nil
	}

	// Parse required SIZE
	sizeStr := cmd.Get("SIZE")
	if sizeStr == "" {
		return rawInvalidKey("missing SIZE"), nil
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size < 1 {
		return rawInvalidKey("invalid SIZE: must be positive integer"), nil
	}
	if size > session.MaxRawDatagramSize {
		return rawInvalidKey(fmt.Sprintf("SIZE exceeds maximum (%d)", session.MaxRawDatagramSize)), nil
	}

	// Parse optional FROM_PORT (SAM 3.2+)
	fromPort := 0
	if fromPortStr := cmd.Get("FROM_PORT"); fromPortStr != "" {
		fromPort, err = parsePort(fromPortStr, "FROM_PORT")
		if err != nil {
			return rawInvalidKey(err.Error()), nil
		}
	}

	// Parse optional TO_PORT (SAM 3.2+)
	toPort := 0
	if toPortStr := cmd.Get("TO_PORT"); toPortStr != "" {
		toPort, err = parsePort(toPortStr, "TO_PORT")
		if err != nil {
			return rawInvalidKey(err.Error()), nil
		}
	}

	// Parse optional PROTOCOL (SAM 3.2+)
	protocolNum := rawSess.Protocol() // Default to session protocol
	if protoStr := cmd.Get("PROTOCOL"); protoStr != "" {
		protocolNum, err = parseProtocol(protoStr)
		if err != nil {
			return rawInvalidKey(err.Error()), nil
		}
	}

	// Get payload data from command
	// NOTE: The actual data follows the command line and is SIZE bytes.
	// For now, we get it from cmd.Payload which should be populated by the parser.
	data := cmd.Payload
	if len(data) != size {
		return rawError(fmt.Sprintf("payload size mismatch: expected %d, got %d", size, len(data))), nil
	}

	// Build send options
	opts := session.RawSendOptions{
		FromPort: fromPort,
		ToPort:   toPort,
		Protocol: protocolNum,
	}

	// Send the raw datagram
	if err := rawSess.Send(dest, data, opts); err != nil {
		return rawError("send failed: " + err.Error()), nil
	}

	// No response on success per SAMv3.md
	return nil, nil
}

// parsePort validates and parses a port string.
// Returns error if port is invalid (negative, > 65535, or non-numeric).
func parsePort(s, name string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid port value", name)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("%s: port must be 0-65535", name)
	}
	return port, nil
}

// parseProtocol validates and parses a protocol string.
// Returns error if protocol is invalid (negative, > 255, or disallowed 6,17,19,20).
func parseProtocol(s string) (int, error) {
	proto, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("PROTOCOL: invalid protocol value")
	}
	if proto < 0 || proto > 255 {
		return 0, fmt.Errorf("PROTOCOL: must be 0-255")
	}
	// Check disallowed protocols per SAM specification
	for _, disallowed := range protocol.DisallowedRawProtocols {
		if proto == disallowed {
			return 0, fmt.Errorf("PROTOCOL: %d is not allowed for RAW sessions", proto)
		}
	}
	return proto, nil
}

// FormatRawReceived creates a RAW RECEIVED response for incoming datagrams.
//
// Per SAMv3.md, the format is:
//
//	RAW RECEIVED SIZE=$numBytes [FROM_PORT=nnn] [TO_PORT=nnn] [PROTOCOL=nnn] \n
//	<$numBytes of data>
//
// Parameters:
//   - dg: The received raw datagram containing port, protocol, and data
//
// Returns the formatted response line (without the data payload).
func FormatRawReceived(dg session.ReceivedRawDatagram) string {
	return fmt.Sprintf("RAW RECEIVED SIZE=%d FROM_PORT=%d TO_PORT=%d PROTOCOL=%d",
		len(dg.Data), dg.FromPort, dg.ToPort, dg.Protocol)
}

// FormatRawHeader creates the header line for forwarded RAW datagrams.
//
// Per SAMv3.md, when HEADER=true is specified in SESSION CREATE,
// the forwarded raw datagram is prepended with:
//
//	FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn\n
//	<datagram_payload>
//
// Parameters:
//   - dg: The received raw datagram containing port and protocol info
//
// Returns the header line (without trailing newline).
func FormatRawHeader(dg session.ReceivedRawDatagram) string {
	return fmt.Sprintf("FROM_PORT=%d TO_PORT=%d PROTOCOL=%d",
		dg.FromPort, dg.ToPort, dg.Protocol)
}

// rawError creates a RAW STATUS error response.
func rawError(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbRaw).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultI2PError).
		WithMessage(msg)
}

// rawInvalidKey creates a RAW STATUS INVALID_KEY error response.
func rawInvalidKey(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbRaw).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultInvalidKey).
		WithMessage(msg)
}
