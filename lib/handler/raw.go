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
	// Per SAMv3.md: "These commands do not support the ID parameter"
	if cmd.Get("ID") != "" {
		return rawError("RAW SEND does not support ID parameter"), nil
	}

	// Lookup RAW session
	rawSess, resp := h.lookupRawSession(ctx)
	if resp != nil {
		return resp, nil
	}

	// Parse and validate required parameters
	dest, size, resp := parseSendRequiredParams(cmd, session.MaxRawDatagramSize, rawInvalidKey)
	if resp != nil {
		return resp, nil
	}

	// Parse port options (SAM 3.2+)
	fromPort, toPort, resp := parseSendPortOptions(cmd, rawInvalidKey)
	if resp != nil {
		return resp, nil
	}

	// Parse protocol option
	protocolNum, resp := h.parseProtocolOption(cmd, rawSess.Protocol())
	if resp != nil {
		return resp, nil
	}

	// Parse SAM 3.3 options
	sam33Opts, resp := parseSendSAM33Options(cmd, rawInvalidKey)
	if resp != nil {
		return resp, nil
	}

	// Validate payload size
	data := cmd.Payload
	if len(data) != size {
		return rawError(fmt.Sprintf("payload size mismatch: expected %d, got %d", size, len(data))), nil
	}

	// Build send options and send
	opts := h.buildSendOptions(fromPort, toPort, protocolNum, sam33Opts)
	if err := rawSess.Send(dest, data, opts); err != nil {
		return rawError("send failed: " + err.Error()), nil
	}

	// No response on success per SAMv3.md
	return nil, nil
}

// lookupRawSession finds the appropriate RAW session for sending.
// Per SAMv3.md, tries bound session first, then most recently created.
func (h *RawHandler) lookupRawSession(ctx *Context) (session.RawSession, *protocol.Response) {
	var rawSess session.RawSession
	var ok bool

	if ctx.Session != nil {
		// Per SAMv3.md: "v1/v2 datagram/raw sending/receiving are not supported
		// on a primary session or on subsessions"
		if _, isPrimary := ctx.Session.(session.PrimarySession); isPrimary {
			return nil, rawError("RAW SEND not supported on PRIMARY sessions; use UDP socket")
		}
		rawSess, ok = ctx.Session.(session.RawSession)
	}

	// If bound session is not RAW style, try most recently created
	if !ok && ctx.Registry != nil {
		if mostRecent := ctx.Registry.MostRecentByStyle(session.StyleRaw); mostRecent != nil {
			rawSess, ok = mostRecent.(session.RawSession)
		}
	}

	if !ok || rawSess == nil {
		return nil, rawError("no RAW session available")
	}
	return rawSess, nil
}

// parseProtocolOption extracts PROTOCOL from the command (SAM 3.2+).
func (h *RawHandler) parseProtocolOption(cmd *protocol.Command, defaultProtocol int) (int, *protocol.Response) {
	protoStr := cmd.Get("PROTOCOL")
	if protoStr == "" {
		return defaultProtocol, nil
	}
	protocolNum, err := parseProtocol(protoStr)
	if err != nil {
		return 0, rawInvalidKey(err.Error())
	}
	return protocolNum, nil
}

// buildSendOptions constructs RawSendOptions from parsed parameters.
func (h *RawHandler) buildSendOptions(fromPort, toPort uint16, protocolNum int, sam33 *sendSAM33Options) session.RawSendOptions {
	return session.RawSendOptions{
		FromPort:        fromPort,
		ToPort:          toPort,
		Protocol:        protocolNum,
		SendTags:        sam33.SendTags,
		TagThreshold:    sam33.TagThreshold,
		Expires:         sam33.Expires,
		SendLeaseset:    sam33.SendLeaseset,
		SendLeasesetSet: sam33.SendLeasesetSet,
	}
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
// Note: FROM_PORT, TO_PORT, and PROTOCOL are only included for SAM 3.2 or higher.
//
// Parameters:
//   - dg: The received raw datagram containing port, protocol, and data
//   - version: The negotiated SAM version (e.g., "3.2", "3.3")
//
// Returns the formatted response line (without the data payload).
func FormatRawReceived(dg session.ReceivedRawDatagram, version string) string {
	if protocol.VersionSupportsPortInfo(version) {
		return fmt.Sprintf("RAW RECEIVED SIZE=%d FROM_PORT=%d TO_PORT=%d PROTOCOL=%d",
			len(dg.Data), dg.FromPort, dg.ToPort, dg.Protocol)
	}
	// SAM 3.0/3.1: No port/protocol info
	return fmt.Sprintf("RAW RECEIVED SIZE=%d", len(dg.Data))
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
