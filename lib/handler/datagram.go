// Package handler implements SAM command handlers per SAMv3.md specification.
// This file implements DATAGRAM SEND and DATAGRAM RECEIVED handling per SAM 3.0-3.3.
package handler

import (
	"fmt"
	"strconv"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// DatagramHandler handles DATAGRAM SEND commands per SAM 3.0-3.3 specification.
//
// DATAGRAM SEND is used to send repliable/authenticated datagrams directly via
// the SAM bridge socket. Unlike RAW datagrams, DATAGRAM includes sender destination
// and signature, enabling replies.
//
// Per SAMv3.md:
//   - DATAGRAM SEND supported on bridge socket for STYLE=DATAGRAM sessions
//   - FROM_PORT, TO_PORT options added in SAM 3.2
//   - SAM 3.3 adds SEND_TAGS, TAG_THRESHOLD, EXPIRES, SEND_LEASESET options
//   - Does not support ID parameter (sends to most recently created DATAGRAM session)
type DatagramHandler struct{}

// NewDatagramHandler creates a new DATAGRAM command handler.
func NewDatagramHandler() *DatagramHandler {
	return &DatagramHandler{}
}

// Handle processes DATAGRAM commands (SEND).
//
// Per SAMv3.md, DATAGRAM commands operate on the most recently created DATAGRAM session
// for this connection (the ID parameter is not supported).
//
// Commands:
//   - DATAGRAM SEND DESTINATION=$dest SIZE=$size [FROM_PORT=nnn] [TO_PORT=nnn]
//     [SEND_TAGS=n] [TAG_THRESHOLD=n] [EXPIRES=n] [SEND_LEASESET=true|false] \n <data>
//
// Response on failure:
//   - DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE="..."
func (h *DatagramHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Require handshake completion
	if !ctx.HandshakeComplete {
		return datagramError("handshake not complete"), nil
	}

	switch cmd.Action {
	case protocol.ActionSend:
		return h.handleSend(ctx, cmd)
	default:
		return datagramError("unknown DATAGRAM action: " + cmd.Action), nil
	}
}

// handleSend processes DATAGRAM SEND command.
//
// Request format per SAMv3.md:
//
//	DATAGRAM SEND DESTINATION=$dest SIZE=$size [FROM_PORT=nnn] [TO_PORT=nnn]
//	              [SEND_TAGS=n] [TAG_THRESHOLD=n] [EXPIRES=n] [SEND_LEASESET=true|false] \n
//	<$size bytes of data>
//
// Response on success: none (datagram is queued for sending)
// Response on failure: DATAGRAM STATUS RESULT=... MESSAGE=...
//
// Per SAMv3.md:
//   - Sends to the most recently created DATAGRAM-style session
//   - FROM_PORT, TO_PORT override session defaults (SAM 3.2+)
//   - SAM 3.3 options: SEND_TAGS, TAG_THRESHOLD, EXPIRES, SEND_LEASESET
//     (parsed but not yet fully implemented pending go-datagrams integration)
func (h *DatagramHandler) handleSend(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Require bound session
	if ctx.Session == nil {
		return datagramError("no session bound"), nil
	}

	// Per SAMv3.md: "v1/v2 datagram/raw sending/receiving are not supported
	// on a primary session or on subsessions"
	// DATAGRAM SEND is a V1/V2 command - reject on PRIMARY sessions
	if _, isPrimary := ctx.Session.(session.PrimarySession); isPrimary {
		return datagramError("DATAGRAM SEND not supported on PRIMARY sessions; use UDP socket"), nil
	}

	// Verify session is DATAGRAM style
	dgSess, ok := ctx.Session.(session.DatagramSession)
	if !ok {
		return datagramError("session is not STYLE=DATAGRAM"), nil
	}

	// Parse required DESTINATION
	dest := cmd.Get("DESTINATION")
	if dest == "" {
		return datagramInvalidKey("missing DESTINATION"), nil
	}

	// Parse required SIZE
	sizeStr := cmd.Get("SIZE")
	if sizeStr == "" {
		return datagramInvalidKey("missing SIZE"), nil
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size < 1 {
		return datagramInvalidKey("invalid SIZE: must be positive integer"), nil
	}
	if size > session.MaxDatagramSize {
		return datagramInvalidKey(fmt.Sprintf("SIZE exceeds maximum (%d)", session.MaxDatagramSize)), nil
	}

	// Parse optional FROM_PORT (SAM 3.2+)
	fromPort := 0
	if fromPortStr := cmd.Get("FROM_PORT"); fromPortStr != "" {
		fromPort, err = parseDatagramPort(fromPortStr, "FROM_PORT")
		if err != nil {
			return datagramInvalidKey(err.Error()), nil
		}
	}

	// Parse optional TO_PORT (SAM 3.2+)
	toPort := 0
	if toPortStr := cmd.Get("TO_PORT"); toPortStr != "" {
		toPort, err = parseDatagramPort(toPortStr, "TO_PORT")
		if err != nil {
			return datagramInvalidKey(err.Error()), nil
		}
	}

	// Parse optional SAM 3.3 options (logged but not yet fully implemented)
	// These are parsed for protocol completeness and future go-datagrams integration
	_ = cmd.Get("SEND_TAGS")     // Number of tags to send
	_ = cmd.Get("TAG_THRESHOLD") // Threshold for requesting more tags
	_ = cmd.Get("EXPIRES")       // Message expiration time
	_ = cmd.Get("SEND_LEASESET") // Whether to include leaseset

	// Get payload data from command
	// NOTE: The actual data follows the command line and is SIZE bytes.
	// The payload is populated by the parser based on the SIZE option.
	data := cmd.Payload
	if len(data) != size {
		return datagramError(fmt.Sprintf("payload size mismatch: expected %d, got %d", size, len(data))), nil
	}

	// Build send options
	opts := session.DatagramSendOptions{
		FromPort: fromPort,
		ToPort:   toPort,
	}

	// Send the datagram
	if err := dgSess.Send(dest, data, opts); err != nil {
		return datagramError("send failed: " + err.Error()), nil
	}

	// No response on success per SAMv3.md
	return nil, nil
}

// parseDatagramPort validates and parses a port string.
// Returns error if port is invalid (negative, > 65535, or non-numeric).
func parseDatagramPort(s, name string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid port value", name)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("%s: port must be 0-65535", name)
	}
	return port, nil
}

// FormatDatagramReceived creates a DATAGRAM RECEIVED response for incoming datagrams.
//
// Per SAMv3.md, the format is:
//
//	DATAGRAM RECEIVED DESTINATION=$dest SIZE=$numBytes [FROM_PORT=nnn] [TO_PORT=nnn] \n
//	<$numBytes of data>
//
// Parameters:
//   - dg: The received datagram containing source, ports, and data
//
// Returns the formatted response line (without the data payload).
func FormatDatagramReceived(dg session.ReceivedDatagram) string {
	return fmt.Sprintf("DATAGRAM RECEIVED DESTINATION=%s SIZE=%d FROM_PORT=%d TO_PORT=%d",
		dg.Source, len(dg.Data), dg.FromPort, dg.ToPort)
}

// FormatDatagramForward creates the header line for forwarded DATAGRAM datagrams.
//
// Per SAMv3.md, forwarded repliable datagrams are prepended with:
//
//	$destination\n
//	<datagram_payload>
//
// Parameters:
//   - dg: The received datagram containing source destination
//
// Returns the header line (just the destination, without trailing newline).
func FormatDatagramForward(dg session.ReceivedDatagram) string {
	return dg.Source
}

// datagramError creates a DATAGRAM STATUS error response.
func datagramError(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbDatagram).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultI2PError).
		WithMessage(msg)
}

// datagramInvalidKey creates a DATAGRAM STATUS INVALID_KEY error response.
func datagramInvalidKey(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbDatagram).
		WithAction(protocol.ActionStatus).
		WithResult(protocol.ResultInvalidKey).
		WithMessage(msg)
}

// RegisterDatagramHandler registers the DATAGRAM handler with the router.
// This should be called during server initialization to enable DATAGRAM commands.
func RegisterDatagramHandler(router *Router) {
	handler := NewDatagramHandler()
	router.Register(protocol.VerbDatagram, handler)
}
