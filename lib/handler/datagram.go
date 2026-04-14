// Package handler implements SAM command handlers per SAMv3.md specification.
// This file implements DATAGRAM SEND and DATAGRAM RECEIVED handling per SAM 3.0-3.3.
package handler

import (
	"fmt"

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
type DatagramHandler struct {
	// style is the session style this handler targets (StyleDatagram, StyleDatagram2, StyleDatagram3).
	style session.Style
}

// NewDatagramHandler creates a new DATAGRAM command handler for STYLE=DATAGRAM sessions.
func NewDatagramHandler() *DatagramHandler {
	return &DatagramHandler{style: session.StyleDatagram}
}

// NewDatagram2Handler creates a new DATAGRAM2 command handler for STYLE=DATAGRAM2 sessions.
func NewDatagram2Handler() *DatagramHandler {
	return &DatagramHandler{style: session.StyleDatagram2}
}

// NewDatagram3Handler creates a new DATAGRAM3 command handler for STYLE=DATAGRAM3 sessions.
func NewDatagram3Handler() *DatagramHandler {
	return &DatagramHandler{style: session.StyleDatagram3}
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
	// Per SAMv3.md: "These commands do not support the ID parameter"
	if cmd.Get("ID") != "" {
		return datagramError("DATAGRAM SEND does not support ID parameter"), nil
	}

	// Lookup DATAGRAM session
	dgSess, resp := h.lookupDatagramSession(ctx)
	if resp != nil {
		return resp, nil
	}

	// Parse and validate required parameters
	dest, size, resp := parseSendRequiredParams(cmd, session.MaxDatagramSize, datagramInvalidKey)
	if resp != nil {
		return resp, nil
	}

	// Parse port options (SAM 3.2+)
	fromPort, toPort, resp := parseSendPortOptions(cmd, datagramInvalidKey)
	if resp != nil {
		return resp, nil
	}

	// Parse SAM 3.3 options
	sam33Opts, resp := parseSendSAM33Options(cmd, datagramInvalidKey)
	if resp != nil {
		return resp, nil
	}

	// Validate payload size
	data := cmd.Payload
	if len(data) != size {
		return datagramError(fmt.Sprintf("payload size mismatch: expected %d, got %d", size, len(data))), nil
	}

	// Build send options and send
	opts := h.buildDatagramSendOptions(fromPort, toPort, sam33Opts)
	if err := dgSess.Send(dest, data, opts); err != nil {
		return datagramError("send failed: " + err.Error()), nil
	}

	// No response on success per SAMv3.md
	return nil, nil
}

// lookupDatagramSession finds the appropriate DATAGRAM session for sending.
// Per SAMv3.md, tries bound session first, then most recently created.
func (h *DatagramHandler) lookupDatagramSession(ctx *Context) (session.DatagramSession, *protocol.Response) {
	var dgSess session.DatagramSession
	var ok bool

	if ctx.Session != nil {
		// Per SAMv3.md: "v1/v2 datagram/raw sending/receiving are not supported
		// on a primary session or on subsessions"
		if _, isPrimary := ctx.Session.(session.PrimarySession); isPrimary {
			return nil, datagramError("DATAGRAM SEND not supported on PRIMARY sessions; use UDP socket")
		}
		dgSess, ok = ctx.Session.(session.DatagramSession)
	}

	// If bound session is not the target style, try most recently created
	if !ok && ctx.Registry != nil {
		if mostRecent := ctx.Registry.MostRecentByStyle(h.style); mostRecent != nil {
			dgSess, ok = mostRecent.(session.DatagramSession)
		}
	}

	if !ok || dgSess == nil {
		return nil, datagramError("no " + string(h.style) + " session available")
	}
	return dgSess, nil
}

// buildDatagramSendOptions constructs DatagramSendOptions from parsed parameters.
func (h *DatagramHandler) buildDatagramSendOptions(fromPort, toPort uint16, sam33 *sendSAM33Options) session.DatagramSendOptions {
	return session.DatagramSendOptions{
		FromPort:        fromPort,
		ToPort:          toPort,
		SendTags:        sam33.SendTags,
		TagThreshold:    sam33.TagThreshold,
		Expires:         sam33.Expires,
		SendLeaseset:    sam33.SendLeaseset,
		SendLeasesetSet: sam33.SendLeasesetSet,
	}
}

// FormatDatagramReceived creates a DATAGRAM RECEIVED response for incoming datagrams.
//
// Per SAMv3.md, the format is:
//
//	DATAGRAM RECEIVED DESTINATION=$dest SIZE=$numBytes [FROM_PORT=nnn] [TO_PORT=nnn] \n
//	<$numBytes of data>
//
// Note: FROM_PORT and TO_PORT are only included for SAM 3.2 or higher.
//
// Parameters:
//   - dg: The received datagram containing source, ports, and data
//   - version: The negotiated SAM version (e.g., "3.2", "3.3")
//
// Returns the formatted response line (without the data payload).
func FormatDatagramReceived(dg session.ReceivedDatagram, version string) string {
	if protocol.VersionSupportsPortInfo(version) {
		return fmt.Sprintf("DATAGRAM RECEIVED DESTINATION=%s SIZE=%d FROM_PORT=%d TO_PORT=%d",
			dg.Source, len(dg.Data), dg.FromPort, dg.ToPort)
	}
	// SAM 3.0/3.1: No port info
	return fmt.Sprintf("DATAGRAM RECEIVED DESTINATION=%s SIZE=%d",
		dg.Source, len(dg.Data))
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

// RegisterDatagramHandler registers DATAGRAM, DATAGRAM2, and DATAGRAM3 handlers
// with the router per SAM 3.0-3.3 specification.
// This should be called during server initialization to enable all datagram commands.
func RegisterDatagramHandler(router *Router) {
	router.Register(protocol.VerbDatagram, NewDatagramHandler())
	router.Register(protocol.VerbDatagram2, NewDatagram2Handler())
	router.Register(protocol.VerbDatagram3, NewDatagram3Handler())
}
