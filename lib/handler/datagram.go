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
	// Lookup DATAGRAM session
	dgSess, resp := h.lookupDatagramSession(ctx)
	if resp != nil {
		return resp, nil
	}

	// Parse and validate required parameters
	dest, size, resp := h.parseDatagramRequiredParams(cmd)
	if resp != nil {
		return resp, nil
	}

	// Parse port options (SAM 3.2+)
	fromPort, toPort, resp := h.parseDatagramPortOptions(cmd)
	if resp != nil {
		return resp, nil
	}

	// Parse SAM 3.3 options
	sam33Opts, resp := h.parseDatagramSAM33Options(cmd)
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

	// If bound session is not DATAGRAM style, try most recently created
	if !ok && ctx.Registry != nil {
		if mostRecent := ctx.Registry.MostRecentByStyle(session.StyleDatagram); mostRecent != nil {
			dgSess, ok = mostRecent.(session.DatagramSession)
		}
	}

	if !ok || dgSess == nil {
		return nil, datagramError("no DATAGRAM session available")
	}
	return dgSess, nil
}

// parseDatagramRequiredParams validates and extracts DESTINATION and SIZE from the command.
func (h *DatagramHandler) parseDatagramRequiredParams(cmd *protocol.Command) (string, int, *protocol.Response) {
	dest := cmd.Get("DESTINATION")
	if dest == "" {
		return "", 0, datagramInvalidKey("missing DESTINATION")
	}

	sizeStr := cmd.Get("SIZE")
	if sizeStr == "" {
		return "", 0, datagramInvalidKey("missing SIZE")
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size < 1 {
		return "", 0, datagramInvalidKey("invalid SIZE: must be positive integer")
	}
	if size > session.MaxDatagramSize {
		return "", 0, datagramInvalidKey(fmt.Sprintf("SIZE exceeds maximum (%d)", session.MaxDatagramSize))
	}
	return dest, size, nil
}

// parseDatagramPortOptions extracts FROM_PORT and TO_PORT from the command (SAM 3.2+).
func (h *DatagramHandler) parseDatagramPortOptions(cmd *protocol.Command) (int, int, *protocol.Response) {
	var fromPort, toPort int
	var err error

	if fromPortStr := cmd.Get("FROM_PORT"); fromPortStr != "" {
		fromPort, err = parseDatagramPort(fromPortStr, "FROM_PORT")
		if err != nil {
			return 0, 0, datagramInvalidKey(err.Error())
		}
	}

	if toPortStr := cmd.Get("TO_PORT"); toPortStr != "" {
		toPort, err = parseDatagramPort(toPortStr, "TO_PORT")
		if err != nil {
			return 0, 0, datagramInvalidKey(err.Error())
		}
	}
	return fromPort, toPort, nil
}

// datagramSAM33Options holds parsed SAM 3.3 options for datagrams.
type datagramSAM33Options struct {
	SendTags        int
	TagThreshold    int
	Expires         int
	SendLeaseset    bool
	SendLeasesetSet bool
}

// parseDatagramSAM33Options extracts SAM 3.3 specific options from the command.
func (h *DatagramHandler) parseDatagramSAM33Options(cmd *protocol.Command) (*datagramSAM33Options, *protocol.Response) {
	opts := &datagramSAM33Options{
		SendLeaseset: true, // Default per SAMv3.md
	}
	var err error

	if sendTagsStr := cmd.Get("SEND_TAGS"); sendTagsStr != "" {
		opts.SendTags, err = parseSAM33Option(sendTagsStr, "SEND_TAGS", 0, 15)
		if err != nil {
			return nil, datagramInvalidKey(err.Error())
		}
	}

	if tagThresholdStr := cmd.Get("TAG_THRESHOLD"); tagThresholdStr != "" {
		opts.TagThreshold, err = parseSAM33Option(tagThresholdStr, "TAG_THRESHOLD", 0, 15)
		if err != nil {
			return nil, datagramInvalidKey(err.Error())
		}
	}

	if expiresStr := cmd.Get("EXPIRES"); expiresStr != "" {
		opts.Expires, err = parseSAM33Option(expiresStr, "EXPIRES", 0, 86400)
		if err != nil {
			return nil, datagramInvalidKey(err.Error())
		}
	}

	if sendLeasesetStr := cmd.Get("SEND_LEASESET"); sendLeasesetStr != "" {
		opts.SendLeaseset, err = parseBoolOption(sendLeasesetStr, "SEND_LEASESET")
		if err != nil {
			return nil, datagramInvalidKey(err.Error())
		}
		opts.SendLeasesetSet = true
	}
	return opts, nil
}

// buildDatagramSendOptions constructs DatagramSendOptions from parsed parameters.
func (h *DatagramHandler) buildDatagramSendOptions(fromPort, toPort int, sam33 *datagramSAM33Options) session.DatagramSendOptions {
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

// parseSAM33Option parses a SAM 3.3 integer option with range validation.
// Per SAMv3.md, these options are optional and have router-dependent defaults.
func parseSAM33Option(s, name string, min, max int) (int, error) {
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value", name)
	}
	if val < min || val > max {
		return 0, fmt.Errorf("%s: value must be %d-%d", name, min, max)
	}
	return val, nil
}

// parseBoolOption parses a boolean option value.
// Accepts "true"/"false" (case-insensitive) per SAM specification.
func parseBoolOption(s, name string) (bool, error) {
	switch s {
	case "true", "TRUE", "True":
		return true, nil
	case "false", "FALSE", "False":
		return false, nil
	default:
		return false, fmt.Errorf("%s: must be true or false", name)
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

// RegisterDatagramHandler registers the DATAGRAM handler with the router.
// This should be called during server initialization to enable DATAGRAM commands.
func RegisterDatagramHandler(router *Router) {
	handler := NewDatagramHandler()
	router.Register(protocol.VerbDatagram, handler)
}
