// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// UtilityHandler handles QUIT, STOP, and EXIT commands per SAM 3.2.
// These commands close the session and socket.
//
// Per SAMv3.md:
//
//	-> QUIT
//	-> STOP
//	-> EXIT
//
// No response is required, but an optional SESSION STATUS may be sent.
type UtilityHandler struct {
	// SendResponse controls whether to send a response before closing.
	// Per SAM spec, response is optional.
	SendResponse bool
}

// NewUtilityHandler creates a new utility command handler.
// By default, sends a response before closing.
func NewUtilityHandler() *UtilityHandler {
	return &UtilityHandler{
		SendResponse: true,
	}
}

// Handle processes QUIT, STOP, or EXIT command.
// Returns a SESSION STATUS response if SendResponse is true, then signals close.
// The caller should close the connection after sending the response.
func (h *UtilityHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Close bound session if any
	if ctx != nil && ctx.Session != nil {
		ctx.Session.Close()
		ctx.UnbindSession()
	}

	if !h.SendResponse {
		return nil, nil
	}

	// Return optional SESSION STATUS response
	return protocol.NewResponse("SESSION").
		WithAction("STATUS").
		WithResult("OK").
		WithMessage("closing"), nil
}

// RegisterUtilityHandlers registers QUIT, STOP, and EXIT handlers with a router.
// All three commands use the same handler logic.
func RegisterUtilityHandlers(router *Router) {
	handler := NewUtilityHandler()
	router.Register("QUIT", handler)
	router.Register("STOP", handler)
	router.Register("EXIT", handler)
}

// HelpHandler handles the HELP command per SAM 3.2.
// Provides basic usage information to clients.
type HelpHandler struct{}

// NewHelpHandler creates a new HELP handler.
func NewHelpHandler() *HelpHandler {
	return &HelpHandler{}
}

// samCommands lists all implemented SAM 3.3 commands.
// This is used by the HELP handler to provide complete command documentation.
var samCommands = []string{
	"HELLO VERSION",
	"DEST GENERATE",
	"SESSION CREATE",
	"SESSION ADD",
	"SESSION REMOVE",
	"STREAM CONNECT",
	"STREAM ACCEPT",
	"STREAM FORWARD",
	"DATAGRAM SEND",
	"RAW SEND",
	"NAMING LOOKUP",
	"PING",
	"PONG",
	"AUTH ADD",
	"AUTH REMOVE",
	"AUTH ENABLE",
	"AUTH DISABLE",
	"QUIT",
	"STOP",
	"EXIT",
	"HELP",
}

// Handle processes a HELP command and returns usage information.
// Per SAM 3.2, returns a list of all implemented SAM commands.
func (h *HelpHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Build command list string
	cmdList := ""
	for i, c := range samCommands {
		if i > 0 {
			cmdList += ", "
		}
		cmdList += c
	}

	return protocol.NewResponse("HELP").
		WithAction("REPLY").
		WithResult("OK").
		WithMessage("SAM 3.3 commands: " + cmdList), nil
}

// RegisterHelpHandler registers the HELP handler with a router.
func RegisterHelpHandler(router *Router) {
	handler := NewHelpHandler()
	router.Register("HELP", handler)
}
