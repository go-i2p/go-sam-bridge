// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"strings"

	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// LeasesetOption represents a single key-value option from a leaseset.
// Per SAM API 0.9.66, options are returned with OPTION: prefix.
type LeasesetOption struct {
	Key   string
	Value string
}

// LeasesetLookupResult contains the result of a leaseset lookup with options.
type LeasesetLookupResult struct {
	// Destination is the resolved destination as Base64.
	Destination string
	// Options contains the leaseset options (service records, etc.).
	Options []LeasesetOption
	// Found indicates whether the leaseset was found.
	Found bool
}

// LeasesetLookupProvider is the interface for querying leasesets with options.
// This abstracts the I2CP integration for testing purposes.
type LeasesetLookupProvider interface {
	// LookupWithOptions performs a leaseset lookup and returns options if requested.
	// Returns the destination and any leaseset options.
	LookupWithOptions(name string) (*LeasesetLookupResult, error)
}

// NamingHandler handles NAMING LOOKUP commands per SAM 3.0-3.3.
// Resolves I2P hostnames, .b32.i2p addresses, and special names like ME.
// As of API 0.9.66, supports OPTIONS=true for leaseset option queries.
type NamingHandler struct {
	destManager      destination.Manager
	leasesetProvider LeasesetLookupProvider
}

// NewNamingHandler creates a new NAMING handler with the given destination manager.
func NewNamingHandler(destManager destination.Manager) *NamingHandler {
	return &NamingHandler{destManager: destManager}
}

// SetLeasesetProvider sets the leaseset lookup provider for OPTIONS=true support.
// If not set, OPTIONS=true lookups will fail with I2P_ERROR.
func (h *NamingHandler) SetLeasesetProvider(provider LeasesetLookupProvider) {
	h.leasesetProvider = provider
}

// Handle processes a NAMING LOOKUP command.
// Per SAMv3.md, NAMING LOOKUP resolves names to destinations.
//
// Request: NAMING LOOKUP NAME=$name [OPTIONS=true]
// Response: NAMING REPLY RESULT=OK NAME=$name VALUE=$destination [OPTION:key=value...]
//
//	NAMING REPLY RESULT=KEY_NOT_FOUND NAME=$name
//	NAMING REPLY RESULT=INVALID_KEY NAME=$name MESSAGE="..."
//	NAMING REPLY RESULT=LEASESET_NOT_FOUND NAME=$name (when OPTIONS=true)
func (h *NamingHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	name := cmd.Get("NAME")
	if name == "" {
		return namingInvalidKey("", "missing NAME parameter"), nil
	}

	// Check for OPTIONS=true (API 0.9.66)
	optionsRequested := isOptionsTrue(cmd.Get("OPTIONS"))

	// Special case: NAME=ME returns session destination
	if name == "ME" {
		return h.handleNameMe(ctx, name, optionsRequested)
	}

	// Validate name format
	if !isValidName(name) {
		return namingInvalidKey(name, "invalid name format"), nil
	}

	// If OPTIONS=true, use leaseset lookup path
	if optionsRequested {
		return h.handleOptionsLookup(name)
	}

	// Standard name resolution without options
	dest, err := h.resolveName(name)
	if err != nil {
		return namingKeyNotFound(name), nil
	}

	return namingOK(name, dest), nil
}

// handleNameMe returns the destination of the current session.
// When optionsRequested is true, it would also return leaseset options,
// but for the current session, we typically don't have external leaseset options.
func (h *NamingHandler) handleNameMe(ctx *Context, name string, optionsRequested bool) (*protocol.Response, error) {
	if ctx.Session == nil {
		return namingInvalidKey(name, "no session bound"), nil
	}

	dest := ctx.Session.Destination()
	if dest == nil {
		return namingInvalidKey(name, "session has no destination"), nil
	}

	// Return the public key as base64
	// Note: For NAME=ME, we don't query leaseset options as this is our own session
	return namingOK(name, string(dest.PublicKey)), nil
}

// handleOptionsLookup performs a NAMING LOOKUP with OPTIONS=true per API 0.9.66.
// This queries the leaseset for the destination and returns any options found.
func (h *NamingHandler) handleOptionsLookup(name string) (*protocol.Response, error) {
	// Check if leaseset provider is available
	if h.leasesetProvider == nil {
		// Per SAM 3.2, return I2P_ERROR if the feature is not supported
		return namingI2PError(name, "leaseset options lookup not available"), nil
	}

	// Perform the leaseset lookup
	result, err := h.leasesetProvider.LookupWithOptions(name)
	if err != nil {
		return namingI2PError(name, err.Error()), nil
	}

	// If leaseset not found when OPTIONS=true, return LEASESET_NOT_FOUND per API 0.9.66
	if !result.Found {
		return namingLeasesetNotFound(name), nil
	}

	// Build response with destination and any options
	return namingOKWithOptions(name, result.Destination, result.Options), nil
}

// resolveName attempts to resolve a name to a destination.
// Supports .i2p hostnames and .b32.i2p addresses.
func (h *NamingHandler) resolveName(name string) (string, error) {
	// Check for .b32.i2p address
	if isB32Address(name) {
		return h.resolveB32(name)
	}

	// Check for .i2p hostname
	if isI2PHostname(name) {
		return h.resolveHostname(name)
	}

	// Check if it's already a Base64 destination
	if isBase64Destination(name) {
		return name, nil
	}

	return "", &namingErr{msg: "unknown name format"}
}

// resolveB32 resolves a .b32.i2p address.
// TODO: This requires network lookup via I2CP.
func (h *NamingHandler) resolveB32(name string) (string, error) {
	// For now, return not found - actual lookup requires I2CP integration
	return "", &namingErr{msg: "b32 lookup not implemented"}
}

// resolveHostname resolves an .i2p hostname.
// TODO: This requires addressbook lookup or network query.
func (h *NamingHandler) resolveHostname(name string) (string, error) {
	// For now, return not found - actual lookup requires addressbook
	return "", &namingErr{msg: "hostname lookup not implemented"}
}

// isValidName checks if a name is valid for lookup.
func isValidName(name string) bool {
	if name == "" {
		return false
	}
	// Check for obviously invalid characters
	if strings.ContainsAny(name, "\n\r\t") {
		return false
	}
	return true
}

// isB32Address checks if the name is a .b32.i2p address.
func isB32Address(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".b32.i2p")
}

// isI2PHostname checks if the name is an .i2p hostname (not b32).
func isI2PHostname(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".i2p") && !strings.HasSuffix(lower, ".b32.i2p")
}

// isBase64Destination checks if the name looks like a base64 destination.
// Destinations are 516+ base64 characters.
func isBase64Destination(name string) bool {
	if len(name) < 516 {
		return false
	}
	// Check for valid base64 characters (I2P alphabet)
	for _, c := range name {
		if !isBase64Char(c) {
			return false
		}
	}
	return true
}

// isBase64Char checks if a rune is a valid I2P Base64 character.
func isBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '~'
}

// namingOK returns a successful NAMING REPLY response.
func namingOK(name, destination string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbNaming).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultOK).
		WithOption("NAME", name).
		WithOption("VALUE", destination)
}

// namingKeyNotFound returns a KEY_NOT_FOUND response.
func namingKeyNotFound(name string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbNaming).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultKeyNotFound).
		WithOption("NAME", name)
}

// namingInvalidKey returns an INVALID_KEY response.
func namingInvalidKey(name, msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbNaming).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultInvalidKey)
	if name != "" {
		resp = resp.WithOption("NAME", name)
	}
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// namingLeasesetNotFound returns a LEASESET_NOT_FOUND response per API 0.9.66.
// This is returned when OPTIONS=true and the leaseset cannot be found.
func namingLeasesetNotFound(name string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbNaming).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultLeasesetNotFound).
		WithOption("NAME", name)
}

// namingI2PError returns an I2P_ERROR response with a message.
func namingI2PError(name, msg string) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbNaming).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultI2PError)
	if name != "" {
		resp = resp.WithOption("NAME", name)
	}
	if msg != "" {
		resp = resp.WithMessage(msg)
	}
	return resp
}

// namingOKWithOptions returns a successful NAMING REPLY response with leaseset options.
// Per API 0.9.66, options are returned with OPTION: prefix.
func namingOKWithOptions(name, destination string, options []LeasesetOption) *protocol.Response {
	resp := protocol.NewResponse(protocol.VerbNaming).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultOK).
		WithOption("NAME", name).
		WithOption("VALUE", destination)

	// Add filtered options with OPTION: prefix per API 0.9.66
	for _, opt := range options {
		if isValidLeasesetOption(opt.Key, opt.Value) {
			resp = resp.WithOption("OPTION:"+opt.Key, opt.Value)
		}
	}

	return resp
}

// isOptionsTrue checks if the OPTIONS parameter is set to true.
// Per SAM spec, empty or missing is treated as false.
func isOptionsTrue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "true" || lower == "yes" || lower == "1"
}

// isValidLeasesetOption checks if a leaseset option key/value pair is valid.
// Per SAM API 0.9.66, keys containing '=' and keys or values containing
// newlines are considered invalid and should be filtered out.
func isValidLeasesetOption(key, value string) bool {
	// Keys cannot contain '='
	if strings.Contains(key, "=") {
		return false
	}
	// Keys and values cannot contain newlines
	if strings.ContainsAny(key, "\n\r") {
		return false
	}
	if strings.ContainsAny(value, "\n\r") {
		return false
	}
	// Empty keys are invalid
	if key == "" {
		return false
	}
	return true
}

// namingErr is an error type for naming lookup errors.
type namingErr struct {
	msg string
}

func (e *namingErr) Error() string {
	return e.msg
}

// Ensure NamingHandler implements Handler interface
var _ Handler = (*NamingHandler)(nil)
