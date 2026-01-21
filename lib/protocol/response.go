package protocol

import (
	"strings"
)

// Response builds SAM protocol responses.
// Per SAMv3.md, responses follow the format:
//
//	VERB [ACTION] [KEY=VALUE]...
//
// All responses are terminated by a newline character.
// Some responses (like STREAM ACCEPT) may include additional lines
// that must be sent after the main response (e.g., destination info).
type Response struct {
	Verb    string
	Action  string
	Options []string // Pre-formatted KEY=VALUE pairs

	// AdditionalLines are sent after the main response line.
	// Used for STREAM ACCEPT which sends destination info on a separate line.
	// Each additional line is sent as-is with newline terminator.
	AdditionalLines []string
}

// NewResponse creates a new response builder with the given verb.
func NewResponse(verb string) *Response {
	return &Response{
		Verb:    verb,
		Options: make([]string, 0),
	}
}

// WithAction sets the response action (e.g., REPLY, STATUS).
func (r *Response) WithAction(action string) *Response {
	r.Action = action
	return r
}

// WithResult adds the RESULT option with the given result code.
// Common result codes: OK, I2P_ERROR, DUPLICATED_ID, etc.
func (r *Response) WithResult(result string) *Response {
	return r.WithOption("RESULT", result)
}

// WithMessage adds the MESSAGE option, typically used with error responses.
// The message is automatically quoted if it contains spaces.
func (r *Response) WithMessage(msg string) *Response {
	return r.WithOption("MESSAGE", msg)
}

// WithDestination adds the DESTINATION option with a Base64 destination.
func (r *Response) WithDestination(dest string) *Response {
	return r.WithOption("DESTINATION", dest)
}

// WithVersion adds the VERSION option.
func (r *Response) WithVersion(version string) *Response {
	return r.WithOption("VERSION", version)
}

// WithOption adds a key-value option to the response.
// Values containing spaces, quotes, or backslashes are automatically quoted.
func (r *Response) WithOption(key, value string) *Response {
	formatted := formatOption(key, value)
	r.Options = append(r.Options, formatted)
	return r
}

// WithAdditionalLine adds an additional line to be sent after the main response.
// Used for STREAM ACCEPT which sends destination info on a separate line.
// The line should NOT include a trailing newline; it will be added automatically.
func (r *Response) WithAdditionalLine(line string) *Response {
	r.AdditionalLines = append(r.AdditionalLines, line)
	return r
}

// String formats the response as a SAM protocol line with newline terminator.
// Note: This only returns the main response line. Use FullString() to get
// all lines including additional lines.
func (r *Response) String() string {
	var parts []string
	parts = append(parts, r.Verb)
	if r.Action != "" {
		parts = append(parts, r.Action)
	}
	parts = append(parts, r.Options...)
	return strings.Join(parts, " ") + "\n"
}

// FullString returns the complete response including all additional lines.
// Each line is terminated with a newline.
func (r *Response) FullString() string {
	result := r.String()
	for _, line := range r.AdditionalLines {
		result += line + "\n"
	}
	return result
}

// HasAdditionalLines returns true if the response has additional lines to send.
func (r *Response) HasAdditionalLines() bool {
	return len(r.AdditionalLines) > 0
}

// Bytes returns the response as a byte slice for writing to connections.
func (r *Response) Bytes() []byte {
	return []byte(r.String())
}

// formatOption formats a key-value pair, quoting the value if necessary.
func formatOption(key, value string) string {
	if needsQuoting(value) {
		value = `"` + escapeValue(value) + `"`
	}
	return key + "=" + value
}

// needsQuoting returns true if the value contains characters that require quoting.
// Per SAM 3.2, values with spaces, tabs, quotes, or backslashes must be quoted.
func needsQuoting(s string) bool {
	return strings.ContainsAny(s, " \t\"\\")
}

// escapeValue escapes quotes and backslashes in a string.
// Per SAM 3.2, double quotes are escaped with backslash, and
// backslashes are represented as two backslashes.
func escapeValue(s string) string {
	// Order matters: escape backslashes first, then quotes
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

// Helper functions to create common responses

// HelloReplyOK creates a successful HELLO REPLY response with version.
func HelloReplyOK(version string) *Response {
	return NewResponse(VerbHello).
		WithAction(ActionReply).
		WithResult(ResultOK).
		WithVersion(version)
}

// HelloReplyNoVersion creates a HELLO REPLY with NOVERSION result.
func HelloReplyNoVersion() *Response {
	return NewResponse(VerbHello).
		WithAction(ActionReply).
		WithResult(ResultNoVersion)
}

// HelloReplyError creates a HELLO REPLY with I2P_ERROR result and message.
func HelloReplyError(message string) *Response {
	return NewResponse(VerbHello).
		WithAction(ActionReply).
		WithResult(ResultI2PError).
		WithMessage(message)
}

// SessionStatusOK creates a successful SESSION STATUS response.
func SessionStatusOK(destination string) *Response {
	return NewResponse(VerbSession).
		WithAction(ActionStatus).
		WithResult(ResultOK).
		WithDestination(destination)
}

// SessionStatusError creates a SESSION STATUS error response.
func SessionStatusError(result, message string) *Response {
	return NewResponse(VerbSession).
		WithAction(ActionStatus).
		WithResult(result).
		WithMessage(message)
}

// StreamStatusOK creates a successful STREAM STATUS response.
func StreamStatusOK() *Response {
	return NewResponse(VerbStream).
		WithAction(ActionStatus).
		WithResult(ResultOK)
}

// StreamStatusError creates a STREAM STATUS error response.
func StreamStatusError(result, message string) *Response {
	return NewResponse(VerbStream).
		WithAction(ActionStatus).
		WithResult(result).
		WithMessage(message)
}

// DestReply creates a DEST REPLY response with public and private keys.
func DestReply(publicKey, privateKey string) *Response {
	return NewResponse(VerbDest).
		WithAction(ActionReply).
		WithOption("PUB", publicKey).
		WithOption("PRIV", privateKey)
}

// NamingReplyOK creates a successful NAMING REPLY response.
func NamingReplyOK(name, value string) *Response {
	return NewResponse(VerbNaming).
		WithAction(ActionReply).
		WithResult(ResultOK).
		WithOption("NAME", name).
		WithOption("VALUE", value)
}

// NamingReplyNotFound creates a NAMING REPLY KEY_NOT_FOUND response.
func NamingReplyNotFound(name string) *Response {
	return NewResponse(VerbNaming).
		WithAction(ActionReply).
		WithResult(ResultKeyNotFound).
		WithOption("NAME", name)
}

// Pong creates a PONG response with the original ping data.
func Pong(data string) *Response {
	if data == "" {
		return NewResponse(VerbPong)
	}
	// PONG includes arbitrary text directly, not as key=value
	r := NewResponse(VerbPong)
	r.Options = append(r.Options, data)
	return r
}
