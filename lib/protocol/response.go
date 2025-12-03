package protocol

import (
	"fmt"
	"strings"
)

// Response represents a SAM protocol response message.
// All responses follow the format: VERB [ACTION] RESULT=value [KEY=VALUE ...]
type Response struct {
	verb    string
	action  string
	options map[string]string
}

// NewResponse creates a new response with the given verb.
// For simple responses like "HELLO REPLY" or "DEST REPLY", verb should be "HELLO" or "DEST".
func NewResponse(verb string) *Response {
	return &Response{
		verb:    verb,
		options: make(map[string]string),
	}
}

// WithAction sets the action portion of the response (e.g., "REPLY", "STATUS").
func (r *Response) WithAction(action string) *Response {
	r.action = action
	return r
}

// WithResult sets the RESULT field (required for most responses).
func (r *Response) WithResult(result string) *Response {
	r.options["RESULT"] = result
	return r
}

// With adds a key=value pair to the response options.
func (r *Response) With(key, value string) *Response {
	r.options[key] = value
	return r
}

// WithMessage adds a MESSAGE field (typically used with error responses).
// The message will be quoted if it contains spaces or special characters.
func (r *Response) WithMessage(message string) *Response {
	r.options["MESSAGE"] = message
	return r
}

// String formats the response as a SAM protocol message line.
// Format: VERB [ACTION] KEY=VALUE [KEY=VALUE ...]
// Values containing spaces or quotes are automatically quoted and escaped.
func (r *Response) String() string {
	var parts []string

	// Add verb and action
	if r.action != "" {
		parts = append(parts, r.verb, r.action)
	} else {
		parts = append(parts, r.verb)
	}

	// Add options in consistent order: RESULT first, then alphabetically
	if result, ok := r.options["RESULT"]; ok {
		parts = append(parts, formatOption("RESULT", result))
	}

	// Add remaining options in alphabetical order
	for key, value := range r.options {
		if key != "RESULT" {
			parts = append(parts, formatOption(key, value))
		}
	}

	return strings.Join(parts, " ") + "\n"
}

// Bytes returns the response as bytes (UTF-8 encoded per SAM 3.2+).
func (r *Response) Bytes() []byte {
	return []byte(r.String())
}

// formatOption formats a key=value pair, quoting the value if necessary.
// Quotes and backslashes in values are escaped per SAM 3.2+ specification.
func formatOption(key, value string) string {
	// Check if value needs quoting (contains space, quote, equals, or backslash)
	needsQuoting := strings.ContainsAny(value, " \"=\\")

	if needsQuoting {
		// Escape existing backslashes first, then quotes
		escaped := strings.ReplaceAll(value, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
		return fmt.Sprintf("%s=\"%s\"", key, escaped)
	}

	return fmt.Sprintf("%s=%s", key, value)
}

// Helper functions for common response types

// HelloReply creates a HELLO REPLY response.
func HelloReply(result, version string) *Response {
	r := NewResponse("HELLO").WithAction("REPLY").WithResult(result)
	if version != "" {
		r.With("VERSION", version)
	}
	return r
}

// SessionStatus creates a SESSION STATUS response.
func SessionStatus(result string) *Response {
	return NewResponse("SESSION").WithAction("STATUS").WithResult(result)
}

// StreamStatus creates a STREAM STATUS response.
func StreamStatus(result string) *Response {
	return NewResponse("STREAM").WithAction("STATUS").WithResult(result)
}

// DestReply creates a DEST REPLY response.
func DestReply(pubKey, privKey string) *Response {
	return NewResponse("DEST").
		WithAction("REPLY").
		WithResult(ResultOK).
		With("PUB", pubKey).
		With("PRIV", privKey)
}

// NamingReply creates a NAMING REPLY response.
func NamingReply(result, name string) *Response {
	r := NewResponse("NAMING").WithAction("REPLY").WithResult(result)
	if name != "" {
		r.With("NAME", name)
	}
	return r
}

// DatagramReceived creates a DATAGRAM RECEIVED response.
func DatagramReceived(size int) *Response {
	return NewResponse("DATAGRAM").
		WithAction("RECEIVED").
		WithResult(ResultOK).
		With("SIZE", fmt.Sprintf("%d", size))
}

// RawReceived creates a RAW RECEIVED response.
func RawReceived(size int) *Response {
	return NewResponse("RAW").
		WithAction("RECEIVED").
		WithResult(ResultOK).
		With("SIZE", fmt.Sprintf("%d", size))
}

// Pong creates a PONG response.
func Pong() *Response {
	return NewResponse("PONG")
}

// ErrorResponse creates a generic error response with MESSAGE field.
func ErrorResponse(verb, action, result, message string) *Response {
	r := NewResponse(verb)
	if action != "" {
		r.WithAction(action)
	}
	return r.WithResult(result).WithMessage(message)
}
