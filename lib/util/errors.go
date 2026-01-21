// Package util provides common utilities for the SAM bridge implementation.
// This includes custom error types, validation helpers, and logging utilities.
package util

import (
	"errors"
	"fmt"
)

// Sentinel errors for SAM protocol operations.
// These map directly to SAM protocol RESULT codes per SAMv3.md specification.
var (
	// ErrDuplicateID indicates a session ID already exists.
	// Maps to RESULT=DUPLICATED_ID per SAM spec.
	ErrDuplicateID = errors.New("duplicated session ID")

	// ErrDuplicateDest indicates an I2P destination is already in use.
	// Maps to RESULT=DUPLICATED_DEST per SAM spec.
	ErrDuplicateDest = errors.New("duplicated destination")

	// ErrSessionNotFound indicates the requested session does not exist.
	// Maps to RESULT=INVALID_ID per SAM spec.
	ErrSessionNotFound = errors.New("session not found")

	// ErrInvalidKey indicates the destination key is malformed or invalid.
	// Maps to RESULT=INVALID_KEY per SAM spec.
	ErrInvalidKey = errors.New("invalid key")

	// ErrTimeout indicates an operation timed out.
	// Maps to RESULT=TIMEOUT per SAM spec.
	ErrTimeout = errors.New("timeout")

	// ErrCantReachPeer indicates the remote peer is unreachable.
	// Maps to RESULT=CANT_REACH_PEER per SAM spec.
	ErrCantReachPeer = errors.New("can't reach peer")

	// ErrPeerNotFound indicates the remote peer's destination was not found.
	// Maps to RESULT=PEER_NOT_FOUND per SAM spec.
	ErrPeerNotFound = errors.New("peer not found")

	// ErrLeasesetNotFound indicates the leaseset could not be found.
	// Maps to RESULT=LEASESET_NOT_FOUND per SAM spec.
	ErrLeasesetNotFound = errors.New("leaseset not found")

	// ErrKeyNotFound indicates a name lookup failed.
	// Maps to RESULT=KEY_NOT_FOUND per SAM spec.
	ErrKeyNotFound = errors.New("key not found")

	// ErrNoVersion indicates version negotiation failed.
	// Maps to RESULT=NOVERSION per SAM spec.
	ErrNoVersion = errors.New("no compatible version")

	// ErrAuthRequired indicates authentication is required.
	ErrAuthRequired = errors.New("authentication required")

	// ErrAuthFailed indicates authentication failed.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrSessionClosed indicates the session has been closed.
	ErrSessionClosed = errors.New("session closed")

	// ErrNotImplemented indicates a feature is not yet implemented.
	ErrNotImplemented = errors.New("not implemented")

	// ErrSilentClose indicates the connection should be closed silently
	// without sending any response. Used when SILENT=true and an operation fails.
	// Per SAMv3.md: "If SILENT=true is passed, the SAM bridge won't issue any
	// other message on the socket. If the connection fails, the socket will be closed."
	ErrSilentClose = errors.New("silent close requested")
)

// SessionError wraps an error with session context.
// Use this when an error occurs during session operations.
type SessionError struct {
	SessionID string // The session ID where the error occurred
	Operation string // The operation being performed (e.g., "connect", "accept")
	Err       error  // The underlying error
}

// NewSessionError creates a new SessionError with context.
func NewSessionError(sessionID, operation string, err error) *SessionError {
	return &SessionError{
		SessionID: sessionID,
		Operation: operation,
		Err:       err,
	}
}

// Error implements the error interface.
func (e *SessionError) Error() string {
	if e.SessionID == "" {
		return fmt.Sprintf("%s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("session %s: %s: %v", e.SessionID, e.Operation, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *SessionError) Unwrap() error {
	return e.Err
}

// ProtocolError wraps an error with SAM protocol command context.
// Use this when an error occurs during command parsing or handling.
type ProtocolError struct {
	Verb    string // The command verb (e.g., "SESSION", "STREAM")
	Action  string // The command action (e.g., "CREATE", "CONNECT")
	Message string // Human-readable error message
	Err     error  // The underlying error (optional)
}

// NewProtocolError creates a new ProtocolError with context.
func NewProtocolError(verb, action, message string) *ProtocolError {
	return &ProtocolError{
		Verb:    verb,
		Action:  action,
		Message: message,
	}
}

// NewProtocolErrorWithCause creates a new ProtocolError with an underlying cause.
func NewProtocolErrorWithCause(verb, action, message string, err error) *ProtocolError {
	return &ProtocolError{
		Verb:    verb,
		Action:  action,
		Message: message,
		Err:     err,
	}
}

// Error implements the error interface.
func (e *ProtocolError) Error() string {
	cmd := e.Verb
	if e.Action != "" {
		cmd = e.Verb + " " + e.Action
	}

	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", cmd, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", cmd, e.Message)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ProtocolError) Unwrap() error {
	return e.Err
}

// ConnectionError wraps an error with connection context.
// Use this when an error occurs at the connection level.
type ConnectionError struct {
	RemoteAddr string // Remote address of the connection
	Operation  string // The operation being performed
	Err        error  // The underlying error
}

// NewConnectionError creates a new ConnectionError with context.
func NewConnectionError(remoteAddr, operation string, err error) *ConnectionError {
	return &ConnectionError{
		RemoteAddr: remoteAddr,
		Operation:  operation,
		Err:        err,
	}
}

// Error implements the error interface.
func (e *ConnectionError) Error() string {
	if e.RemoteAddr == "" {
		return fmt.Sprintf("%s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %v", e.RemoteAddr, e.Operation, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// SilentCloseError wraps an error that should cause the connection to be
// closed silently without sending any response. This is used when SILENT=true
// is set and an operation fails.
// Per SAMv3.md: "If SILENT=true is passed, the SAM bridge won't issue any
// other message on the socket. If the connection fails, the socket will be closed."
type SilentCloseError struct {
	Operation string // The operation that failed (e.g., "connect", "accept")
	Err       error  // The underlying error
}

// NewSilentCloseError creates a new SilentCloseError.
func NewSilentCloseError(operation string, err error) *SilentCloseError {
	return &SilentCloseError{
		Operation: operation,
		Err:       err,
	}
}

// Error implements the error interface.
func (e *SilentCloseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("silent close (%s): %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("silent close (%s)", e.Operation)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *SilentCloseError) Unwrap() error {
	return e.Err
}

// IsSilentClose returns true if the error indicates the connection should
// be closed without sending a response (SILENT=true behavior).
func IsSilentClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrSilentClose) {
		return true
	}
	var silentErr *SilentCloseError
	return errors.As(err, &silentErr)
}

// IsRetryable returns true if the error represents a condition that may
// succeed if retried (e.g., timeout, temporary network issues).
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// These errors may succeed on retry
	if errors.Is(err, ErrTimeout) {
		return true
	}
	if errors.Is(err, ErrCantReachPeer) {
		return true
	}
	if errors.Is(err, ErrLeasesetNotFound) {
		return true
	}

	return false
}

// IsPermanent returns true if the error represents a permanent failure
// that will not succeed on retry (e.g., invalid key, auth failed).
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}

	// These errors will not succeed on retry
	if errors.Is(err, ErrInvalidKey) {
		return true
	}
	if errors.Is(err, ErrDuplicateID) {
		return true
	}
	if errors.Is(err, ErrDuplicateDest) {
		return true
	}
	if errors.Is(err, ErrAuthFailed) {
		return true
	}
	if errors.Is(err, ErrNoVersion) {
		return true
	}

	return false
}

// ToResultCode converts a sentinel error to a SAM protocol RESULT code.
// Returns "I2P_ERROR" for unknown errors.
func ToResultCode(err error) string {
	if err == nil {
		return "OK"
	}

	switch {
	case errors.Is(err, ErrDuplicateID):
		return "DUPLICATED_ID"
	case errors.Is(err, ErrDuplicateDest):
		return "DUPLICATED_DEST"
	case errors.Is(err, ErrSessionNotFound):
		return "INVALID_ID"
	case errors.Is(err, ErrInvalidKey):
		return "INVALID_KEY"
	case errors.Is(err, ErrTimeout):
		return "TIMEOUT"
	case errors.Is(err, ErrCantReachPeer):
		return "CANT_REACH_PEER"
	case errors.Is(err, ErrPeerNotFound):
		return "PEER_NOT_FOUND"
	case errors.Is(err, ErrLeasesetNotFound):
		return "LEASESET_NOT_FOUND"
	case errors.Is(err, ErrKeyNotFound):
		return "KEY_NOT_FOUND"
	case errors.Is(err, ErrNoVersion):
		return "NOVERSION"
	default:
		return "I2P_ERROR"
	}
}
