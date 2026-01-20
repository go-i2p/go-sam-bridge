// Package session implements SAM v3.0-3.3 session management.
package session

import (
	"errors"
)

// Session configuration validation errors.
var (
	// ErrInvalidPort indicates a port number is out of valid range (0-65535).
	ErrInvalidPort = errors.New("invalid port: must be 0-65535")

	// ErrInvalidProtocol indicates a protocol number is invalid.
	// For RAW sessions, protocols 6, 17, 19, 20 are disallowed.
	ErrInvalidProtocol = errors.New("invalid protocol: disallowed or out of range")

	// ErrInvalidTunnelConfig indicates tunnel configuration is invalid.
	ErrInvalidTunnelConfig = errors.New("invalid tunnel configuration")

	// ErrForwardActive indicates FORWARD is already active on the session.
	ErrForwardActive = errors.New("forward already active")

	// ErrAcceptActive indicates ACCEPT is already active on the session.
	ErrAcceptActive = errors.New("accept already active")

	// ErrSubsessionNotFound indicates a subsession was not found.
	ErrSubsessionNotFound = errors.New("subsession not found")

	// ErrNotPrimarySession indicates the operation requires a PRIMARY session.
	ErrNotPrimarySession = errors.New("operation requires PRIMARY session")

	// ErrSessionNotActive indicates the session is not in active state.
	ErrSessionNotActive = errors.New("session not active")
)
