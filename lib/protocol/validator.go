package protocol

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Empty Value Policy per SAM 3.2:
//
// The SAM specification allows empty option values in three forms:
//   - KEY (no equals sign)
//   - KEY= (equals with no value)
//   - KEY="" (equals with empty quoted string)
//
// This implementation treats all three forms as equivalent empty strings.
// For optional parameters, empty strings use documented defaults.
// For required parameters, empty strings return appropriate errors.
//
// Consistency rules:
//   - Port values: empty → 0 (default port)
//   - Protocol values: empty → 18 (default RAW protocol)
//   - Signature types: empty → 7 (Ed25519, security default)
//   - Boolean values: empty → specified default
//   - Session IDs: empty → error (required field)
//   - Destinations: empty → error (required field)

// Validation errors
var (
	ErrPortOutOfRange       = errors.New("port out of range (0-65535)")
	ErrProtocolOutOfRange   = errors.New("protocol out of range (0-255)")
	ErrProtocolDisallowed   = errors.New("protocol is disallowed for RAW sessions")
	ErrInvalidSessionID     = errors.New("session ID contains invalid characters")
	ErrEmptySessionID       = errors.New("session ID cannot be empty")
	ErrInvalidSignatureType = errors.New("invalid signature type")
	ErrEmptyValue           = errors.New("value cannot be empty")
)

// RequireNonEmpty validates that a value is not empty.
// Returns ErrEmptyValue if the value is empty string.
// Use this for required parameters that don't have defaults.
func RequireNonEmpty(value, fieldName string) error {
	if value == "" {
		return fmt.Errorf("%s: %w", fieldName, ErrEmptyValue)
	}
	return nil
}

// ValidatePort validates an I2CP port number.
// Valid range is 0-65535 per SAMv3.md.
func ValidatePort(port int) error {
	if port < MinPort || port > MaxPort {
		return fmt.Errorf("%w: got %d", ErrPortOutOfRange, port)
	}
	return nil
}

// ValidatePortString validates and parses a port string.
// Returns the parsed port or error.
func ValidatePortString(s string) (int, error) {
	if s == "" {
		return 0, nil // Default port is 0
	}

	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port value %q: %w", s, err)
	}

	if err := ValidatePort(port); err != nil {
		return 0, err
	}

	return port, nil
}

// ValidateProtocol validates an I2CP protocol number for RAW sessions.
// Valid range is 0-255, excluding disallowed protocols (6, 17, 19, 20).
func ValidateProtocol(protocol int) error {
	if protocol < MinProtocol || protocol > MaxProtocol {
		return fmt.Errorf("%w: got %d", ErrProtocolOutOfRange, protocol)
	}

	for _, disallowed := range DisallowedRawProtocols {
		if protocol == disallowed {
			return fmt.Errorf("%w: %d", ErrProtocolDisallowed, protocol)
		}
	}

	return nil
}

// ValidateProtocolString validates and parses a protocol string.
// Returns the parsed protocol or error. Empty string returns default (18).
func ValidateProtocolString(s string) (int, error) {
	if s == "" {
		return DefaultRawProtocol, nil
	}

	protocol, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid protocol value %q: %w", s, err)
	}

	if err := ValidateProtocol(protocol); err != nil {
		return 0, err
	}

	return protocol, nil
}

// ValidateSessionID validates a SAM session ID (nickname).
// Session IDs cannot be empty and cannot contain whitespace.
// Per SAM spec, IDs should be randomly generated to prevent collisions.
func ValidateSessionID(id string) error {
	if id == "" {
		return ErrEmptySessionID
	}

	for _, r := range id {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%w: contains whitespace", ErrInvalidSessionID)
		}
	}

	return nil
}

// ValidateSignatureType validates a signature type number.
// Valid values are 0-8 per I2P specification.
func ValidateSignatureType(sigType int) error {
	if sigType < 0 || sigType > 8 {
		return fmt.Errorf("%w: got %d", ErrInvalidSignatureType, sigType)
	}
	return nil
}

// ValidateSignatureTypeString validates and parses a signature type string.
// Returns the parsed type or error. Empty string returns default (Ed25519/7).
func ValidateSignatureTypeString(s string) (int, error) {
	if s == "" {
		return DefaultSignatureType, nil
	}

	sigType, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid signature type %q: %w", s, err)
	}

	if err := ValidateSignatureType(sigType); err != nil {
		return 0, err
	}

	return sigType, nil
}

// ValidateStyle validates a SAM session style.
// Valid styles: STREAM, DATAGRAM, RAW, DATAGRAM2, DATAGRAM3, PRIMARY, MASTER.
func ValidateStyle(style string) error {
	normalized := strings.ToUpper(style)
	switch normalized {
	case StyleStream, StyleDatagram, StyleRaw, StyleDatagram2, StyleDatagram3, StylePrimary, StyleMaster:
		return nil
	default:
		return fmt.Errorf("unknown session style: %s", style)
	}
}

// NormalizeStyle normalizes a session style to uppercase and converts
// deprecated MASTER to PRIMARY per SAM 3.3.
func NormalizeStyle(style string) string {
	normalized := strings.ToUpper(style)
	if normalized == StyleMaster {
		return StylePrimary
	}
	return normalized
}

// ParseEncryptionTypes parses the i2cp.leaseSetEncType option.
// Format is comma-separated integers (e.g., "4,0").
// Returns the parsed types or default if empty.
func ParseEncryptionTypes(s string) ([]int, error) {
	if s == "" {
		return DefaultEncryptionTypes, nil
	}

	parts := strings.Split(s, ",")
	types := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		t, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption type %q: %w", part, err)
		}

		types = append(types, t)
	}

	if len(types) == 0 {
		return DefaultEncryptionTypes, nil
	}

	return types, nil
}

// ParseTunnelQuantity parses a tunnel quantity option.
// Returns default (3) if empty.
func ParseTunnelQuantity(s string) (int, error) {
	if s == "" {
		return DefaultTunnelQuantity, nil
	}

	qty, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid tunnel quantity %q: %w", s, err)
	}

	if qty < 0 || qty > 16 {
		return 0, fmt.Errorf("tunnel quantity out of range (0-16): %d", qty)
	}

	return qty, nil
}

// ParseBool parses a boolean option value.
// Accepts "true", "false", "1", "0" (case-insensitive).
func ParseBool(s string, defaultVal bool) (bool, error) {
	if s == "" {
		return defaultVal, nil
	}

	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", s)
	}
}
