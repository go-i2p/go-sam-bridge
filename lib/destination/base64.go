// Package destination implements I2P destination management including key generation,
// Base64 encoding/decoding, and offline signature handling.
// See SAMv3.md for destination format details.
package destination

import (
	"github.com/go-i2p/common/base64"
)

// Re-export base64 functions from go-i2p/common/base64 for convenience.
// These functions use the I2P-modified Base64 alphabet where + becomes - and / becomes ~.

// Base64Encode encodes data to I2P Base64 format.
// I2P uses a modified alphabet where + becomes - and / becomes ~.
func Base64Encode(data []byte) string {
	return base64.EncodeToString(data)
}

// Base64Decode decodes I2P Base64 encoded data.
// Returns an error if the input contains invalid characters or has invalid length.
func Base64Decode(s string) ([]byte, error) {
	return base64.DecodeString(s)
}

// Base64EncodeToString is an alias for Base64Encode for API consistency.
func Base64EncodeToString(data []byte) string {
	return base64.EncodeToString(data)
}

// Base64DecodeString is an alias for Base64Decode for API consistency.
func Base64DecodeString(s string) ([]byte, error) {
	return base64.DecodeString(s)
}

// StdToI2PBase64 converts standard Base64 to I2P Base64.
// Replaces + with - and / with ~.
func StdToI2PBase64(s string) string {
	result := make([]byte, len(s))
	for i, c := range s {
		switch c {
		case '+':
			result[i] = '-'
		case '/':
			result[i] = '~'
		default:
			result[i] = byte(c)
		}
	}
	return string(result)
}

// I2PToStdBase64 converts I2P Base64 to standard Base64.
// Replaces - with + and ~ with /.
func I2PToStdBase64(s string) string {
	result := make([]byte, len(s))
	for i, c := range s {
		switch c {
		case '-':
			result[i] = '+'
		case '~':
			result[i] = '/'
		default:
			result[i] = byte(c)
		}
	}
	return string(result)
}
