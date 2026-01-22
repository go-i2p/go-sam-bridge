// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"strconv"

	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// DestHandler handles DEST GENERATE commands per SAM 3.0-3.3.
// Generates new I2P destinations with configurable signature types.
type DestHandler struct {
	manager destination.Manager
}

// NewDestHandler creates a new DEST handler with the given destination manager.
func NewDestHandler(manager destination.Manager) *DestHandler {
	return &DestHandler{manager: manager}
}

// Handle processes a DEST GENERATE command.
// Per SAMv3.md, DEST GENERATE creates a new destination keypair.
// DEST GENERATE cannot be used to create a destination with offline signatures.
//
// Request: DEST GENERATE [SIGNATURE_TYPE=value]
// Response: DEST REPLY PUB=$destination PRIV=$privkey
//
//	DEST REPLY RESULT=I2P_ERROR MESSAGE="..."
func (h *DestHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	// Per SAM spec: DEST GENERATE cannot be used to create a destination with
	// offline signatures. Reject any offline signature-related parameters.
	offlineParams := []string{"OFFLINE_SIGNATURE", "OFFLINE", "TRANSIENT_KEY"}
	for _, param := range offlineParams {
		if cmd.Get(param) != "" {
			return destError("DEST GENERATE cannot create offline-signed destinations"), nil
		}
	}

	// Parse signature type option (default 0 per spec, but 7 is recommended)
	sigType, err := parseSignatureType(cmd)
	if err != nil {
		return destError(err.Error()), nil
	}

	// Validate signature type is supported
	if !destination.IsValidSignatureType(sigType) {
		return destError("unsupported signature type"), nil
	}

	// Generate the destination
	dest, privateKey, err := h.manager.Generate(sigType)
	if err != nil {
		return destError("key generation failed: " + err.Error()), nil
	}

	// Encode public destination
	pubBase64, err := h.manager.EncodePublic(dest)
	if err != nil {
		return destError("encoding failed: " + err.Error()), nil
	}

	// Encode private key (includes destination + private keys)
	privBase64, err := h.manager.Encode(dest, privateKey)
	if err != nil {
		return destError("encoding failed: " + err.Error()), nil
	}

	return destReply(pubBase64, privBase64), nil
}

// parseSignatureType extracts and validates the SIGNATURE_TYPE option.
// Returns default Ed25519 (7) if not specified.
//
// NOTE: SAM spec defaults to DSA_SHA1 (0), but go-sam-bridge intentionally
// deviates from spec to use modern cryptography. DSA_SHA1 is deprecated and
// insecure. All clients are strongly recommended to use Ed25519 anyway.
// This is a security-conscious deviation from the specification.
func parseSignatureType(cmd *protocol.Command) (int, error) {
	sigTypeStr := cmd.Get("SIGNATURE_TYPE")
	if sigTypeStr == "" {
		// go-sam-bridge defaults to Ed25519 for security
		// This deviates from SAM spec (which defaults to deprecated DSA_SHA1)
		return protocol.SigTypeEd25519, nil
	}

	// Try numeric value first
	sigType, err := strconv.Atoi(sigTypeStr)
	if err == nil {
		return sigType, nil
	}

	// Try named signature types (case-insensitive per SAM spec)
	sigType, ok := parseSignatureTypeName(sigTypeStr)
	if !ok {
		return 0, &destError_{"invalid SIGNATURE_TYPE: " + sigTypeStr}
	}

	return sigType, nil
}

// parseSignatureTypeName converts a signature type name to its numeric value.
// Names are case-insensitive per SAM specification.
func parseSignatureTypeName(name string) (int, bool) {
	// Map of signature type names to values
	names := map[string]int{
		"DSA_SHA1":             protocol.SigTypeDSA_SHA1,
		"ECDSA_SHA256_P256":    protocol.SigTypeECDSA_SHA256_P256,
		"ECDSA_SHA384_P384":    protocol.SigTypeECDSA_SHA384_P384,
		"ECDSA_SHA512_P521":    protocol.SigTypeECDSA_SHA512_P521,
		"RSA_SHA256_2048":      protocol.SigTypeRSA_SHA256_2048,
		"RSA_SHA384_3072":      protocol.SigTypeRSA_SHA384_3072,
		"RSA_SHA512_4096":      protocol.SigTypeRSA_SHA512_4096,
		"ED25519":              protocol.SigTypeEd25519,
		"EDDSA_SHA512_ED25519": protocol.SigTypeEd25519, // Alias
		"ED25519PH":            protocol.SigTypeEd25519ph,
	}

	// Case-insensitive lookup
	for n, v := range names {
		if equalFold(n, name) {
			return v, true
		}
	}

	return 0, false
}

// equalFold is a simple case-insensitive string comparison.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if toLower(a[i]) != toLower(b[i]) {
			return false
		}
	}
	return true
}

// toLower converts an ASCII character to lowercase.
func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// destReply returns a successful DEST REPLY response.
func destReply(pub, priv string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbDest).
		WithAction(protocol.ActionReply).
		WithOption("PUB", pub).
		WithOption("PRIV", priv)
}

// destError returns an I2P_ERROR response with a message.
func destError(msg string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbDest).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultI2PError).
		WithMessage(msg)
}

// destError_ is an error type for DEST handler errors.
type destError_ struct {
	msg string
}

func (e *destError_) Error() string {
	return e.msg
}
