// Package destination implements I2P destination management.
package destination

import (
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
)

// Re-export signature type constants from go-i2p/common for convenience.
// All clients should use SigTypeEd25519 (7) for new destinations.
const (
	SigTypeDSA_SHA1          = signature.SIGNATURE_TYPE_DSA_SHA1
	SigTypeECDSA_SHA256_P256 = signature.SIGNATURE_TYPE_ECDSA_SHA256_P256
	SigTypeECDSA_SHA384_P384 = signature.SIGNATURE_TYPE_ECDSA_SHA384_P384
	SigTypeECDSA_SHA512_P521 = signature.SIGNATURE_TYPE_ECDSA_SHA512_P521
	SigTypeRSA_SHA256_2048   = signature.SIGNATURE_TYPE_RSA_SHA256_2048
	SigTypeRSA_SHA384_3072   = signature.SIGNATURE_TYPE_RSA_SHA384_3072
	SigTypeRSA_SHA512_4096   = signature.SIGNATURE_TYPE_RSA_SHA512_4096
	SigTypeEd25519           = signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519
	SigTypeEd25519ph         = signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH
)

// DefaultSignatureType is Ed25519 per SAM specification recommendation.
const DefaultSignatureType = SigTypeEd25519

// Re-export encryption type constants from go-i2p/common for convenience.
const (
	EncTypeElGamal      = key_certificate.KEYCERT_CRYPTO_ELG
	EncTypeECIES_X25519 = key_certificate.KEYCERT_CRYPTO_X25519
)

// DefaultEncryptionTypes specifies ECIES-X25519 with ElGamal fallback.
var DefaultEncryptionTypes = []int{EncTypeECIES_X25519, EncTypeElGamal}

// OfflineSignature represents offline signing capability per SAM 3.3.
// This allows a session to use a transient signing key while keeping
// the long-term identity key offline for security.
type OfflineSignature struct {
	// Expires is the time when the offline signature expires.
	Expires time.Time

	// TransientSignatureType is the signature type of the transient key.
	TransientSignatureType int

	// TransientPublicKey is the transient public signing key.
	TransientPublicKey []byte

	// Signature is the signature from the long-term key over the transient data.
	Signature []byte

	// TransientPrivateKey is the transient private signing key (optional, for signing).
	TransientPrivateKey []byte
}

// IsExpired returns true if the offline signature has expired.
func (o *OfflineSignature) IsExpired() bool {
	if o == nil {
		return true
	}
	return time.Now().After(o.Expires)
}

// IsValid performs basic validation of the offline signature structure.
// Note: This does NOT verify the cryptographic signature.
func (o *OfflineSignature) IsValid() bool {
	if o == nil {
		return false
	}
	if o.IsExpired() {
		return false
	}
	if len(o.TransientPublicKey) == 0 {
		return false
	}
	if len(o.Signature) == 0 {
		return false
	}
	return true
}

// Bytes returns the serialized offline signature for transmission.
func (o *OfflineSignature) Bytes() []byte {
	if o == nil {
		return nil
	}
	// Format: expires (4 bytes) + sig type (2 bytes) + transient pub key + signature
	expires := o.Expires.Unix()
	result := make([]byte, 0, 6+len(o.TransientPublicKey)+len(o.Signature))

	// Expires as 4-byte big-endian Unix timestamp
	result = append(result,
		byte(expires>>24),
		byte(expires>>16),
		byte(expires>>8),
		byte(expires),
	)

	// Signature type as 2-byte big-endian
	result = append(result,
		byte(o.TransientSignatureType>>8),
		byte(o.TransientSignatureType),
	)

	result = append(result, o.TransientPublicKey...)
	result = append(result, o.Signature...)
	return result
}

// SignatureTypeName returns the human-readable name for a signature type.
func SignatureTypeName(sigType int) string {
	switch sigType {
	case SigTypeDSA_SHA1:
		return "DSA-SHA1"
	case SigTypeECDSA_SHA256_P256:
		return "ECDSA-SHA256-P256"
	case SigTypeECDSA_SHA384_P384:
		return "ECDSA-SHA384-P384"
	case SigTypeECDSA_SHA512_P521:
		return "ECDSA-SHA512-P521"
	case SigTypeRSA_SHA256_2048:
		return "RSA-SHA256-2048"
	case SigTypeRSA_SHA384_3072:
		return "RSA-SHA384-3072"
	case SigTypeRSA_SHA512_4096:
		return "RSA-SHA512-4096"
	case SigTypeEd25519:
		return "Ed25519"
	case SigTypeEd25519ph:
		return "Ed25519ph"
	default:
		return "Unknown"
	}
}

// IsValidSignatureType returns true if the signature type is recognized.
func IsValidSignatureType(sigType int) bool {
	return sigType >= SigTypeDSA_SHA1 && sigType <= SigTypeEd25519ph
}

// EncryptionTypeName returns the human-readable name for an encryption type.
func EncryptionTypeName(encType int) string {
	switch encType {
	case EncTypeElGamal:
		return "ElGamal"
	case EncTypeECIES_X25519:
		return "ECIES-X25519"
	default:
		return "Unknown"
	}
}
