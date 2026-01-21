// Package destination implements I2P destination management.
package destination

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/go-i2p/common/key_certificate"
)

// Offline signature parsing errors.
var (
	// ErrNoOfflineSignature indicates no offline signature is present.
	ErrNoOfflineSignature = errors.New("no offline signature present")

	// ErrInvalidOfflineSignature indicates the offline signature data is malformed.
	ErrInvalidOfflineSignature = errors.New("invalid offline signature format")

	// ErrOfflineSignatureExpired indicates the offline signature has expired.
	ErrOfflineSignatureExpired = errors.New("offline signature expired")

	// ErrUnsupportedTransientType indicates the transient signature type is not supported.
	ErrUnsupportedTransientType = errors.New("unsupported transient signature type")

	// ErrOfflineNotAllowed indicates offline signatures are not allowed for this style.
	ErrOfflineNotAllowed = errors.New("offline signatures only allowed for STREAM and RAW sessions")
)

// HasOfflineSignature checks if the signing private key is all zeros,
// which indicates an offline signature section follows per SAMv3.md.
// The signingPrivKeyLen parameter should match the expected length for the signature type.
func HasOfflineSignature(privateKeyData []byte, signingPrivKeyOffset, signingPrivKeyLen int) bool {
	if len(privateKeyData) < signingPrivKeyOffset+signingPrivKeyLen {
		return false
	}
	signingPrivKey := privateKeyData[signingPrivKeyOffset : signingPrivKeyOffset+signingPrivKeyLen]
	return isAllZeros(signingPrivKey)
}

// isAllZeros checks if all bytes in the slice are zero.
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return len(data) > 0
}

// ParsedOfflineSignature contains the parsed offline signature data.
// This struct is used during parsing before creating the session config OfflineSignature.
type ParsedOfflineSignature struct {
	// Expires is when the offline signature expires.
	Expires time.Time

	// TransientSigType is the signature type of the transient key.
	TransientSigType int

	// TransientPublicKey is the transient signing public key.
	TransientPublicKey []byte

	// Signature is the signature from the long-term (offline) key.
	Signature []byte

	// TransientPrivateKey is the transient signing private key.
	TransientPrivateKey []byte
}

// ParseOfflineSignature parses the offline signature section from private key data.
//
// Per SAMv3.md, the offline signature format is:
// - Expires timestamp (4 bytes, big endian, seconds since epoch)
// - Sig type of transient Signing Public Key (2 bytes, big endian)
// - Transient Signing Public key (length per transient sig type)
// - Signature of above three fields by offline key (length per destination sig type)
// - Transient Signing Private key (length per transient sig type)
//
// Parameters:
//   - offlineData: the data after the all-zeros signing private key
//   - destSigType: the signature type of the destination (for offline signature length)
//
// Returns the parsed offline signature or an error.
func ParseOfflineSignature(offlineData []byte, destSigType int) (*ParsedOfflineSignature, error) {
	if len(offlineData) < 6 {
		return nil, ErrInvalidOfflineSignature
	}

	offset := 0

	// 1. Expires timestamp (4 bytes, big endian)
	expiresUnix := binary.BigEndian.Uint32(offlineData[offset : offset+4])
	expires := time.Unix(int64(expiresUnix), 0)
	offset += 4

	// 2. Transient signature type (2 bytes, big endian)
	transientSigType := int(binary.BigEndian.Uint16(offlineData[offset : offset+2]))
	offset += 2

	// 3. Transient public key (length depends on transient sig type)
	transientPubKeyLen, err := getSigningPublicKeyLength(transientSigType)
	if err != nil {
		return nil, ErrUnsupportedTransientType
	}

	if len(offlineData) < offset+transientPubKeyLen {
		return nil, ErrInvalidOfflineSignature
	}
	transientPubKey := make([]byte, transientPubKeyLen)
	copy(transientPubKey, offlineData[offset:offset+transientPubKeyLen])
	offset += transientPubKeyLen

	// 4. Signature by offline key (length depends on destination sig type)
	sigLen, err := getSignatureLength(destSigType)
	if err != nil {
		return nil, ErrInvalidOfflineSignature
	}

	if len(offlineData) < offset+sigLen {
		return nil, ErrInvalidOfflineSignature
	}
	signature := make([]byte, sigLen)
	copy(signature, offlineData[offset:offset+sigLen])
	offset += sigLen

	// 5. Transient private key (length depends on transient sig type)
	transientPrivKeyLen, err := getSigningPrivateKeyLength(transientSigType)
	if err != nil {
		return nil, ErrUnsupportedTransientType
	}

	if len(offlineData) < offset+transientPrivKeyLen {
		return nil, ErrInvalidOfflineSignature
	}
	transientPrivKey := make([]byte, transientPrivKeyLen)
	copy(transientPrivKey, offlineData[offset:offset+transientPrivKeyLen])

	return &ParsedOfflineSignature{
		Expires:             expires,
		TransientSigType:    transientSigType,
		TransientPublicKey:  transientPubKey,
		Signature:           signature,
		TransientPrivateKey: transientPrivKey,
	}, nil
}

// IsExpired returns true if the offline signature has expired.
func (p *ParsedOfflineSignature) IsExpired() bool {
	if p == nil {
		return true
	}
	return time.Now().After(p.Expires)
}

// Bytes serializes the offline signature back to binary format for transmission.
// This is used when echoing back the offline signature in SESSION STATUS response.
func (p *ParsedOfflineSignature) Bytes() []byte {
	if p == nil {
		return nil
	}

	size := 4 + 2 + len(p.TransientPublicKey) + len(p.Signature) + len(p.TransientPrivateKey)
	buf := bytes.NewBuffer(make([]byte, 0, size))

	// Expires as 4-byte big-endian Unix timestamp
	var expires [4]byte
	binary.BigEndian.PutUint32(expires[:], uint32(p.Expires.Unix()))
	buf.Write(expires[:])

	// Transient signature type as 2-byte big-endian
	var sigType [2]byte
	binary.BigEndian.PutUint16(sigType[:], uint16(p.TransientSigType))
	buf.Write(sigType[:])

	// Transient public key
	buf.Write(p.TransientPublicKey)

	// Signature
	buf.Write(p.Signature)

	// Transient private key
	buf.Write(p.TransientPrivateKey)

	return buf.Bytes()
}

// getSigningPublicKeyLength returns the signing public key length for a signature type.
func getSigningPublicKeyLength(sigType int) (int, error) {
	// Use key_certificate package for accurate sizes
	size, err := key_certificate.GetSigningKeySize(sigType)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// getSigningPrivateKeyLength returns the signing private key length for a signature type.
// For Ed25519, the private key is 64 bytes (32-byte seed + 32-byte public key).
func getSigningPrivateKeyLength(sigType int) (int, error) {
	switch sigType {
	case SigTypeDSA_SHA1:
		return 20, nil // DSA private key
	case SigTypeECDSA_SHA256_P256:
		return 32, nil // P-256 private key
	case SigTypeECDSA_SHA384_P384:
		return 48, nil // P-384 private key
	case SigTypeECDSA_SHA512_P521:
		return 66, nil // P-521 private key
	case SigTypeRSA_SHA256_2048:
		return 512, nil // RSA-2048 private key (CRT form)
	case SigTypeRSA_SHA384_3072:
		return 768, nil // RSA-3072 private key (CRT form)
	case SigTypeRSA_SHA512_4096:
		return 1024, nil // RSA-4096 private key (CRT form)
	case SigTypeEd25519, SigTypeEd25519ph:
		return 64, nil // Ed25519: 32-byte seed + 32-byte public key
	default:
		return 0, ErrUnsupportedTransientType
	}
}

// getSignatureLength returns the signature length for a signature type.
func getSignatureLength(sigType int) (int, error) {
	switch sigType {
	case SigTypeDSA_SHA1:
		return 40, nil
	case SigTypeECDSA_SHA256_P256:
		return 64, nil
	case SigTypeECDSA_SHA384_P384:
		return 96, nil
	case SigTypeECDSA_SHA512_P521:
		return 132, nil
	case SigTypeRSA_SHA256_2048:
		return 256, nil
	case SigTypeRSA_SHA384_3072:
		return 384, nil
	case SigTypeRSA_SHA512_4096:
		return 512, nil
	case SigTypeEd25519, SigTypeEd25519ph:
		return 64, nil
	default:
		return 0, errors.New("unsupported signature type")
	}
}
