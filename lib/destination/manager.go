// Package destination implements I2P destination management.
package destination

import (
	"errors"
	"sync"

	commondest "github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/go-i2p/lib/keys"

	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// Manager handles I2P destination creation, parsing, and encoding.
// This is the main interface for working with I2P destinations in the SAM bridge.
type Manager interface {
	// Generate creates a new destination with the specified signature type.
	// Implements SAM DEST GENERATE command.
	// signatureType: 7=Ed25519 (recommended), 0=DSA_SHA1 (deprecated)
	Generate(signatureType int) (*commondest.Destination, []byte, error)

	// Parse decodes a Base64 private key string into destination and private key.
	// Validates format per PrivateKeyFile specification.
	Parse(privkeyBase64 string) (*commondest.Destination, []byte, error)

	// ParseWithOffline decodes a Base64 private key string and also detects/parses
	// offline signatures per SAM 3.3 specification.
	ParseWithOffline(privkeyBase64 string) (*ParseResult, error)

	// ParsePublic decodes a Base64 public destination string.
	ParsePublic(destBase64 string) (*commondest.Destination, error)

	// Encode converts destination and private key to Base64 private key format.
	Encode(dest *commondest.Destination, privateKey []byte) (string, error)

	// EncodePublic converts a Destination to Base64 public format.
	EncodePublic(d *commondest.Destination) (string, error)
}

// ManagerImpl is the concrete implementation of Manager.
// It uses go-i2p/keys for key generation and go-i2p/common for data structures.
type ManagerImpl struct {
	mu sync.RWMutex

	// cache stores parsed destinations for performance.
	cache map[string]*commondest.Destination
}

// NewManager creates a new destination manager.
func NewManager() *ManagerImpl {
	return &ManagerImpl{
		cache: make(map[string]*commondest.Destination),
	}
}

// ParseResult contains the result of parsing a private key, including
// offline signature data if present.
type ParseResult struct {
	// Destination is the parsed I2P destination.
	Destination *commondest.Destination
	// PrivateKey contains the private key bytes.
	PrivateKey []byte
	// SignatureType is the destination's signature type.
	SignatureType int
	// OfflineSignature contains the parsed offline signature, if present.
	// Nil if the destination does not use offline signatures.
	OfflineSignature *ParsedOfflineSignature
}

// Manager errors.
var (
	// ErrUnsupportedSignatureType indicates the signature type is not supported.
	ErrUnsupportedSignatureType = errors.New("unsupported signature type")

	// ErrInvalidDestination indicates the destination data is invalid.
	ErrInvalidDestination = errors.New("invalid destination")

	// ErrInvalidPrivateKey indicates the private key data is invalid.
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrKeyGenerationFailed indicates key generation failed.
	ErrKeyGenerationFailed = errors.New("key generation failed")
)

// Generate creates a new destination with the specified signature type.
// Uses go-i2p/keys.DestinationKeyStore for proper Ed25519/X25519 key generation.
func (m *ManagerImpl) Generate(signatureType int) (*commondest.Destination, []byte, error) {
	if !IsValidSignatureType(signatureType) {
		return nil, nil, ErrUnsupportedSignatureType
	}

	// Currently only Ed25519 is supported via go-i2p/keys
	if signatureType != SigTypeEd25519 {
		return nil, nil, ErrUnsupportedSignatureType
	}

	// Use go-i2p/keys for proper key generation
	keyStore, err := keys.NewDestinationKeyStore()
	if err != nil {
		return nil, nil, util.NewSessionError("", "generate destination", err)
	}

	dest := keyStore.Destination()

	// Get private keys for SAM protocol
	// EncryptionPrivateKey returns types.PrivateEncryptionKey which has Bytes()
	// SigningPrivateKey returns types.SigningPrivateKey which has Len() but not Bytes()
	// We need to get the raw bytes from the signing key via the signer
	encPrivKey := keyStore.EncryptionPrivateKey()

	// For the signing private key, we need to create a signer and extract bytes
	// The Ed25519PrivateKey type has a Bytes() method, but the interface doesn't expose it
	// We'll store just the encryption private key for now, as signing is done internally
	encPrivKeyBytes := encPrivKey.Bytes()

	// The signing private key bytes are embedded in the Ed25519 key (64 bytes)
	// For now, we just return the encryption private key
	// TODO: Add proper signing key serialization when needed
	return dest, encPrivKeyBytes, nil
}

// Parse decodes a Base64 private key string into destination and private key bytes.
func (m *ManagerImpl) Parse(privkeyBase64 string) (*commondest.Destination, []byte, error) {
	if privkeyBase64 == "" {
		return nil, nil, ErrInvalidPrivateKey
	}

	data, err := Base64Decode(privkeyBase64)
	if err != nil {
		return nil, nil, util.NewSessionError("", "parse private key", err)
	}

	// Minimum destination size
	if len(data) < keys_and_cert.KEYS_AND_CERT_MIN_SIZE {
		return nil, nil, ErrInvalidPrivateKey
	}

	// Parse the destination using go-i2p/common
	dest, remainder, err := commondest.ReadDestination(data)
	if err != nil {
		return nil, nil, util.NewSessionError("", "parse destination", err)
	}

	// Remaining bytes are the private keys
	return &dest, remainder, nil
}

// ParseWithOffline decodes a Base64 private key string and also detects/parses
// offline signatures per SAM 3.3 specification.
//
// The private key format is:
//   - Destination (public key, signing public key, certificate)
//   - Private encryption key (256 bytes for ElGamal, 32 for X25519)
//   - Signing private key (length per sig type, all zeros if offline)
//   - Offline signature section (if signing key is all zeros)
//
// Per SAMv3.md, if the signing private key is all zeros, an offline signature
// section follows with: expires (4B) + transient sig type (2B) + transient pub key
// + signature + transient priv key.
func (m *ManagerImpl) ParseWithOffline(privkeyBase64 string) (*ParseResult, error) {
	if privkeyBase64 == "" {
		return nil, ErrInvalidPrivateKey
	}

	data, err := Base64Decode(privkeyBase64)
	if err != nil {
		return nil, util.NewSessionError("", "parse private key", err)
	}

	// Minimum destination size
	if len(data) < keys_and_cert.KEYS_AND_CERT_MIN_SIZE {
		return nil, ErrInvalidPrivateKey
	}

	// Parse the destination using go-i2p/common
	dest, remainder, err := commondest.ReadDestination(data)
	if err != nil {
		return nil, util.NewSessionError("", "parse destination", err)
	}

	// Get signature type from the destination's key certificate
	sigType := SigTypeEd25519 // Default
	if dest.KeysAndCert != nil && dest.KeysAndCert.KeyCertificate != nil {
		sigType = dest.KeysAndCert.KeyCertificate.SigningPublicKeyType()
	}

	result := &ParseResult{
		Destination:   &dest,
		PrivateKey:    remainder,
		SignatureType: sigType,
	}

	// Calculate expected key sizes to detect offline signature
	// Encryption private key size (256 for ElGamal, 32 for X25519)
	encPrivKeySize := 256 // ElGamal default
	if dest.KeysAndCert != nil && dest.KeysAndCert.KeyCertificate != nil {
		cryptoType := dest.KeysAndCert.KeyCertificate.PublicKeyType()
		if cryptoType == EncTypeECIES_X25519 {
			encPrivKeySize = 32
		}
	}

	// Signing private key size
	sigPrivKeySize, err := getSigningPrivateKeyLength(sigType)
	if err != nil {
		// Unknown signature type, return without offline signature check
		return result, nil
	}

	signingKeyOffset := encPrivKeySize
	minPrivKeySize := encPrivKeySize + sigPrivKeySize

	// Check if we have enough data to examine signing private key
	if len(remainder) < minPrivKeySize {
		return result, nil
	}

	// Check if signing private key is all zeros (indicates offline signature)
	if HasOfflineSignature(remainder, signingKeyOffset, sigPrivKeySize) {
		// Parse offline signature from data after signing private key
		offlineOffset := signingKeyOffset + sigPrivKeySize
		if len(remainder) > offlineOffset {
			offlineSig, offlineErr := ParseOfflineSignature(remainder[offlineOffset:], sigType)
			if offlineErr == nil {
				result.OfflineSignature = offlineSig
			}
			// If parsing fails, we still return the result without offline signature
		}
	}

	return result, nil
}

// ParsePublic decodes a Base64 public destination string.
func (m *ManagerImpl) ParsePublic(destBase64 string) (*commondest.Destination, error) {
	if destBase64 == "" {
		return nil, ErrInvalidDestination
	}

	// Check cache first
	m.mu.RLock()
	if cached, ok := m.cache[destBase64]; ok {
		m.mu.RUnlock()
		return cached, nil
	}
	m.mu.RUnlock()

	data, err := Base64Decode(destBase64)
	if err != nil {
		return nil, util.NewSessionError("", "parse destination", err)
	}

	dest, _, err := commondest.ReadDestination(data)
	if err != nil {
		return nil, util.NewSessionError("", "parse destination", err)
	}

	// Cache the parsed destination
	m.mu.Lock()
	m.cache[destBase64] = &dest
	m.mu.Unlock()

	return &dest, nil
}

// Encode converts destination and private key to Base64 private key format.
func (m *ManagerImpl) Encode(dest *commondest.Destination, privateKey []byte) (string, error) {
	if dest == nil {
		return "", ErrInvalidDestination
	}

	destBytes, err := dest.Bytes()
	if err != nil {
		return "", util.NewSessionError("", "encode destination", err)
	}

	// Combine destination bytes with private key
	fullData := make([]byte, 0, len(destBytes)+len(privateKey))
	fullData = append(fullData, destBytes...)
	fullData = append(fullData, privateKey...)

	return Base64Encode(fullData), nil
}

// EncodePublic converts a Destination to Base64 public format.
func (m *ManagerImpl) EncodePublic(d *commondest.Destination) (string, error) {
	if d == nil {
		return "", ErrInvalidDestination
	}
	return d.Base64()
}

// ClearCache clears the destination cache.
func (m *ManagerImpl) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]*commondest.Destination)
}

// CacheSize returns the number of cached destinations.
func (m *ManagerImpl) CacheSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

// Verify Manager interface compliance
var _ Manager = (*ManagerImpl)(nil)
