// Package destination implements I2P destination management.
package destination

import (
	"errors"
	"fmt"

	commondest "github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/go-i2p/lib/keys"
	lru "github.com/hashicorp/golang-lru/v2"

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

// DefaultCacheSize is the default maximum number of destinations to cache.
// This prevents unbounded memory growth in long-running servers.
const DefaultCacheSize = 1000

// ManagerImpl is the concrete implementation of Manager.
// It uses go-i2p/keys for key generation and go-i2p/common for data structures.
// The destination cache is bounded using an LRU eviction policy to prevent
// unbounded memory growth in long-running servers.
type ManagerImpl struct {
	// cache stores parsed destinations with LRU eviction policy.
	// Maximum size is set at construction time via NewManagerWithCacheSize.
	// The LRU cache is internally thread-safe, so no external mutex is needed.
	cache *lru.Cache[string, *commondest.Destination]

	// cacheCapacity stores the maximum cache size set at construction.
	cacheCapacity int
}

// NewManager creates a new destination manager with default cache size.
// Uses DefaultCacheSize (1000) for the LRU cache.
func NewManager() *ManagerImpl {
	return NewManagerWithCacheSize(DefaultCacheSize)
}

// NewManagerWithCacheSize creates a new destination manager with a custom cache size.
// The cache uses LRU eviction when the size limit is reached.
// cacheSize must be > 0; if 0 or negative, DefaultCacheSize is used.
func NewManagerWithCacheSize(cacheSize int) *ManagerImpl {
	if cacheSize <= 0 {
		cacheSize = DefaultCacheSize
	}
	// LRU cache creation should not fail with valid size
	cache, _ := lru.New[string, *commondest.Destination](cacheSize)
	return &ManagerImpl{
		cache:         cache,
		cacheCapacity: cacheSize,
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
//
// Returns the destination and complete private key bytes in SAM PrivateKeyFile format:
//   - Encryption private key (32 bytes for X25519)
//   - Signing private key (64 bytes for Ed25519)
//
// Per SAMv3.md DEST GENERATE specification.
func (m *ManagerImpl) Generate(signatureType int) (*commondest.Destination, []byte, error) {
	if !IsValidSignatureType(signatureType) {
		return nil, nil, ErrUnsupportedSignatureType
	}

	// Currently only Ed25519 is supported via go-i2p/keys
	if signatureType != SigTypeEd25519 {
		return nil, nil, fmt.Errorf("%w: only Ed25519 (type 7) is currently supported, got type %d", ErrUnsupportedSignatureType, signatureType)
	}

	// Use go-i2p/keys for proper key generation
	keyStore, err := keys.NewDestinationKeyStore()
	if err != nil {
		return nil, nil, util.NewSessionError("", "generate destination", err)
	}

	dest := keyStore.Destination()

	// Get private keys for SAM protocol
	// PrivateKeyFile format: encryption_private_key || signing_private_key
	encPrivKey := keyStore.EncryptionPrivateKey()
	encPrivKeyBytes := encPrivKey.Bytes() // 32 bytes for X25519

	// Get signing private key bytes
	// The SigningPrivateKey interface doesn't expose Bytes(), but the concrete
	// Ed25519PrivateKey type implements types.PrivateKey which has Bytes()
	sigPrivKey := keyStore.SigningPrivateKey()

	// Type assert to get bytes - Ed25519PrivateKey implements PrivateKey.Bytes()
	type bytesProvider interface {
		Bytes() []byte
	}
	sigKeyWithBytes, ok := sigPrivKey.(bytesProvider)
	if !ok {
		return nil, nil, errors.New("signing private key does not provide Bytes() method")
	}
	sigPrivKeyBytes := sigKeyWithBytes.Bytes() // 64 bytes for Ed25519

	// Combine: encryption_private_key || signing_private_key
	// This is the SAM PrivateKeyFile format per SAMv3.md
	privateKeyBytes := make([]byte, 0, len(encPrivKeyBytes)+len(sigPrivKeyBytes))
	privateKeyBytes = append(privateKeyBytes, encPrivKeyBytes...)
	privateKeyBytes = append(privateKeyBytes, sigPrivKeyBytes...)

	return dest, privateKeyBytes, nil
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
	// Decode and parse destination
	dest, remainder, err := m.decodeAndParseDestination(privkeyBase64)
	if err != nil {
		return nil, err
	}

	// Extract signature type and build initial result
	result := m.buildParseResult(dest, remainder)

	// Check for and parse offline signature if present
	m.detectAndParseOfflineSignature(dest, remainder, result)

	return result, nil
}

// decodeAndParseDestination decodes base64 and parses the destination.
func (m *ManagerImpl) decodeAndParseDestination(privkeyBase64 string) (commondest.Destination, []byte, error) {
	if privkeyBase64 == "" {
		return commondest.Destination{}, nil, ErrInvalidPrivateKey
	}

	data, err := Base64Decode(privkeyBase64)
	if err != nil {
		return commondest.Destination{}, nil, util.NewSessionError("", "parse private key", err)
	}

	if len(data) < keys_and_cert.KEYS_AND_CERT_MIN_SIZE {
		return commondest.Destination{}, nil, ErrInvalidPrivateKey
	}

	dest, remainder, err := commondest.ReadDestination(data)
	if err != nil {
		return commondest.Destination{}, nil, util.NewSessionError("", "parse destination", err)
	}
	return dest, remainder, nil
}

// buildParseResult creates the initial ParseResult with signature type.
func (m *ManagerImpl) buildParseResult(dest commondest.Destination, remainder []byte) *ParseResult {
	sigType := SigTypeEd25519 // Default
	if dest.KeysAndCert != nil && dest.KeysAndCert.KeyCertificate != nil {
		sigType = dest.KeysAndCert.KeyCertificate.SigningPublicKeyType()
	}

	return &ParseResult{
		Destination:   &dest,
		PrivateKey:    remainder,
		SignatureType: sigType,
	}
}

// detectAndParseOfflineSignature checks for and parses offline signature if present.
func (m *ManagerImpl) detectAndParseOfflineSignature(dest commondest.Destination, remainder []byte, result *ParseResult) {
	// Calculate encryption private key size (256 for ElGamal, 32 for X25519)
	encPrivKeySize := m.getEncryptionKeySize(dest)

	// Get signing private key size
	sigPrivKeySize, err := getSigningPrivateKeyLength(result.SignatureType)
	if err != nil {
		return // Unknown signature type, skip offline check
	}

	signingKeyOffset := encPrivKeySize
	minPrivKeySize := encPrivKeySize + sigPrivKeySize

	// Check if we have enough data to examine signing private key
	if len(remainder) < minPrivKeySize {
		return
	}

	// Check if signing private key is all zeros (indicates offline signature)
	if HasOfflineSignature(remainder, signingKeyOffset, sigPrivKeySize) {
		offlineOffset := signingKeyOffset + sigPrivKeySize
		if len(remainder) > offlineOffset {
			offlineSig, offlineErr := ParseOfflineSignature(remainder[offlineOffset:], result.SignatureType)
			if offlineErr == nil {
				result.OfflineSignature = offlineSig
			}
		}
	}
}

// getEncryptionKeySize returns the encryption private key size for the destination.
func (m *ManagerImpl) getEncryptionKeySize(dest commondest.Destination) int {
	encPrivKeySize := 256 // ElGamal default
	if dest.KeysAndCert != nil && dest.KeysAndCert.KeyCertificate != nil {
		cryptoType := dest.KeysAndCert.KeyCertificate.PublicKeyType()
		if cryptoType == EncTypeECIES_X25519 {
			encPrivKeySize = 32
		}
	}
	return encPrivKeySize
}

// ParsePublic decodes a Base64 public destination string.
// Results are cached using an LRU eviction policy to prevent unbounded growth.
func (m *ManagerImpl) ParsePublic(destBase64 string) (*commondest.Destination, error) {
	if destBase64 == "" {
		return nil, ErrInvalidDestination
	}

	// Check cache first (LRU cache is thread-safe)
	if cached, ok := m.cache.Get(destBase64); ok {
		return cached, nil
	}

	data, err := Base64Decode(destBase64)
	if err != nil {
		return nil, util.NewSessionError("", "parse destination", err)
	}

	dest, _, err := commondest.ReadDestination(data)
	if err != nil {
		return nil, util.NewSessionError("", "parse destination", err)
	}

	// Cache the parsed destination (LRU will evict oldest if at capacity)
	m.cache.Add(destBase64, &dest)

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
// This is useful for testing or when memory pressure is detected.
func (m *ManagerImpl) ClearCache() {
	m.cache.Purge()
}

// CacheSize returns the number of cached destinations.
func (m *ManagerImpl) CacheSize() int {
	return m.cache.Len()
}

// CacheCapacity returns the maximum cache size.
// This is the limit set at construction time.
func (m *ManagerImpl) CacheCapacity() int {
	return m.cacheCapacity
}

// Verify Manager interface compliance
var _ Manager = (*ManagerImpl)(nil)
