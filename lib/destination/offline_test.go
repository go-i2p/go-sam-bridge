// Package destination implements I2P destination management.
package destination

import (
	"testing"
	"time"
)

func TestHasOfflineSignature(t *testing.T) {
	tests := []struct {
		name           string
		privateKeyData []byte
		offset         int
		length         int
		expected       bool
	}{
		{
			name:           "all zeros signing key",
			privateKeyData: make([]byte, 64),
			offset:         0,
			length:         32,
			expected:       true,
		},
		{
			name:           "non-zero signing key",
			privateKeyData: []byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			offset:         0,
			length:         32,
			expected:       false,
		},
		{
			name:           "all zeros with offset",
			privateKeyData: []byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0},
			offset:         4,
			length:         8,
			expected:       true,
		},
		{
			name:           "data too short",
			privateKeyData: []byte{0, 0, 0, 0},
			offset:         0,
			length:         8,
			expected:       false,
		},
		{
			name:           "empty data",
			privateKeyData: []byte{},
			offset:         0,
			length:         32,
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasOfflineSignature(tt.privateKeyData, tt.offset, tt.length)
			if result != tt.expected {
				t.Errorf("HasOfflineSignature() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsAllZeros(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "all zeros",
			data:     []byte{0, 0, 0, 0},
			expected: true,
		},
		{
			name:     "has non-zero",
			data:     []byte{0, 0, 1, 0},
			expected: false,
		},
		{
			name:     "empty slice",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "single zero",
			data:     []byte{0},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAllZeros(tt.data)
			if result != tt.expected {
				t.Errorf("isAllZeros() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseOfflineSignature(t *testing.T) {
	// Build a valid offline signature for Ed25519 destination and Ed25519 transient
	// Format: expires (4) + transient sig type (2) + transient pub key (32) + signature (64) + transient priv key (64)
	futureTime := time.Now().Add(24 * time.Hour).Unix()
	validData := make([]byte, 4+2+32+64+64)

	// Expires (big-endian)
	validData[0] = byte(futureTime >> 24)
	validData[1] = byte(futureTime >> 16)
	validData[2] = byte(futureTime >> 8)
	validData[3] = byte(futureTime)

	// Transient sig type = Ed25519 (7)
	validData[4] = 0
	validData[5] = 7

	// Fill transient pub key with test data
	for i := 0; i < 32; i++ {
		validData[6+i] = byte(i)
	}

	// Fill signature with test data
	for i := 0; i < 64; i++ {
		validData[6+32+i] = byte(i + 100)
	}

	// Fill transient private key with test data
	for i := 0; i < 64; i++ {
		validData[6+32+64+i] = byte(i + 200)
	}

	t.Run("valid Ed25519 offline signature", func(t *testing.T) {
		parsed, err := ParseOfflineSignature(validData, SigTypeEd25519)
		if err != nil {
			t.Fatalf("ParseOfflineSignature() error = %v", err)
		}

		if parsed.TransientSigType != SigTypeEd25519 {
			t.Errorf("TransientSigType = %d, want %d", parsed.TransientSigType, SigTypeEd25519)
		}

		if len(parsed.TransientPublicKey) != 32 {
			t.Errorf("TransientPublicKey length = %d, want 32", len(parsed.TransientPublicKey))
		}

		if len(parsed.Signature) != 64 {
			t.Errorf("Signature length = %d, want 64", len(parsed.Signature))
		}

		if len(parsed.TransientPrivateKey) != 64 {
			t.Errorf("TransientPrivateKey length = %d, want 64", len(parsed.TransientPrivateKey))
		}

		if parsed.IsExpired() {
			t.Error("expected signature to not be expired")
		}
	})

	t.Run("data too short for header", func(t *testing.T) {
		_, err := ParseOfflineSignature([]byte{0, 0, 0}, SigTypeEd25519)
		if err != ErrInvalidOfflineSignature {
			t.Errorf("expected ErrInvalidOfflineSignature, got %v", err)
		}
	})

	t.Run("unsupported transient signature type", func(t *testing.T) {
		badData := make([]byte, 100)
		badData[4] = 0
		badData[5] = 255 // Invalid sig type
		_, err := ParseOfflineSignature(badData, SigTypeEd25519)
		if err != ErrUnsupportedTransientType {
			t.Errorf("expected ErrUnsupportedTransientType, got %v", err)
		}
	})

	t.Run("data too short for transient public key", func(t *testing.T) {
		shortData := make([]byte, 8) // Only header
		shortData[5] = 7             // Ed25519
		_, err := ParseOfflineSignature(shortData, SigTypeEd25519)
		if err != ErrInvalidOfflineSignature {
			t.Errorf("expected ErrInvalidOfflineSignature, got %v", err)
		}
	})

	t.Run("data too short for signature", func(t *testing.T) {
		shortData := make([]byte, 6+32) // Header + transient pub key
		shortData[5] = 7                // Ed25519
		_, err := ParseOfflineSignature(shortData, SigTypeEd25519)
		if err != ErrInvalidOfflineSignature {
			t.Errorf("expected ErrInvalidOfflineSignature, got %v", err)
		}
	})

	t.Run("data too short for transient private key", func(t *testing.T) {
		shortData := make([]byte, 6+32+64) // Header + transient pub key + signature
		shortData[5] = 7                   // Ed25519
		_, err := ParseOfflineSignature(shortData, SigTypeEd25519)
		if err != ErrInvalidOfflineSignature {
			t.Errorf("expected ErrInvalidOfflineSignature, got %v", err)
		}
	})
}

func TestParsedOfflineSignature_IsExpired(t *testing.T) {
	t.Run("nil signature is expired", func(t *testing.T) {
		var p *ParsedOfflineSignature
		if !p.IsExpired() {
			t.Error("nil signature should be expired")
		}
	})

	t.Run("past expiration is expired", func(t *testing.T) {
		p := &ParsedOfflineSignature{
			Expires: time.Now().Add(-1 * time.Hour),
		}
		if !p.IsExpired() {
			t.Error("past signature should be expired")
		}
	})

	t.Run("future expiration is not expired", func(t *testing.T) {
		p := &ParsedOfflineSignature{
			Expires: time.Now().Add(1 * time.Hour),
		}
		if p.IsExpired() {
			t.Error("future signature should not be expired")
		}
	})
}

func TestParsedOfflineSignature_Bytes(t *testing.T) {
	t.Run("nil signature returns nil", func(t *testing.T) {
		var p *ParsedOfflineSignature
		if p.Bytes() != nil {
			t.Error("nil signature should return nil bytes")
		}
	})

	t.Run("round-trip serialization", func(t *testing.T) {
		expires := time.Unix(1700000000, 0)
		original := &ParsedOfflineSignature{
			Expires:             expires,
			TransientSigType:    SigTypeEd25519,
			TransientPublicKey:  make([]byte, 32),
			Signature:           make([]byte, 64),
			TransientPrivateKey: make([]byte, 64),
		}

		// Fill with test data
		for i := 0; i < 32; i++ {
			original.TransientPublicKey[i] = byte(i)
		}
		for i := 0; i < 64; i++ {
			original.Signature[i] = byte(i + 50)
			original.TransientPrivateKey[i] = byte(i + 150)
		}

		data := original.Bytes()
		parsed, err := ParseOfflineSignature(data, SigTypeEd25519)
		if err != nil {
			t.Fatalf("failed to parse serialized data: %v", err)
		}

		if parsed.Expires.Unix() != original.Expires.Unix() {
			t.Errorf("Expires mismatch: got %v, want %v", parsed.Expires, original.Expires)
		}

		if parsed.TransientSigType != original.TransientSigType {
			t.Errorf("TransientSigType mismatch: got %d, want %d", parsed.TransientSigType, original.TransientSigType)
		}

		for i := 0; i < 32; i++ {
			if parsed.TransientPublicKey[i] != original.TransientPublicKey[i] {
				t.Errorf("TransientPublicKey[%d] mismatch", i)
			}
		}

		for i := 0; i < 64; i++ {
			if parsed.Signature[i] != original.Signature[i] {
				t.Errorf("Signature[%d] mismatch", i)
			}
		}

		for i := 0; i < 64; i++ {
			if parsed.TransientPrivateKey[i] != original.TransientPrivateKey[i] {
				t.Errorf("TransientPrivateKey[%d] mismatch", i)
			}
		}
	})
}

func TestGetSigningPublicKeyLength(t *testing.T) {
	tests := []struct {
		sigType      int
		expectedSize int
		expectError  bool
	}{
		{SigTypeDSA_SHA1, 128, false},
		{SigTypeECDSA_SHA256_P256, 64, false},
		{SigTypeECDSA_SHA384_P384, 96, false},
		{SigTypeECDSA_SHA512_P521, 132, false},
		{SigTypeEd25519, 32, false},
		{SigTypeEd25519ph, 32, false},
		{255, 0, true}, // Invalid type
	}

	for _, tt := range tests {
		t.Run(SignatureTypeName(tt.sigType), func(t *testing.T) {
			size, err := getSigningPublicKeyLength(tt.sigType)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for sig type %d", tt.sigType)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if size != tt.expectedSize {
					t.Errorf("size = %d, want %d", size, tt.expectedSize)
				}
			}
		})
	}
}

func TestGetSigningPrivateKeyLength(t *testing.T) {
	tests := []struct {
		sigType      int
		expectedSize int
		expectError  bool
	}{
		{SigTypeDSA_SHA1, 20, false},
		{SigTypeECDSA_SHA256_P256, 32, false},
		{SigTypeECDSA_SHA384_P384, 48, false},
		{SigTypeECDSA_SHA512_P521, 66, false},
		{SigTypeRSA_SHA256_2048, 512, false},
		{SigTypeRSA_SHA384_3072, 768, false},
		{SigTypeRSA_SHA512_4096, 1024, false},
		{SigTypeEd25519, 64, false},
		{SigTypeEd25519ph, 64, false},
		{255, 0, true}, // Invalid type
	}

	for _, tt := range tests {
		t.Run(SignatureTypeName(tt.sigType), func(t *testing.T) {
			size, err := getSigningPrivateKeyLength(tt.sigType)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for sig type %d", tt.sigType)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if size != tt.expectedSize {
					t.Errorf("size = %d, want %d", size, tt.expectedSize)
				}
			}
		})
	}
}

func TestGetSignatureLength(t *testing.T) {
	tests := []struct {
		sigType      int
		expectedSize int
		expectError  bool
	}{
		{SigTypeDSA_SHA1, 40, false},
		{SigTypeECDSA_SHA256_P256, 64, false},
		{SigTypeECDSA_SHA384_P384, 96, false},
		{SigTypeECDSA_SHA512_P521, 132, false},
		{SigTypeRSA_SHA256_2048, 256, false},
		{SigTypeRSA_SHA384_3072, 384, false},
		{SigTypeRSA_SHA512_4096, 512, false},
		{SigTypeEd25519, 64, false},
		{SigTypeEd25519ph, 64, false},
		{255, 0, true}, // Invalid type
	}

	for _, tt := range tests {
		t.Run(SignatureTypeName(tt.sigType), func(t *testing.T) {
			size, err := getSignatureLength(tt.sigType)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for sig type %d", tt.sigType)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if size != tt.expectedSize {
					t.Errorf("size = %d, want %d", size, tt.expectedSize)
				}
			}
		})
	}
}
