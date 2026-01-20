package destination

import (
	"testing"
	"time"
)

func TestOfflineSignature_IsExpired(t *testing.T) {
	t.Run("nil offline signature", func(t *testing.T) {
		var o *OfflineSignature
		if !o.IsExpired() {
			t.Error("nil OfflineSignature IsExpired() should return true")
		}
	})

	t.Run("expired signature", func(t *testing.T) {
		o := &OfflineSignature{
			Expires: time.Now().Add(-1 * time.Hour),
		}
		if !o.IsExpired() {
			t.Error("expired OfflineSignature IsExpired() should return true")
		}
	})

	t.Run("valid not expired", func(t *testing.T) {
		o := &OfflineSignature{
			Expires: time.Now().Add(1 * time.Hour),
		}
		if o.IsExpired() {
			t.Error("valid OfflineSignature IsExpired() should return false")
		}
	})
}

func TestOfflineSignature_IsValid(t *testing.T) {
	t.Run("nil offline signature", func(t *testing.T) {
		var o *OfflineSignature
		if o.IsValid() {
			t.Error("nil OfflineSignature IsValid() should return false")
		}
	})

	t.Run("expired signature", func(t *testing.T) {
		o := &OfflineSignature{
			Expires:            time.Now().Add(-1 * time.Hour),
			TransientPublicKey: []byte{1, 2, 3},
			Signature:          []byte{4, 5, 6},
		}
		if o.IsValid() {
			t.Error("expired OfflineSignature IsValid() should return false")
		}
	})

	t.Run("missing transient key", func(t *testing.T) {
		o := &OfflineSignature{
			Expires:   time.Now().Add(1 * time.Hour),
			Signature: []byte{1, 2, 3},
		}
		if o.IsValid() {
			t.Error("OfflineSignature without transient key IsValid() should return false")
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		o := &OfflineSignature{
			Expires:            time.Now().Add(1 * time.Hour),
			TransientPublicKey: []byte{1, 2, 3},
		}
		if o.IsValid() {
			t.Error("OfflineSignature without signature IsValid() should return false")
		}
	})

	t.Run("valid signature", func(t *testing.T) {
		o := &OfflineSignature{
			Expires:                time.Now().Add(1 * time.Hour),
			TransientSignatureType: SigTypeEd25519,
			TransientPublicKey:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
			Signature:              []byte{9, 10, 11, 12},
		}
		if !o.IsValid() {
			t.Error("valid OfflineSignature IsValid() should return true")
		}
	})
}

func TestOfflineSignature_Bytes(t *testing.T) {
	t.Run("nil offline signature", func(t *testing.T) {
		var o *OfflineSignature
		if o.Bytes() != nil {
			t.Error("nil OfflineSignature Bytes() should return nil")
		}
	})

	t.Run("bytes serialization", func(t *testing.T) {
		expires := time.Unix(0x12345678, 0)
		o := &OfflineSignature{
			Expires:                expires,
			TransientSignatureType: 7,
			TransientPublicKey:     []byte{0xAA, 0xBB},
			Signature:              []byte{0xCC, 0xDD},
		}
		b := o.Bytes()
		// Expected: 4 bytes expires + 2 bytes sig type + 2 bytes pub key + 2 bytes sig
		if len(b) != 10 {
			t.Errorf("Bytes() length = %d, want 10", len(b))
		}
		// Check expires bytes (big-endian)
		if b[0] != 0x12 || b[1] != 0x34 || b[2] != 0x56 || b[3] != 0x78 {
			t.Errorf("Bytes() expires = %x, want 12345678", b[:4])
		}
		// Check sig type (big-endian, type 7)
		if b[4] != 0x00 || b[5] != 0x07 {
			t.Errorf("Bytes() sig type = %x, want 0007", b[4:6])
		}
	})
}

func TestSignatureTypeName(t *testing.T) {
	tests := []struct {
		sigType  int
		expected string
	}{
		{SigTypeDSA_SHA1, "DSA-SHA1"},
		{SigTypeECDSA_SHA256_P256, "ECDSA-SHA256-P256"},
		{SigTypeEd25519, "Ed25519"},
		{SigTypeEd25519ph, "Ed25519ph"},
		{99, "Unknown"},
		{-1, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := SignatureTypeName(tt.sigType)
			if result != tt.expected {
				t.Errorf("SignatureTypeName(%d) = %q, want %q", tt.sigType, result, tt.expected)
			}
		})
	}
}

func TestIsValidSignatureType(t *testing.T) {
	tests := []struct {
		sigType  int
		expected bool
	}{
		{SigTypeDSA_SHA1, true},
		{SigTypeEd25519, true},
		{SigTypeEd25519ph, true},
		{-1, false},
		{9, false},
		{100, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := IsValidSignatureType(tt.sigType)
			if result != tt.expected {
				t.Errorf("IsValidSignatureType(%d) = %v, want %v", tt.sigType, result, tt.expected)
			}
		})
	}
}

func TestEncryptionTypeName(t *testing.T) {
	tests := []struct {
		encType  int
		expected string
	}{
		{EncTypeElGamal, "ElGamal"},
		{EncTypeECIES_X25519, "ECIES-X25519"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := EncryptionTypeName(tt.encType)
			if result != tt.expected {
				t.Errorf("EncryptionTypeName(%d) = %q, want %q", tt.encType, result, tt.expected)
			}
		})
	}
}

func TestDefaultValues(t *testing.T) {
	if DefaultSignatureType != SigTypeEd25519 {
		t.Errorf("DefaultSignatureType = %d, want %d", DefaultSignatureType, SigTypeEd25519)
	}

	if len(DefaultEncryptionTypes) != 2 {
		t.Errorf("DefaultEncryptionTypes length = %d, want 2", len(DefaultEncryptionTypes))
	}
	if DefaultEncryptionTypes[0] != EncTypeECIES_X25519 {
		t.Errorf("DefaultEncryptionTypes[0] = %d, want %d", DefaultEncryptionTypes[0], EncTypeECIES_X25519)
	}
	if DefaultEncryptionTypes[1] != EncTypeElGamal {
		t.Errorf("DefaultEncryptionTypes[1] = %d, want %d", DefaultEncryptionTypes[1], EncTypeElGamal)
	}
}
