package destination

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.cache == nil {
		t.Error("Manager cache should be initialized")
	}
	if m.CacheSize() != 0 {
		t.Errorf("Initial cache size = %d, want 0", m.CacheSize())
	}
}

func TestManagerImpl_Generate(t *testing.T) {
	m := NewManager()

	t.Run("Ed25519 generation", func(t *testing.T) {
		dest, privateKey, err := m.Generate(SigTypeEd25519)
		if err != nil {
			t.Fatalf("Generate(Ed25519) error = %v", err)
		}
		if dest == nil {
			t.Fatal("Generate() returned nil destination")
		}
		if len(privateKey) == 0 {
			t.Error("Generate() returned empty private key")
		}
	})

	t.Run("Ed25519 key sizes correct", func(t *testing.T) {
		// Verify private key contains both encryption (32B) and signing (64B) keys
		_, privateKey, err := m.Generate(SigTypeEd25519)
		if err != nil {
			t.Fatalf("Generate(Ed25519) error = %v", err)
		}
		// Expected: 32 bytes X25519 + 64 bytes Ed25519 = 96 bytes total
		expectedSize := 32 + 64 // X25519 encryption + Ed25519 signing
		if len(privateKey) != expectedSize {
			t.Errorf("Private key size = %d bytes, want %d bytes (32 X25519 + 64 Ed25519)",
				len(privateKey), expectedSize)
		}
	})

	t.Run("unsupported signature type DSA", func(t *testing.T) {
		_, _, err := m.Generate(SigTypeDSA_SHA1)
		if err == nil {
			t.Error("Generate(DSA) should return error for unsupported type")
		}
		if err != ErrUnsupportedSignatureType {
			t.Errorf("Generate(DSA) error = %v, want ErrUnsupportedSignatureType", err)
		}
	})

	t.Run("invalid signature type", func(t *testing.T) {
		_, _, err := m.Generate(999)
		if err == nil {
			t.Error("Generate(999) should return error")
		}
		if err != ErrUnsupportedSignatureType {
			t.Errorf("Generate(999) error = %v, want ErrUnsupportedSignatureType", err)
		}
	})
}

func TestManagerImpl_Parse(t *testing.T) {
	m := NewManager()

	t.Run("empty input", func(t *testing.T) {
		_, _, err := m.Parse("")
		if err == nil {
			t.Error("Parse(\"\") should return error")
		}
		if err != ErrInvalidPrivateKey {
			t.Errorf("Parse(\"\") error = %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, _, err := m.Parse("!!!invalid!!!")
		if err == nil {
			t.Error("Parse(invalid) should return error")
		}
	})

	t.Run("too short data", func(t *testing.T) {
		// Very short valid base64 string
		_, _, err := m.Parse("SGVsbG8=")
		if err == nil {
			t.Error("Parse(short) should return error")
		}
	})
}

func TestManagerImpl_ParsePublic(t *testing.T) {
	m := NewManager()

	t.Run("empty input", func(t *testing.T) {
		_, err := m.ParsePublic("")
		if err == nil {
			t.Error("ParsePublic(\"\") should return error")
		}
		if err != ErrInvalidDestination {
			t.Errorf("ParsePublic(\"\") error = %v, want ErrInvalidDestination", err)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := m.ParsePublic("!!!invalid!!!")
		if err == nil {
			t.Error("ParsePublic(invalid) should return error")
		}
	})
}

func TestManagerImpl_Encode(t *testing.T) {
	m := NewManager()

	t.Run("nil destination", func(t *testing.T) {
		_, err := m.Encode(nil, []byte{1, 2, 3})
		if err == nil {
			t.Error("Encode(nil) should return error")
		}
	})
}

func TestManagerImpl_EncodePublic(t *testing.T) {
	m := NewManager()

	t.Run("nil destination", func(t *testing.T) {
		_, err := m.EncodePublic(nil)
		if err == nil {
			t.Error("EncodePublic(nil) should return error")
		}
	})
}

func TestManagerImpl_Cache(t *testing.T) {
	m := NewManager()

	if m.CacheSize() != 0 {
		t.Errorf("Initial CacheSize() = %d, want 0", m.CacheSize())
	}

	m.ClearCache()
	if m.CacheSize() != 0 {
		t.Errorf("After ClearCache() CacheSize() = %d, want 0", m.CacheSize())
	}
}

func TestManagerImpl_GenerateAndEncode(t *testing.T) {
	m := NewManager()

	// Generate a destination
	dest, privateKey, err := m.Generate(SigTypeEd25519)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Encode it
	encoded, err := m.Encode(dest, privateKey)
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if encoded == "" {
		t.Error("Encoded private key should not be empty")
	}

	// Encode public portion
	publicEncoded, err := m.EncodePublic(dest)
	if err != nil {
		t.Fatalf("EncodePublic error: %v", err)
	}
	if publicEncoded == "" {
		t.Error("Encoded public destination should not be empty")
	}
}
