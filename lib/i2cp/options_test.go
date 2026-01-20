package i2cp

import (
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

func TestMapSAMConfigToI2CP(t *testing.T) {
	t.Run("nil config returns defaults", func(t *testing.T) {
		config := MapSAMConfigToI2CP(nil)
		if config == nil {
			t.Fatal("MapSAMConfigToI2CP returned nil")
		}
		if config.SignatureType != 7 {
			t.Errorf("expected default signature type 7, got %d", config.SignatureType)
		}
	})

	t.Run("maps all fields correctly", func(t *testing.T) {
		samConfig := &session.SessionConfig{
			SignatureType:          8,
			EncryptionTypes:        []int{4, 0},
			InboundQuantity:        5,
			OutboundQuantity:       6,
			InboundLength:          2,
			OutboundLength:         2,
			InboundBackupQuantity:  1,
			OutboundBackupQuantity: 1,
			ReduceIdleTime:         300,
			CloseIdleTime:          600,
		}

		config := MapSAMConfigToI2CP(samConfig)

		if config.SignatureType != 8 {
			t.Errorf("expected signature type 8, got %d", config.SignatureType)
		}
		if len(config.EncryptionTypes) != 2 {
			t.Errorf("expected 2 encryption types, got %d", len(config.EncryptionTypes))
		}
		if config.InboundQuantity != 5 {
			t.Errorf("expected inbound quantity 5, got %d", config.InboundQuantity)
		}
		if config.OutboundQuantity != 6 {
			t.Errorf("expected outbound quantity 6, got %d", config.OutboundQuantity)
		}
		if config.ReduceIdleTime != 300 {
			t.Errorf("expected reduce idle time 300, got %d", config.ReduceIdleTime)
		}
		if config.CloseIdleTime != 600 {
			t.Errorf("expected close idle time 600, got %d", config.CloseIdleTime)
		}
	})
}

func TestI2CPOptions(t *testing.T) {
	t.Run("NewI2CPOptions creates empty map", func(t *testing.T) {
		opts := NewI2CPOptions()
		if opts == nil {
			t.Fatal("NewI2CPOptions returned nil")
		}
		if len(opts) != 0 {
			t.Errorf("expected empty map, got %d entries", len(opts))
		}
	})

	t.Run("Set and Get string", func(t *testing.T) {
		opts := NewI2CPOptions()
		opts.Set("key", "value")
		if opts.Get("key") != "value" {
			t.Errorf("expected 'value', got '%s'", opts.Get("key"))
		}
	})

	t.Run("SetInt and GetInt", func(t *testing.T) {
		opts := NewI2CPOptions()
		opts.SetInt("count", 42)
		if opts.GetInt("count") != 42 {
			t.Errorf("expected 42, got %d", opts.GetInt("count"))
		}
	})

	t.Run("SetBool and GetBool", func(t *testing.T) {
		opts := NewI2CPOptions()
		opts.SetBool("enabled", true)
		if !opts.GetBool("enabled") {
			t.Error("expected true, got false")
		}
		opts.SetBool("disabled", false)
		if opts.GetBool("disabled") {
			t.Error("expected false, got true")
		}
	})

	t.Run("GetInt with invalid value returns 0", func(t *testing.T) {
		opts := NewI2CPOptions()
		opts.Set("invalid", "not-a-number")
		if opts.GetInt("invalid") != 0 {
			t.Errorf("expected 0 for invalid int, got %d", opts.GetInt("invalid"))
		}
	})

	t.Run("Get missing key returns empty string", func(t *testing.T) {
		opts := NewI2CPOptions()
		if opts.Get("missing") != "" {
			t.Errorf("expected empty string, got '%s'", opts.Get("missing"))
		}
	})
}

func TestBuildFromSAMConfig(t *testing.T) {
	t.Run("nil config returns empty options", func(t *testing.T) {
		opts := BuildFromSAMConfig(nil)
		if len(opts) != 0 {
			t.Errorf("expected empty options, got %d", len(opts))
		}
	})

	t.Run("builds options from config", func(t *testing.T) {
		config := &session.SessionConfig{
			InboundQuantity:  3,
			OutboundQuantity: 3,
			InboundLength:    3,
			OutboundLength:   3,
			EncryptionTypes:  []int{4, 0},
		}

		opts := BuildFromSAMConfig(config)

		if opts.GetInt("inbound.quantity") != 3 {
			t.Errorf("expected inbound.quantity 3, got %d", opts.GetInt("inbound.quantity"))
		}
		if opts.Get("i2cp.leaseSetEncType") != "4,0" {
			t.Errorf("expected encryption types '4,0', got '%s'", opts.Get("i2cp.leaseSetEncType"))
		}
		if !opts.GetBool("i2cp.fastReceive") {
			t.Error("expected fastReceive to be true")
		}
	})
}

func TestParseI2CPOptions(t *testing.T) {
	t.Run("parses known options", func(t *testing.T) {
		cmdOptions := map[string]string{
			"inbound.quantity":     "5",
			"outbound.quantity":    "5",
			"i2cp.leaseSetEncType": "4",
			"unknown.option":       "ignored",
		}

		opts := ParseI2CPOptions(cmdOptions)

		if opts.Get("inbound.quantity") != "5" {
			t.Errorf("expected inbound.quantity '5', got '%s'", opts.Get("inbound.quantity"))
		}
		if opts.Get("i2cp.leaseSetEncType") != "4" {
			t.Errorf("expected encryption type '4', got '%s'", opts.Get("i2cp.leaseSetEncType"))
		}
		if opts.Get("unknown.option") != "" {
			t.Errorf("unknown option should not be parsed: '%s'", opts.Get("unknown.option"))
		}
	})

	t.Run("parses all i2cp.* options", func(t *testing.T) {
		cmdOptions := map[string]string{
			"i2cp.customOption": "custom-value",
		}

		opts := ParseI2CPOptions(cmdOptions)

		if opts.Get("i2cp.customOption") != "custom-value" {
			t.Errorf("expected custom i2cp option, got '%s'", opts.Get("i2cp.customOption"))
		}
	})
}

func TestSignatureTypeName(t *testing.T) {
	tests := []struct {
		sigType int
		name    string
	}{
		{0, "DSA_SHA1"},
		{7, "Ed25519"},
		{8, "Ed25519ph"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := SignatureTypeName(tt.sigType)
			if name != tt.name {
				t.Errorf("expected %s, got %s", tt.name, name)
			}
		})
	}
}

func TestEncryptionTypeName(t *testing.T) {
	tests := []struct {
		encType int
		name    string
	}{
		{0, "ElGamal"},
		{4, "ECIES-X25519"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := EncryptionTypeName(tt.encType)
			if name != tt.name {
				t.Errorf("expected %s, got %s", tt.name, name)
			}
		})
	}
}

func TestValidateSignatureType(t *testing.T) {
	validTypes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8}
	for _, sigType := range validTypes {
		if !ValidateSignatureType(sigType) {
			t.Errorf("signature type %d should be valid", sigType)
		}
	}

	invalidTypes := []int{-1, 9, 100}
	for _, sigType := range invalidTypes {
		if ValidateSignatureType(sigType) {
			t.Errorf("signature type %d should be invalid", sigType)
		}
	}
}

func TestValidateEncryptionType(t *testing.T) {
	validTypes := []int{0, 4}
	for _, encType := range validTypes {
		if !ValidateEncryptionType(encType) {
			t.Errorf("encryption type %d should be valid", encType)
		}
	}

	invalidTypes := []int{-1, 1, 2, 3, 5, 100}
	for _, encType := range invalidTypes {
		if ValidateEncryptionType(encType) {
			t.Errorf("encryption type %d should be invalid", encType)
		}
	}
}
