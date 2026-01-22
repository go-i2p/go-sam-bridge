package session

import (
	"testing"
)

func TestDefaultSessionConfig(t *testing.T) {
	cfg := DefaultSessionConfig()

	if cfg.SignatureType != DefaultSignatureType {
		t.Errorf("SignatureType = %d, want %d", cfg.SignatureType, DefaultSignatureType)
	}
	if cfg.InboundQuantity != DefaultTunnelQuantity {
		t.Errorf("InboundQuantity = %d, want %d", cfg.InboundQuantity, DefaultTunnelQuantity)
	}
	if cfg.OutboundQuantity != DefaultTunnelQuantity {
		t.Errorf("OutboundQuantity = %d, want %d", cfg.OutboundQuantity, DefaultTunnelQuantity)
	}
	if cfg.InboundLength != DefaultTunnelLength {
		t.Errorf("InboundLength = %d, want %d", cfg.InboundLength, DefaultTunnelLength)
	}
	if cfg.OutboundLength != DefaultTunnelLength {
		t.Errorf("OutboundLength = %d, want %d", cfg.OutboundLength, DefaultTunnelLength)
	}
	if cfg.Protocol != DefaultRawProtocol {
		t.Errorf("Protocol = %d, want %d", cfg.Protocol, DefaultRawProtocol)
	}
	if len(cfg.EncryptionTypes) != 2 || cfg.EncryptionTypes[0] != 4 || cfg.EncryptionTypes[1] != 0 {
		t.Errorf("EncryptionTypes = %v, want [4, 0]", cfg.EncryptionTypes)
	}
	if cfg.FromPort != 0 {
		t.Errorf("FromPort = %d, want 0", cfg.FromPort)
	}
	if cfg.ToPort != 0 {
		t.Errorf("ToPort = %d, want 0", cfg.ToPort)
	}
	if cfg.HeaderEnabled {
		t.Error("HeaderEnabled = true, want false")
	}
	if cfg.OfflineSignature != nil {
		t.Error("OfflineSignature should be nil")
	}
	if cfg.I2CPOptions == nil {
		t.Error("I2CPOptions should be initialized (not nil)")
	}
	if len(cfg.I2CPOptions) != 0 {
		t.Errorf("I2CPOptions should be empty, got %d entries", len(cfg.I2CPOptions))
	}
}

func TestSessionConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*SessionConfig)
		wantErr error
	}{
		{
			name:    "valid default config",
			modify:  func(_ *SessionConfig) {},
			wantErr: nil,
		},
		{
			name: "invalid FromPort negative",
			modify: func(c *SessionConfig) {
				c.FromPort = -1
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "invalid FromPort too high",
			modify: func(c *SessionConfig) {
				c.FromPort = 65536
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "valid FromPort max",
			modify: func(c *SessionConfig) {
				c.FromPort = 65535
			},
			wantErr: nil,
		},
		{
			name: "invalid ToPort negative",
			modify: func(c *SessionConfig) {
				c.ToPort = -1
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "invalid ToPort too high",
			modify: func(c *SessionConfig) {
				c.ToPort = 65536
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "invalid Protocol negative",
			modify: func(c *SessionConfig) {
				c.Protocol = -1
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "invalid Protocol too high",
			modify: func(c *SessionConfig) {
				c.Protocol = 256
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "disallowed Protocol 6 (TCP)",
			modify: func(c *SessionConfig) {
				c.Protocol = 6
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "disallowed Protocol 17 (UDP)",
			modify: func(c *SessionConfig) {
				c.Protocol = 17
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "disallowed Protocol 19",
			modify: func(c *SessionConfig) {
				c.Protocol = 19
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "disallowed Protocol 20",
			modify: func(c *SessionConfig) {
				c.Protocol = 20
			},
			wantErr: ErrInvalidProtocol,
		},
		{
			name: "valid Protocol 18",
			modify: func(c *SessionConfig) {
				c.Protocol = 18
			},
			wantErr: nil,
		},
		{
			name: "invalid ListenPort",
			modify: func(c *SessionConfig) {
				c.ListenPort = -1
			},
			wantErr: ErrInvalidPort,
		},
		{
			name: "invalid InboundQuantity negative",
			modify: func(c *SessionConfig) {
				c.InboundQuantity = -1
			},
			wantErr: ErrInvalidTunnelConfig,
		},
		{
			name: "invalid OutboundQuantity negative",
			modify: func(c *SessionConfig) {
				c.OutboundQuantity = -1
			},
			wantErr: ErrInvalidTunnelConfig,
		},
		{
			name: "invalid InboundLength negative",
			modify: func(c *SessionConfig) {
				c.InboundLength = -1
			},
			wantErr: ErrInvalidTunnelConfig,
		},
		{
			name: "invalid OutboundLength negative",
			modify: func(c *SessionConfig) {
				c.OutboundLength = -1
			},
			wantErr: ErrInvalidTunnelConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultSessionConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSessionConfig_Chaining(t *testing.T) {
	cfg := DefaultSessionConfig().
		WithFromPort(1234).
		WithToPort(5678).
		WithTunnelQuantity(5).
		WithTunnelLength(4).
		WithSignatureType(7).
		WithEncryptionTypes([]int{4, 0})

	if cfg.FromPort != 1234 {
		t.Errorf("FromPort = %d, want 1234", cfg.FromPort)
	}
	if cfg.ToPort != 5678 {
		t.Errorf("ToPort = %d, want 5678", cfg.ToPort)
	}
	if cfg.InboundQuantity != 5 {
		t.Errorf("InboundQuantity = %d, want 5", cfg.InboundQuantity)
	}
	if cfg.OutboundQuantity != 5 {
		t.Errorf("OutboundQuantity = %d, want 5", cfg.OutboundQuantity)
	}
	if cfg.InboundLength != 4 {
		t.Errorf("InboundLength = %d, want 4", cfg.InboundLength)
	}
	if cfg.OutboundLength != 4 {
		t.Errorf("OutboundLength = %d, want 4", cfg.OutboundLength)
	}
	if cfg.SignatureType != 7 {
		t.Errorf("SignatureType = %d, want 7", cfg.SignatureType)
	}
}

func TestSessionConfig_I2CPOptionsChaining(t *testing.T) {
	t.Run("WithI2CPOption single", func(t *testing.T) {
		cfg := DefaultSessionConfig().
			WithI2CPOption("i2cp.leaseSetEncType", "4,0")

		if cfg.I2CPOptions["i2cp.leaseSetEncType"] != "4,0" {
			t.Errorf("I2CPOptions[i2cp.leaseSetEncType] = %q, want %q", cfg.I2CPOptions["i2cp.leaseSetEncType"], "4,0")
		}
	})

	t.Run("WithI2CPOption multiple", func(t *testing.T) {
		cfg := DefaultSessionConfig().
			WithI2CPOption("i2cp.leaseSetEncType", "4,0").
			WithI2CPOption("streaming.maxConnsPerMinute", "10")

		if cfg.I2CPOptions["i2cp.leaseSetEncType"] != "4,0" {
			t.Errorf("I2CPOptions[i2cp.leaseSetEncType] = %q, want %q", cfg.I2CPOptions["i2cp.leaseSetEncType"], "4,0")
		}
		if cfg.I2CPOptions["streaming.maxConnsPerMinute"] != "10" {
			t.Errorf("I2CPOptions[streaming.maxConnsPerMinute] = %q, want %q", cfg.I2CPOptions["streaming.maxConnsPerMinute"], "10")
		}
	})

	t.Run("WithI2CPOptions replaces all", func(t *testing.T) {
		cfg := DefaultSessionConfig().
			WithI2CPOption("old.option", "value").
			WithI2CPOptions(map[string]string{
				"new.option": "value",
			})

		if _, exists := cfg.I2CPOptions["old.option"]; exists {
			t.Error("WithI2CPOptions should replace all existing options")
		}
		if cfg.I2CPOptions["new.option"] != "value" {
			t.Errorf("I2CPOptions[new.option] = %q, want %q", cfg.I2CPOptions["new.option"], "value")
		}
	})

	t.Run("WithI2CPOption on nil map", func(t *testing.T) {
		cfg := &SessionConfig{}
		cfg.WithI2CPOption("key", "value")

		if cfg.I2CPOptions == nil {
			t.Error("WithI2CPOption should initialize nil map")
		}
		if cfg.I2CPOptions["key"] != "value" {
			t.Errorf("I2CPOptions[key] = %q, want %q", cfg.I2CPOptions["key"], "value")
		}
	})
}

func TestSessionConfig_Clone(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var cfg *SessionConfig
		clone := cfg.Clone()
		if clone != nil {
			t.Error("Clone of nil should return nil")
		}
	})

	t.Run("basic clone", func(t *testing.T) {
		orig := DefaultSessionConfig()
		orig.FromPort = 1234
		orig.ToPort = 5678

		clone := orig.Clone()
		if clone == orig {
			t.Error("Clone should create new instance")
		}
		if clone.FromPort != 1234 {
			t.Errorf("Clone.FromPort = %d, want 1234", clone.FromPort)
		}
		if clone.ToPort != 5678 {
			t.Errorf("Clone.ToPort = %d, want 5678", clone.ToPort)
		}
	})

	t.Run("encryption types isolation", func(t *testing.T) {
		orig := DefaultSessionConfig()
		clone := orig.Clone()

		// Modify original
		orig.EncryptionTypes[0] = 99

		// Clone should be unaffected
		if clone.EncryptionTypes[0] == 99 {
			t.Error("Clone EncryptionTypes should be isolated from original")
		}
	})

	t.Run("offline signature clone", func(t *testing.T) {
		orig := DefaultSessionConfig()
		orig.OfflineSignature = &OfflineSignature{
			Expires:            12345,
			TransientType:      7,
			TransientPublicKey: []byte("pubkey"),
			Signature:          []byte("sig"),
		}

		clone := orig.Clone()
		if clone.OfflineSignature == orig.OfflineSignature {
			t.Error("Clone should create new OfflineSignature instance")
		}
		if clone.OfflineSignature.Expires != 12345 {
			t.Errorf("Clone.OfflineSignature.Expires = %d, want 12345", clone.OfflineSignature.Expires)
		}
		if string(clone.OfflineSignature.TransientPublicKey) != "pubkey" {
			t.Errorf("Clone.OfflineSignature.TransientPublicKey = %q, want %q", clone.OfflineSignature.TransientPublicKey, "pubkey")
		}
		if string(clone.OfflineSignature.Signature) != "sig" {
			t.Errorf("Clone.OfflineSignature.Signature = %q, want %q", clone.OfflineSignature.Signature, "sig")
		}

		// Modify original
		orig.OfflineSignature.Expires = 99999
		orig.OfflineSignature.TransientPublicKey[0] = 'X'

		// Clone should be unaffected
		if clone.OfflineSignature.Expires == 99999 {
			t.Error("Clone OfflineSignature.Expires should be isolated")
		}
		if clone.OfflineSignature.TransientPublicKey[0] == 'X' {
			t.Error("Clone OfflineSignature.TransientPublicKey should be isolated")
		}
	})

	t.Run("I2CPOptions clone", func(t *testing.T) {
		orig := DefaultSessionConfig()
		orig.I2CPOptions["i2cp.leaseSetEncType"] = "4,0"
		orig.I2CPOptions["streaming.maxConnsPerMinute"] = "10"

		clone := orig.Clone()
		if clone.I2CPOptions == nil {
			t.Error("Clone I2CPOptions should not be nil")
		}
		if clone.I2CPOptions["i2cp.leaseSetEncType"] != "4,0" {
			t.Errorf("Clone.I2CPOptions[i2cp.leaseSetEncType] = %q, want %q", clone.I2CPOptions["i2cp.leaseSetEncType"], "4,0")
		}
		if clone.I2CPOptions["streaming.maxConnsPerMinute"] != "10" {
			t.Errorf("Clone.I2CPOptions[streaming.maxConnsPerMinute] = %q, want %q", clone.I2CPOptions["streaming.maxConnsPerMinute"], "10")
		}

		// Modify original
		orig.I2CPOptions["i2cp.leaseSetEncType"] = "modified"

		// Clone should be unaffected
		if clone.I2CPOptions["i2cp.leaseSetEncType"] == "modified" {
			t.Error("Clone I2CPOptions should be isolated from original")
		}
	})
}

func TestConnectOptions(t *testing.T) {
	opts := ConnectOptions{
		FromPort: 1234,
		ToPort:   5678,
		Silent:   true,
	}

	if opts.FromPort != 1234 {
		t.Errorf("FromPort = %d, want 1234", opts.FromPort)
	}
	if opts.ToPort != 5678 {
		t.Errorf("ToPort = %d, want 5678", opts.ToPort)
	}
	if !opts.Silent {
		t.Error("Silent = false, want true")
	}
}

func TestAcceptOptions(t *testing.T) {
	opts := AcceptOptions{
		Silent: true,
	}

	if !opts.Silent {
		t.Error("Silent = false, want true")
	}
}

func TestForwardOptions(t *testing.T) {
	opts := ForwardOptions{
		Port:       8080,
		Host:       "127.0.0.1",
		Silent:     true,
		SSLEnabled: true,
	}

	if opts.Port != 8080 {
		t.Errorf("Port = %d, want 8080", opts.Port)
	}
	if opts.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want %q", opts.Host, "127.0.0.1")
	}
	if !opts.Silent {
		t.Error("Silent = false, want true")
	}
	if !opts.SSLEnabled {
		t.Error("SSLEnabled = false, want true")
	}
}

func TestDatagramSendOptions(t *testing.T) {
	opts := DatagramSendOptions{
		FromPort: 1234,
		ToPort:   5678,
	}

	if opts.FromPort != 1234 {
		t.Errorf("FromPort = %d, want 1234", opts.FromPort)
	}
	if opts.ToPort != 5678 {
		t.Errorf("ToPort = %d, want 5678", opts.ToPort)
	}
}

func TestRawSendOptions(t *testing.T) {
	opts := RawSendOptions{
		FromPort: 1234,
		ToPort:   5678,
		Protocol: 18,
	}

	if opts.FromPort != 1234 {
		t.Errorf("FromPort = %d, want 1234", opts.FromPort)
	}
	if opts.ToPort != 5678 {
		t.Errorf("ToPort = %d, want 5678", opts.ToPort)
	}
	if opts.Protocol != 18 {
		t.Errorf("Protocol = %d, want 18", opts.Protocol)
	}
}

func TestSubsessionOptions(t *testing.T) {
	opts := SubsessionOptions{
		FromPort:       1234,
		ToPort:         5678,
		Protocol:       18,
		ListenPort:     8080,
		ListenProtocol: 19,
		HeaderEnabled:  true,
		Host:           "127.0.0.1",
		Port:           9090,
	}

	if opts.FromPort != 1234 {
		t.Errorf("FromPort = %d, want 1234", opts.FromPort)
	}
	if opts.ToPort != 5678 {
		t.Errorf("ToPort = %d, want 5678", opts.ToPort)
	}
	if opts.Protocol != 18 {
		t.Errorf("Protocol = %d, want 18", opts.Protocol)
	}
	if opts.ListenPort != 8080 {
		t.Errorf("ListenPort = %d, want 8080", opts.ListenPort)
	}
	if opts.ListenProtocol != 19 {
		t.Errorf("ListenProtocol = %d, want 19", opts.ListenProtocol)
	}
	if !opts.HeaderEnabled {
		t.Error("HeaderEnabled = false, want true")
	}
	if opts.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want %q", opts.Host, "127.0.0.1")
	}
	if opts.Port != 9090 {
		t.Errorf("Port = %d, want 9090", opts.Port)
	}
}

func TestIsDisallowedProtocol(t *testing.T) {
	tests := []struct {
		protocol int
		expected bool
	}{
		{0, false},
		{5, false},
		{6, true}, // TCP
		{7, false},
		{16, false},
		{17, true}, // UDP
		{18, false},
		{19, true},
		{20, true},
		{21, false},
		{255, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := isDisallowedProtocol(tt.protocol); got != tt.expected {
				t.Errorf("isDisallowedProtocol(%d) = %v, want %v", tt.protocol, got, tt.expected)
			}
		})
	}
}
