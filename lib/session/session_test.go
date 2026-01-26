package session

import (
	"testing"
)

func TestStatus_String(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusCreating, "CREATING"},
		{StatusActive, "ACTIVE"},
		{StatusClosing, "CLOSING"},
		{StatusClosed, "CLOSED"},
		{Status(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf("Status.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestStyle_IsValid(t *testing.T) {
	tests := []struct {
		style    Style
		expected bool
	}{
		{StyleStream, true},
		{StyleDatagram, true},
		{StyleRaw, true},
		{StyleDatagram2, true},
		{StyleDatagram3, true},
		{StylePrimary, true},
		{StyleMaster, true},
		{Style("INVALID"), false},
		{Style(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.style), func(t *testing.T) {
			if got := tt.style.IsValid(); got != tt.expected {
				t.Errorf("Style.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStyle_IsPrimary(t *testing.T) {
	tests := []struct {
		style    Style
		expected bool
	}{
		{StylePrimary, true},
		{StyleMaster, true},
		{StyleStream, false},
		{StyleDatagram, false},
		{StyleRaw, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.style), func(t *testing.T) {
			if got := tt.style.IsPrimary(); got != tt.expected {
				t.Errorf("Style.IsPrimary() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDestination_Hash(t *testing.T) {
	t.Run("nil destination", func(t *testing.T) {
		var d *Destination
		if got := d.Hash(); got != "" {
			t.Errorf("nil Destination.Hash() = %q, want empty string", got)
		}
	})

	t.Run("empty public key", func(t *testing.T) {
		d := &Destination{PublicKey: []byte{}}
		if got := d.Hash(); got != "" {
			t.Errorf("empty PublicKey.Hash() = %q, want empty string", got)
		}
	})

	t.Run("short public key returns hex encoded", func(t *testing.T) {
		d := &Destination{PublicKey: []byte("shortkey")}
		got := d.Hash()
		// "shortkey" hex encoded = 73686f72746b6579
		want := "73686f72746b6579"
		if got != want {
			t.Errorf("short PublicKey.Hash() = %q, want %q", got, want)
		}
	})

	t.Run("long public key truncated to 32 bytes hex encoded", func(t *testing.T) {
		longKey := make([]byte, 64)
		for i := range longKey {
			longKey[i] = byte(i)
		}
		d := &Destination{PublicKey: longKey}
		got := d.Hash()
		// 32 bytes hex encoded = 64 characters
		if len(got) != 64 {
			t.Errorf("long PublicKey.Hash() len = %d, want 64", len(got))
		}
		// Verify it contains only hex characters
		for _, c := range got {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Hash contains non-hex character: %c", c)
			}
		}
	})

	t.Run("binary data produces valid hex", func(t *testing.T) {
		// Test with bytes that are not valid UTF-8 to verify hex encoding works
		d := &Destination{PublicKey: []byte{0x00, 0xff, 0x80, 0x7f}}
		got := d.Hash()
		want := "00ff807f"
		if got != want {
			t.Errorf("binary PublicKey.Hash() = %q, want %q", got, want)
		}
	})
}

func TestReceivedDatagram(t *testing.T) {
	dg := ReceivedDatagram{
		Source:   "test-source",
		FromPort: 1234,
		ToPort:   5678,
		Data:     []byte("test data"),
	}

	if dg.Source != "test-source" {
		t.Errorf("Source = %q, want %q", dg.Source, "test-source")
	}
	if dg.FromPort != 1234 {
		t.Errorf("FromPort = %d, want %d", dg.FromPort, 1234)
	}
	if dg.ToPort != 5678 {
		t.Errorf("ToPort = %d, want %d", dg.ToPort, 5678)
	}
	if string(dg.Data) != "test data" {
		t.Errorf("Data = %q, want %q", string(dg.Data), "test data")
	}
}

func TestReceivedRawDatagram(t *testing.T) {
	dg := ReceivedRawDatagram{
		FromPort: 1234,
		ToPort:   5678,
		Protocol: 18,
		Data:     []byte("raw data"),
	}

	if dg.FromPort != 1234 {
		t.Errorf("FromPort = %d, want %d", dg.FromPort, 1234)
	}
	if dg.ToPort != 5678 {
		t.Errorf("ToPort = %d, want %d", dg.ToPort, 5678)
	}
	if dg.Protocol != 18 {
		t.Errorf("Protocol = %d, want %d", dg.Protocol, 18)
	}
	if string(dg.Data) != "raw data" {
		t.Errorf("Data = %q, want %q", string(dg.Data), "raw data")
	}
}
