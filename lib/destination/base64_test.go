package destination

import (
	"bytes"
	"testing"
)

func TestBase64Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte zero",
			input:    []byte{0x00},
			expected: "AA==",
		},
		{
			name:     "two bytes",
			input:    []byte{0x00, 0x00},
			expected: "AAA=",
		},
		{
			name:     "three bytes",
			input:    []byte{0x00, 0x00, 0x00},
			expected: "AAAA",
		},
		{
			name:     "Hello",
			input:    []byte("Hello"),
			expected: "SGVsbG8=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64Encode(tt.input)
			if result != tt.expected {
				t.Errorf("Base64Encode(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase64Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "empty input",
			input:    "",
			expected: nil,
			wantErr:  false,
		},
		{
			name:     "single byte",
			input:    "AA==",
			expected: []byte{0x00},
			wantErr:  false,
		},
		{
			name:     "Hello",
			input:    "SGVsbG8=",
			expected: []byte("Hello"),
			wantErr:  false,
		},
		{
			name:     "invalid character",
			input:    "!!!!", // Invalid I2P Base64 characters
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base64Decode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Base64Decode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(result, tt.expected) {
				t.Errorf("Base64Decode(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase64RoundTrip(t *testing.T) {
	tests := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x00, 0xFF},
		[]byte("Hello, World!"),
		make([]byte, 100),
		make([]byte, 256),
	}

	for i, input := range tests {
		encoded := Base64Encode(input)
		decoded, err := Base64Decode(encoded)
		if err != nil {
			t.Errorf("test %d: decode error: %v", i, err)
			continue
		}
		if !bytes.Equal(decoded, input) {
			t.Errorf("test %d: roundtrip failed: got %v, want %v", i, decoded, input)
		}
	}
}

func TestStdToI2PBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABC+/==", "ABC-~=="},
		{"hello+world/test", "hello-world~test"},
		{"nochange", "nochange"},
	}

	for _, tt := range tests {
		result := StdToI2PBase64(tt.input)
		if result != tt.expected {
			t.Errorf("StdToI2PBase64(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestI2PToStdBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABC-~==", "ABC+/=="},
		{"hello-world~test", "hello+world/test"},
		{"nochange", "nochange"},
	}

	for _, tt := range tests {
		result := I2PToStdBase64(tt.input)
		if result != tt.expected {
			t.Errorf("I2PToStdBase64(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestBase64ConversionRoundTrip(t *testing.T) {
	original := "ABC+/=="
	i2p := StdToI2PBase64(original)
	std := I2PToStdBase64(i2p)
	if std != original {
		t.Errorf("conversion roundtrip failed: got %q, want %q", std, original)
	}
}
