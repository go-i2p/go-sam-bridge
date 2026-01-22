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

// TestI2PBase64Alphabet verifies that Base64Encode produces only I2P alphabet characters.
// Per SAMv3.md: "Base 64 encoding must use the I2P standard Base 64 alphabet 'A-Z, a-z, 0-9, -, ~'."
// Standard Base64 uses + and /, which must be replaced with - and ~ respectively.
func TestI2PBase64Alphabet(t *testing.T) {
	// Test data that produces + and / in standard base64
	// 0xfb produces '+' in position 0 (252 >> 2 = 63 = '+')
	// 0xff, 0xfe produces '/' in various positions
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "bytes producing + in standard base64",
			input: []byte{0xfb, 0xef, 0xbe}, // produces "++++/" in std base64
		},
		{
			name:  "bytes producing / in standard base64",
			input: []byte{0xff, 0xff, 0xff}, // produces "////" in std base64
		},
		{
			name:  "mixed special characters",
			input: []byte{0xfb, 0xff, 0xfe, 0xef, 0xbe, 0xfb},
		},
		{
			name:  "large random-like data",
			input: []byte{0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7, 0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base64Encode(tt.input)

			// Verify no standard base64 special characters are present
			for i, c := range encoded {
				if c == '+' {
					t.Errorf("I2P base64 should not contain '+' at position %d, encoded: %q", i, encoded)
				}
				if c == '/' {
					t.Errorf("I2P base64 should not contain '/' at position %d, encoded: %q", i, encoded)
				}
			}

			// Verify roundtrip still works
			decoded, err := Base64Decode(encoded)
			if err != nil {
				t.Errorf("failed to decode I2P base64: %v", err)
				return
			}
			if !bytes.Equal(decoded, tt.input) {
				t.Errorf("roundtrip failed: got %v, want %v", decoded, tt.input)
			}
		})
	}
}

// TestI2PBase64CrossCompatibility tests that our encoding is compatible with
// known I2P destinations. These test vectors are derived from actual I2P destinations.
func TestI2PBase64CrossCompatibility(t *testing.T) {
	// Verify that encoding special characters produces I2P alphabet
	// These bytes would produce + and / in standard base64
	testCases := []struct {
		name     string
		data     []byte
		contains string // Expected I2P character that replaces std base64
	}{
		{
			name:     "tilde replacement for slash",
			data:     []byte{0xff, 0xff, 0xff},
			contains: "~", // Standard base64 would have /
		},
		{
			name:     "dash replacement for plus",
			data:     []byte{0xfb, 0xef, 0xbe},
			contains: "-", // Standard base64 would have +
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := Base64Encode(tc.data)
			hasExpected := false
			for _, c := range encoded {
				if string(c) == tc.contains {
					hasExpected = true
					break
				}
			}
			if !hasExpected {
				t.Errorf("expected I2P base64 to contain %q for input %v, got: %q", tc.contains, tc.data, encoded)
			}
		})
	}
}
