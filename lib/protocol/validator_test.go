package protocol

import (
	"errors"
	"testing"
)

func TestValidatePort(t *testing.T) {
	tests := []struct {
		port    int
		wantErr bool
	}{
		{0, false},
		{1, false},
		{80, false},
		{443, false},
		{7656, false},
		{65535, false},
		{-1, true},
		{65536, true},
		{100000, true},
	}

	for _, tt := range tests {
		err := ValidatePort(tt.port)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidatePort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
		}
	}
}

func TestValidatePortString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"", 0, false}, // default
		{"0", 0, false},
		{"80", 80, false},
		{"7656", 7656, false},
		{"65535", 65535, false},
		{"-1", 0, true},
		{"65536", 0, true},
		{"abc", 0, true},
		{"12.5", 0, true},
	}

	for _, tt := range tests {
		got, err := ValidatePortString(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidatePortString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ValidatePortString(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestValidateProtocol(t *testing.T) {
	tests := []struct {
		protocol int
		wantErr  bool
	}{
		{0, false},
		{18, false}, // default
		{255, false},
		{1, false},
		{6, true},  // TCP - disallowed
		{17, true}, // UDP - disallowed
		{19, true}, // disallowed
		{20, true}, // disallowed
		{-1, true},
		{256, true},
	}

	for _, tt := range tests {
		err := ValidateProtocol(tt.protocol)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateProtocol(%d) error = %v, wantErr %v", tt.protocol, err, tt.wantErr)
		}
	}
}

func TestValidateProtocolString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"", 18, false}, // default
		{"18", 18, false},
		{"0", 0, false},
		{"255", 255, false},
		{"6", 0, true},  // disallowed
		{"17", 0, true}, // disallowed
		{"abc", 0, true},
		{"-1", 0, true},
	}

	for _, tt := range tests {
		got, err := ValidateProtocolString(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateProtocolString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ValidateProtocolString(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestValidateSessionID(t *testing.T) {
	tests := []struct {
		id      string
		wantErr error
	}{
		{"test123", nil},
		{"my-session", nil},
		{"session_1", nil},
		{"", ErrEmptySessionID},
		{"has space", ErrInvalidSessionID},
		{"has\ttab", ErrInvalidSessionID},
		{"has\nnewline", ErrInvalidSessionID},
	}

	for _, tt := range tests {
		err := ValidateSessionID(tt.id)
		if tt.wantErr == nil && err != nil {
			t.Errorf("ValidateSessionID(%q) unexpected error: %v", tt.id, err)
		}
		if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("ValidateSessionID(%q) error = %v, want %v", tt.id, err, tt.wantErr)
		}
	}
}

func TestValidateSignatureType(t *testing.T) {
	tests := []struct {
		sigType int
		wantErr bool
	}{
		{0, false},
		{7, false}, // Ed25519
		{8, false},
		{-1, true},
		{9, true},
		{100, true},
	}

	for _, tt := range tests {
		err := ValidateSignatureType(tt.sigType)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateSignatureType(%d) error = %v, wantErr %v", tt.sigType, err, tt.wantErr)
		}
	}
}

func TestValidateSignatureTypeString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"", 7, false}, // default Ed25519
		{"7", 7, false},
		{"0", 0, false},
		{"8", 8, false},
		{"-1", 0, true},
		{"9", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		got, err := ValidateSignatureTypeString(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateSignatureTypeString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ValidateSignatureTypeString(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestValidateStyle(t *testing.T) {
	tests := []struct {
		style   string
		wantErr bool
	}{
		{"STREAM", false},
		{"stream", false},
		{"Stream", false},
		{"DATAGRAM", false},
		{"RAW", false},
		{"DATAGRAM2", false},
		{"DATAGRAM3", false},
		{"PRIMARY", false},
		{"MASTER", false},
		{"UNKNOWN", true},
		{"", true},
	}

	for _, tt := range tests {
		err := ValidateStyle(tt.style)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateStyle(%q) error = %v, wantErr %v", tt.style, err, tt.wantErr)
		}
	}
}

func TestNormalizeStyle(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"stream", "STREAM"},
		{"STREAM", "STREAM"},
		{"master", "PRIMARY"}, // deprecated → PRIMARY
		{"MASTER", "PRIMARY"},
		{"PRIMARY", "PRIMARY"},
		{"datagram", "DATAGRAM"},
	}

	for _, tt := range tests {
		got := NormalizeStyle(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeStyle(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseEncryptionTypes(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		wantErr  bool
	}{
		{"", []int{4, 0}, false}, // default
		{"4", []int{4}, false},
		{"4,0", []int{4, 0}, false},
		{"0,4", []int{0, 4}, false},
		{"4, 0", []int{4, 0}, false}, // with space
		{"1,2,3", []int{1, 2, 3}, false},
		{"abc", nil, true},
		{"4,abc", nil, true},
	}

	for _, tt := range tests {
		got, err := ParseEncryptionTypes(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseEncryptionTypes(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if len(got) != len(tt.expected) {
			t.Errorf("ParseEncryptionTypes(%q) = %v, want %v", tt.input, got, tt.expected)
			continue
		}
		for i, v := range tt.expected {
			if got[i] != v {
				t.Errorf("ParseEncryptionTypes(%q)[%d] = %d, want %d", tt.input, i, got[i], v)
			}
		}
	}
}

func TestParseTunnelQuantity(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"", 3, false}, // default
		{"1", 1, false},
		{"3", 3, false},
		{"5", 5, false},
		{"16", 16, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"17", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseTunnelQuantity(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTunnelQuantity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ParseTunnelQuantity(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input      string
		defaultVal bool
		expected   bool
		wantErr    bool
	}{
		{"", true, true, false},
		{"", false, false, false},
		{"true", false, true, false},
		{"false", true, false, false},
		{"TRUE", false, true, false},
		{"FALSE", true, false, false},
		{"1", false, true, false},
		{"0", true, false, false},
		{"yes", false, true, false},
		{"no", true, false, false},
		{"invalid", false, false, true},
	}

	for _, tt := range tests {
		got, err := ParseBool(tt.input, tt.defaultVal)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseBool(%q, %v) error = %v, wantErr %v", tt.input, tt.defaultVal, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ParseBool(%q, %v) = %v, want %v", tt.input, tt.defaultVal, got, tt.expected)
		}
	}
}

func TestRequireNonEmpty(t *testing.T) {
	tests := []struct {
		value     string
		fieldName string
		wantErr   bool
	}{
		{"value", "FIELD", false},
		{"  ", "FIELD", false}, // whitespace is not empty
		{"0", "FIELD", false},
		{"", "FIELD", true},
	}

	for _, tt := range tests {
		err := RequireNonEmpty(tt.value, tt.fieldName)
		if (err != nil) != tt.wantErr {
			t.Errorf("RequireNonEmpty(%q, %q) error = %v, wantErr %v", tt.value, tt.fieldName, err, tt.wantErr)
		}
		if tt.wantErr && err != nil {
			if !errors.Is(err, ErrEmptyValue) {
				t.Errorf("RequireNonEmpty(%q, %q) error should wrap ErrEmptyValue", tt.value, tt.fieldName)
			}
		}
	}
}
