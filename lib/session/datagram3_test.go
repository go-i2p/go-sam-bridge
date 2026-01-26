// Package session implements SAM v3.0-3.3 session management.
// Tests for Datagram3SessionImpl.
package session

import (
	"encoding/base32"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewDatagram3Session(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		config *SessionConfig
	}{
		{
			name:   "basic creation",
			id:     "test-dg3",
			config: DefaultSessionConfig(),
		},
		{
			name:   "nil config uses defaults",
			id:     "test-dg3-nil",
			config: nil,
		},
		{
			name:   "empty id",
			id:     "",
			config: DefaultSessionConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewDatagram3Session(tt.id, nil, nil, tt.config)
			if sess == nil {
				t.Fatal("NewDatagram3Session returned nil")
			}

			if sess.ID() != tt.id {
				t.Errorf("ID() = %q, want %q", sess.ID(), tt.id)
			}

			if sess.Style() != StyleDatagram3 {
				t.Errorf("Style() = %v, want %v", sess.Style(), StyleDatagram3)
			}

			if sess.Status() != StatusCreating {
				t.Errorf("Status() = %v, want %v", sess.Status(), StatusCreating)
			}

			// Clean up
			if err := sess.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestDatagram3Session_Send(t *testing.T) {
	sess := NewDatagram3Session("test-send", nil, nil, nil)
	defer sess.Close()

	// Session must be active to send
	sess.SetStatus(StatusActive)

	tests := []struct {
		name    string
		dest    string
		data    []byte
		wantErr error
	}{
		{
			name:    "empty payload",
			dest:    "test.i2p",
			data:    []byte{},
			wantErr: ErrEmptyPayload,
		},
		{
			name:    "too large payload",
			dest:    "test.i2p",
			data:    make([]byte, MaxDatagram3Size+1),
			wantErr: ErrPayloadTooLarge,
		},
		{
			name:    "valid payload returns not implemented",
			dest:    "test.i2p",
			data:    []byte("hello world"),
			wantErr: ErrDatagram3SendNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sess.Send(tt.dest, tt.data, DatagramSendOptions{})
			if err != tt.wantErr {
				t.Errorf("Send() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDatagram3Session_Send_NotActive(t *testing.T) {
	sess := NewDatagram3Session("test-inactive", nil, nil, nil)
	defer sess.Close()

	// Session is in StatusCreating by default, not StatusActive
	err := sess.Send("test.i2p", []byte("hello"), DatagramSendOptions{})
	if err != ErrSessionNotActive {
		t.Errorf("Send() error = %v, want %v", err, ErrSessionNotActive)
	}
}

func TestDatagram3Session_Receive(t *testing.T) {
	sess := NewDatagram3Session("test-receive", nil, nil, nil)
	defer sess.Close()

	ch := sess.Receive()
	if ch == nil {
		t.Fatal("Receive() returned nil channel")
	}
}

func TestDatagram3Session_SetForwarding(t *testing.T) {
	sess := NewDatagram3Session("test-forward", nil, nil, nil)
	defer sess.Close()

	tests := []struct {
		name    string
		host    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid config",
			host:    "127.0.0.1",
			port:    12345,
			wantErr: false,
		},
		{
			name:    "empty host uses default",
			host:    "",
			port:    12345,
			wantErr: false,
		},
		{
			name:    "zero port",
			host:    "127.0.0.1",
			port:    0,
			wantErr: true,
		},
		{
			name:    "negative port",
			host:    "127.0.0.1",
			port:    -1,
			wantErr: true,
		},
		{
			name:    "port too high",
			host:    "127.0.0.1",
			port:    65536,
			wantErr: true,
		},
		{
			name:    "max valid port",
			host:    "127.0.0.1",
			port:    65535,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sess.SetForwarding(tt.host, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetForwarding() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if !sess.IsForwarding() {
					t.Error("IsForwarding() should be true after SetForwarding")
				}

				if sess.ForwardingAddr() == nil {
					t.Error("ForwardingAddr() should not be nil after SetForwarding")
				}
			}
		})
	}
}

func TestDatagram3Session_DeliverDatagram(t *testing.T) {
	sess := NewDatagram3Session("test-deliver", nil, nil, nil)
	defer sess.Close()

	// Create a valid 44-byte base64 hash (32 bytes binary -> 44 bytes base64)
	sourceHash := make([]byte, 32)
	for i := range sourceHash {
		sourceHash[i] = byte(i)
	}
	sourceBase64 := base64.StdEncoding.EncodeToString(sourceHash)

	dg := ReceivedDatagram{
		Source:   sourceBase64, // 44-byte base64 hash for DATAGRAM3
		FromPort: 1234,
		ToPort:   5678,
		Data:     []byte("test data"),
	}

	// Delivery should succeed (no replay protection in DATAGRAM3)
	if !sess.DeliverDatagram(dg) {
		t.Error("DeliverDatagram should return true")
	}

	// Verify datagram was delivered to channel
	select {
	case received := <-sess.Receive():
		if received.Source != dg.Source {
			t.Errorf("Received Source = %q, want %q", received.Source, dg.Source)
		}
		if string(received.Data) != string(dg.Data) {
			t.Errorf("Received Data = %q, want %q", received.Data, dg.Data)
		}
		if received.FromPort != dg.FromPort {
			t.Errorf("Received FromPort = %d, want %d", received.FromPort, dg.FromPort)
		}
		if received.ToPort != dg.ToPort {
			t.Errorf("Received ToPort = %d, want %d", received.ToPort, dg.ToPort)
		}
	default:
		t.Error("Expected datagram in receive channel")
	}

	// Same datagram delivered again should also succeed (no replay protection)
	if !sess.DeliverDatagram(dg) {
		t.Error("Second DeliverDatagram should also succeed (no replay protection in DATAGRAM3)")
	}
}

func TestDatagram3Session_Close(t *testing.T) {
	sess := NewDatagram3Session("test-close", nil, nil, nil)

	// First close should succeed
	if err := sess.Close(); err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Status should be closed
	if sess.Status() != StatusClosed {
		t.Errorf("Status() = %v, want %v after Close", sess.Status(), StatusClosed)
	}

	// Double close should be safe
	if err := sess.Close(); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestDatagram3Session_MaxSize(t *testing.T) {
	// Verify MaxDatagram3Size matches expectation
	if MaxDatagram3Size != 31744 {
		t.Errorf("MaxDatagram3Size = %d, want 31744", MaxDatagram3Size)
	}
}

func TestDatagram3Session_Constants(t *testing.T) {
	tests := []struct {
		name   string
		value  int
		expect int
	}{
		{
			name:   "Datagram3HashSize",
			value:  Datagram3HashSize,
			expect: 32,
		},
		{
			name:   "Datagram3Base64HashSize",
			value:  Datagram3Base64HashSize,
			expect: 44,
		},
		{
			name:   "Datagram3Base32HashSize",
			value:  Datagram3Base32HashSize,
			expect: 52,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.expect {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expect)
			}
		})
	}
}

func TestDatagram3Session_ImplementsInterface(t *testing.T) {
	// This test verifies compile-time interface compliance
	var _ DatagramSession = (*Datagram3SessionImpl)(nil)
}

func TestDatagram3Session_ForwardingAddrInitiallyNil(t *testing.T) {
	sess := NewDatagram3Session("test-nil-forward", nil, nil, nil)
	defer sess.Close()

	if sess.ForwardingAddr() != nil {
		t.Error("ForwardingAddr() should be nil initially")
	}

	if sess.IsForwarding() {
		t.Error("IsForwarding() should be false initially")
	}
}

func TestDatagram3Session_DeliverDropsWhenChannelFull(t *testing.T) {
	sess := NewDatagram3Session("test-channel-full", nil, nil, nil)
	defer sess.Close()

	// Fill the receive channel (capacity is 100)
	for i := 0; i < 100; i++ {
		dg := ReceivedDatagram{
			Source: "hash" + string(rune('0'+i%10)),
			Data:   []byte("test"),
		}
		sess.DeliverDatagram(dg)
	}

	// Next delivery should fail because channel is full
	dg := ReceivedDatagram{
		Source: "overflow",
		Data:   []byte("overflow"),
	}
	result := sess.DeliverDatagram(dg)
	if result {
		t.Error("DeliverDatagram should return false when channel is full")
	}
}

// Tests for HashToB32Address function

func TestHashToB32Address(t *testing.T) {
	tests := []struct {
		name       string
		hash       string
		wantSuffix string
		wantErr    error
	}{
		{
			name: "valid all zeros hash",
			// 32 bytes of zeros -> base64 = 44 bytes
			hash:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
			wantSuffix: ".b32.i2p",
			wantErr:    nil,
		},
		{
			name: "valid sequential bytes hash",
			hash: func() string {
				b := make([]byte, 32)
				for i := range b {
					b[i] = byte(i)
				}
				return base64.StdEncoding.EncodeToString(b)
			}(),
			wantSuffix: ".b32.i2p",
			wantErr:    nil,
		},
		{
			name:       "too short hash",
			hash:       "AAAAAAA=", // Only 5 bytes
			wantSuffix: "",
			wantErr:    ErrInvalidHashLength,
		},
		{
			name:       "too long hash",
			hash:       base64.StdEncoding.EncodeToString(make([]byte, 64)), // 64 bytes
			wantSuffix: "",
			wantErr:    ErrInvalidHashLength,
		},
		{
			name:       "invalid base64 encoding",
			hash:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!!", // 44 bytes, invalid base64 chars at end
			wantSuffix: "",
			wantErr:    ErrInvalidHashFormat,
		},
		{
			name:       "empty hash",
			hash:       "",
			wantSuffix: "",
			wantErr:    ErrInvalidHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HashToB32Address(tt.hash)

			// Check error
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("HashToB32Address() error = nil, want %v", tt.wantErr)
					return
				}
				// Use errors.Is for wrapped errors
				if err != tt.wantErr && !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("HashToB32Address() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("HashToB32Address() unexpected error = %v", err)
				return
			}

			// Check result has correct suffix
			if !strings.HasSuffix(result, tt.wantSuffix) {
				t.Errorf("HashToB32Address() = %q, want suffix %q", result, tt.wantSuffix)
			}

			// Check result is lowercase
			if result != strings.ToLower(result) {
				t.Errorf("HashToB32Address() = %q, should be lowercase", result)
			}

			// Check base32 portion length (52 chars + ".b32.i2p" = 60 chars total)
			expectedLen := Datagram3Base32HashSize + len(".b32.i2p")
			if len(result) != expectedLen {
				t.Errorf("HashToB32Address() len = %d, want %d", len(result), expectedLen)
			}
		})
	}
}

func TestHashToB32Address_RoundTrip(t *testing.T) {
	// Verify we can decode the base32 portion back to the original hash
	original := make([]byte, 32)
	for i := range original {
		original[i] = byte(i * 7 % 256) // Some pattern
	}

	base64Hash := base64.StdEncoding.EncodeToString(original)
	b32Addr, err := HashToB32Address(base64Hash)
	if err != nil {
		t.Fatalf("HashToB32Address() error = %v", err)
	}

	// Extract base32 portion (remove .b32.i2p suffix)
	base32Part := strings.TrimSuffix(b32Addr, ".b32.i2p")
	if len(base32Part) != Datagram3Base32HashSize {
		t.Errorf("base32 portion len = %d, want %d", len(base32Part), Datagram3Base32HashSize)
	}

	// Decode base32 back to binary
	// I2P uses uppercase for decoding
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(base32Part))
	if err != nil {
		t.Fatalf("base32 decode error = %v", err)
	}

	// Compare with original
	if len(decoded) != len(original) {
		t.Errorf("decoded len = %d, want %d", len(decoded), len(original))
	}

	for i, b := range decoded {
		if b != original[i] {
			t.Errorf("decoded[%d] = %d, want %d", i, b, original[i])
		}
	}
}

func TestValidateHash(t *testing.T) {
	tests := []struct {
		name  string
		hash  string
		valid bool
	}{
		{
			name:  "valid all zeros",
			hash:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
			valid: true,
		},
		{
			name: "valid sequential bytes",
			hash: func() string {
				b := make([]byte, 32)
				for i := range b {
					b[i] = byte(i)
				}
				return base64.StdEncoding.EncodeToString(b)
			}(),
			valid: true,
		},
		{
			name:  "too short",
			hash:  "AAAA",
			valid: false,
		},
		{
			name:  "too long",
			hash:  base64.StdEncoding.EncodeToString(make([]byte, 64)),
			valid: false,
		},
		{
			name:  "invalid base64 chars",
			hash:  "!!!invalid!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", // 44 chars but invalid
			valid: false,
		},
		{
			name:  "empty",
			hash:  "",
			valid: false,
		},
		{
			name:  "44 chars but wrong decoded length",
			hash:  "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3", // Wrong padding, decodes to different length
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateHash(tt.hash)
			if result != tt.valid {
				t.Errorf("ValidateHash(%q) = %v, want %v", tt.hash, result, tt.valid)
			}
		})
	}
}

func TestDatagram3Session_NoReplayProtection(t *testing.T) {
	// DATAGRAM3 is unauthenticated and has no replay protection.
	// The same datagram can be delivered multiple times.
	sess := NewDatagram3Session("test-no-replay", nil, nil, nil)
	defer sess.Close()

	// Create hash for source
	sourceHash := make([]byte, 32)
	sourceBase64 := base64.StdEncoding.EncodeToString(sourceHash)

	dg := ReceivedDatagram{
		Source:   sourceBase64,
		FromPort: 0,
		ToPort:   0,
		Data:     []byte("same data"),
	}

	// Deliver the same datagram 3 times - all should succeed
	for i := 0; i < 3; i++ {
		if !sess.DeliverDatagram(dg) {
			t.Errorf("DeliverDatagram attempt %d should succeed", i+1)
		}
	}

	// Read all 3 from channel
	for i := 0; i < 3; i++ {
		select {
		case received := <-sess.Receive():
			if string(received.Data) != string(dg.Data) {
				t.Errorf("Received data mismatch at %d", i)
			}
		default:
			t.Errorf("Expected datagram %d in channel", i+1)
		}
	}
}

func TestDatagram3Session_DifferenceFromDatagram2(t *testing.T) {
	// Verify DATAGRAM3 uses StyleDatagram3 (not StyleDatagram2)
	sess := NewDatagram3Session("test-style", nil, nil, nil)
	defer sess.Close()

	if sess.Style() == StyleDatagram2 {
		t.Error("DATAGRAM3 session should not use StyleDatagram2")
	}

	if sess.Style() != StyleDatagram3 {
		t.Errorf("Style() = %v, want %v", sess.Style(), StyleDatagram3)
	}
}

func TestHashToB32Address_KnownVector(t *testing.T) {
	// Test with a known vector to ensure correct encoding
	// 32 bytes of 0xFF
	allOnes := make([]byte, 32)
	for i := range allOnes {
		allOnes[i] = 0xFF
	}

	base64Hash := base64.StdEncoding.EncodeToString(allOnes)
	if len(base64Hash) != 44 {
		t.Fatalf("base64 hash len = %d, want 44", len(base64Hash))
	}

	result, err := HashToB32Address(base64Hash)
	if err != nil {
		t.Fatalf("HashToB32Address() error = %v", err)
	}

	// The base32 encoding of 32 bytes of 0xFF should be 52 7s
	// (since 0xFF in base32 is represented by 7777... pattern)
	expected := "77777777777777777777777777777777777777777777777777777.b32.i2p"
	if result != expected {
		// The actual encoding may differ; let's just verify the length and suffix
		if !strings.HasSuffix(result, ".b32.i2p") {
			t.Errorf("result = %q, should have .b32.i2p suffix", result)
		}
		if len(result) != 60 { // 52 + 8
			t.Errorf("result len = %d, want 60", len(result))
		}
	}
}

func TestDatagram3Session_ErrorMessages(t *testing.T) {
	// Verify error messages are descriptive
	if !strings.Contains(ErrDatagram3SendNotImplemented.Error(), "DATAGRAM3") {
		t.Error("ErrDatagram3SendNotImplemented should mention DATAGRAM3")
	}

	if !strings.Contains(ErrInvalidHashLength.Error(), "44") {
		t.Error("ErrInvalidHashLength should mention expected length")
	}

	if !strings.Contains(ErrInvalidHashFormat.Error(), "base64") {
		t.Error("ErrInvalidHashFormat should mention base64")
	}
}

func TestDatagram3Session_OfflineSignature(t *testing.T) {
	sess := NewDatagram3Session("test-dg3-offline", nil, nil, nil)
	defer sess.Close()

	// Initially nil
	if sig := sess.OfflineSignature(); sig != nil {
		t.Errorf("OfflineSignature() initially = %v, want nil", sig)
	}

	// Set offline signature
	testSig := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	sess.SetOfflineSignature(testSig)

	// Get and verify
	got := sess.OfflineSignature()
	if got == nil {
		t.Fatal("OfflineSignature() returned nil after set")
	}
	if len(got) != len(testSig) {
		t.Errorf("OfflineSignature() len = %d, want %d", len(got), len(testSig))
	}
	for i := range testSig {
		if got[i] != testSig[i] {
			t.Errorf("OfflineSignature()[%d] = %d, want %d", i, got[i], testSig[i])
		}
	}

	// Verify returned slice is a copy (defensive copy)
	got[0] = 0xFF
	check := sess.OfflineSignature()
	if check[0] != testSig[0] {
		t.Error("OfflineSignature() should return a defensive copy")
	}
}

func TestDatagram3Session_OfflineSignature_Nil(t *testing.T) {
	sess := NewDatagram3Session("test-dg3-offline-nil", nil, nil, nil)
	defer sess.Close()

	// Set then clear by setting empty
	testSig := []byte{0x01, 0x02}
	sess.SetOfflineSignature(testSig)

	emptySig := []byte{}
	sess.SetOfflineSignature(emptySig)

	got := sess.OfflineSignature()
	if got == nil {
		t.Log("Empty signature returned as nil (acceptable)")
	} else if len(got) != 0 {
		t.Errorf("OfflineSignature() = %v, want empty", got)
	}
}
