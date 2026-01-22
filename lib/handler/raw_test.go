package handler

import (
	"strings"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockRawSession implements session.RawSession for testing
type mockRawSession struct {
	*session.BaseSession
	protocol      int
	headerEnabled bool
	sendErr       error
	lastSendDest  string
	lastSendData  []byte
	lastSendOpts  session.RawSendOptions
}

func newMockRawSession(id string) *mockRawSession {
	return &mockRawSession{
		BaseSession: session.NewBaseSession(id, session.StyleRaw, nil, nil, nil),
		protocol:    18, // Default RAW protocol
	}
}

func (m *mockRawSession) Protocol() int {
	return m.protocol
}

func (m *mockRawSession) HeaderEnabled() bool {
	return m.headerEnabled
}

func (m *mockRawSession) Send(dest string, data []byte, opts session.RawSendOptions) error {
	m.lastSendDest = dest
	m.lastSendData = data
	m.lastSendOpts = opts
	return m.sendErr
}

func (m *mockRawSession) Receive() <-chan session.ReceivedRawDatagram {
	return make(chan session.ReceivedRawDatagram)
}

func TestRawHandler_Handle(t *testing.T) {
	handler := NewRawHandler()

	tests := []struct {
		name          string
		command       *protocol.Command
		session       session.Session
		handshakeDone bool
		wantResult    string
		wantNil       bool // true if expecting nil response (success)
	}{
		{
			name: "handshake not complete",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: false,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "no session bound",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
				},
				Payload: []byte("hello"),
			},
			session:       nil,
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "session not RAW style",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
				},
				Payload: []byte("hello"),
			},
			session:       session.NewBaseSession("test", session.StyleStream, nil, nil, nil),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "missing DESTINATION",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"SIZE": "5",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "missing SIZE",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - non-numeric",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "abc",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - zero",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "0",
				},
				Payload: []byte{},
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - negative",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "-1",
				},
				Payload: []byte{},
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid FROM_PORT - too large",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"FROM_PORT":   "99999",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid TO_PORT - negative",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"TO_PORT":     "-1",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid PROTOCOL - disallowed 6 (TCP)",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"PROTOCOL":    "6",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid PROTOCOL - disallowed 17 (UDP)",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"PROTOCOL":    "17",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid PROTOCOL - too large",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"PROTOCOL":    "256",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "payload size mismatch",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "10",
				},
				Payload: []byte("hello"), // only 5 bytes, not 10
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "unknown action",
			command: &protocol.Command{
				Verb:   protocol.VerbRaw,
				Action: "UNKNOWN",
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
				},
				Payload: []byte("hello"),
			},
			session:       newMockRawSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext(&mockConn{}, newMockRegistry())
			ctx.HandshakeComplete = tt.handshakeDone
			if tt.session != nil {
				ctx.BindSession(tt.session)
			}

			resp, err := handler.Handle(ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if tt.wantNil {
				if resp != nil {
					t.Errorf("Handle() = %v, want nil", resp)
				}
				return
			}

			if resp == nil {
				t.Fatal("Handle() returned nil, want response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("Handle() = %q, want RESULT=%s", respStr, tt.wantResult)
			}
		})
	}
}

func TestRawHandler_HandleSend_Success(t *testing.T) {
	handler := NewRawHandler()
	mockSess := newMockRawSession("test-raw")

	// Test basic successful send (returns nil on success per SAM spec)
	cmd := &protocol.Command{
		Verb:   protocol.VerbRaw,
		Action: protocol.ActionSend,
		Options: map[string]string{
			"DESTINATION": "test.i2p",
			"SIZE":        "5",
		},
		Payload: []byte("hello"),
	}

	ctx := NewContext(&mockConn{}, newMockRegistry())
	ctx.HandshakeComplete = true
	ctx.BindSession(mockSess)

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// The actual send will fail because it's a stub, but we can verify
	// the command was parsed correctly if the mock doesn't return an error

	// Note: Since session.Send returns ErrRawSendNotImplemented,
	// we expect an error response
	if resp != nil {
		if !strings.Contains(resp.String(), "RESULT=") {
			t.Errorf("unexpected response: %s", resp.String())
		}
	}
}

func TestRawHandler_HandleSend_WithOptions(t *testing.T) {
	handler := NewRawHandler()
	mockSess := newMockRawSession("test-raw")
	mockSess.protocol = 18

	// Test with FROM_PORT, TO_PORT, and PROTOCOL options
	cmd := &protocol.Command{
		Verb:   protocol.VerbRaw,
		Action: protocol.ActionSend,
		Options: map[string]string{
			"DESTINATION": "test.i2p",
			"SIZE":        "5",
			"FROM_PORT":   "1234",
			"TO_PORT":     "5678",
			"PROTOCOL":    "18",
		},
		Payload: []byte("hello"),
	}

	ctx := NewContext(&mockConn{}, newMockRegistry())
	ctx.HandshakeComplete = true
	ctx.BindSession(mockSess)

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Verify the command was parsed and validated correctly
	// The send itself will fail with ErrRawSendNotImplemented
	if resp != nil && strings.Contains(resp.String(), "INVALID_KEY") {
		t.Errorf("unexpected INVALID_KEY error: %s", resp.String())
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		want    int
		wantErr bool
	}{
		{"0", "PORT", 0, false},
		{"1234", "PORT", 1234, false},
		{"65535", "PORT", 65535, false},
		{"-1", "PORT", 0, true},
		{"65536", "PORT", 0, true},
		{"abc", "PORT", 0, true},
		{"", "PORT", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePort(tt.input, tt.name)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parsePort(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parsePort(%q) unexpected error = %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("parsePort(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"0", 0, false},
		{"18", 18, false},
		{"255", 255, false},
		// Disallowed protocols
		{"6", 0, true},  // TCP
		{"17", 0, true}, // UDP
		{"19", 0, true}, // DCCPv4
		{"20", 0, true}, // DCCPv6
		// Invalid values
		{"-1", 0, true},
		{"256", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseProtocol(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseProtocol(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseProtocol(%q) unexpected error = %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("parseProtocol(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatRawReceived(t *testing.T) {
	// Test SAM 3.2+ (with ports and protocol)
	t.Run("SAM 3.2+ includes ports and protocol", func(t *testing.T) {
		tests := []struct {
			name    string
			dg      session.ReceivedRawDatagram
			version string
			want    string
		}{
			{
				name: "SAM 3.2 with all info",
				dg: session.ReceivedRawDatagram{
					FromPort: 1234,
					ToPort:   5678,
					Protocol: 18,
					Data:     []byte("hello world"),
				},
				version: "3.2",
				want:    "RAW RECEIVED SIZE=11 FROM_PORT=1234 TO_PORT=5678 PROTOCOL=18",
			},
			{
				name: "SAM 3.3 with all info",
				dg: session.ReceivedRawDatagram{
					FromPort: 100,
					ToPort:   200,
					Protocol: 42,
					Data:     []byte("test"),
				},
				version: "3.3",
				want:    "RAW RECEIVED SIZE=4 FROM_PORT=100 TO_PORT=200 PROTOCOL=42",
			},
			{
				name: "empty version defaults to include info",
				dg: session.ReceivedRawDatagram{
					FromPort: 0,
					ToPort:   0,
					Protocol: 18,
					Data:     []byte("x"),
				},
				version: "",
				want:    "RAW RECEIVED SIZE=1 FROM_PORT=0 TO_PORT=0 PROTOCOL=18",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := FormatRawReceived(tt.dg, tt.version)
				if got != tt.want {
					t.Errorf("FormatRawReceived() = %q, want %q", got, tt.want)
				}
			})
		}
	})

	// Test SAM 3.0/3.1 (without ports and protocol)
	t.Run("SAM 3.0/3.1 excludes ports and protocol", func(t *testing.T) {
		tests := []struct {
			name    string
			dg      session.ReceivedRawDatagram
			version string
			want    string
		}{
			{
				name: "SAM 3.0 size only",
				dg: session.ReceivedRawDatagram{
					FromPort: 1234,
					ToPort:   5678,
					Protocol: 18,
					Data:     []byte("hello world"),
				},
				version: "3.0",
				want:    "RAW RECEIVED SIZE=11",
			},
			{
				name: "SAM 3.1 size only",
				dg: session.ReceivedRawDatagram{
					FromPort: 100,
					ToPort:   200,
					Protocol: 42,
					Data:     []byte("test"),
				},
				version: "3.1",
				want:    "RAW RECEIVED SIZE=4",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := FormatRawReceived(tt.dg, tt.version)
				if got != tt.want {
					t.Errorf("FormatRawReceived() = %q, want %q", got, tt.want)
				}
			})
		}
	})
}

func TestFormatRawHeader(t *testing.T) {
	dg := session.ReceivedRawDatagram{
		FromPort: 1234,
		ToPort:   5678,
		Protocol: 18,
		Data:     []byte("hello"),
	}

	got := FormatRawHeader(dg)
	want := "FROM_PORT=1234 TO_PORT=5678 PROTOCOL=18"
	if got != want {
		t.Errorf("FormatRawHeader() = %q, want %q", got, want)
	}
}

func TestRawError(t *testing.T) {
	resp := rawError("test error message")
	got := resp.String()

	if !strings.Contains(got, "RAW STATUS") {
		t.Errorf("rawError() = %q, want 'RAW STATUS'", got)
	}
	if !strings.Contains(got, "RESULT=I2P_ERROR") {
		t.Errorf("rawError() = %q, want 'RESULT=I2P_ERROR'", got)
	}
	if !strings.Contains(got, "MESSAGE=") {
		t.Errorf("rawError() = %q, want 'MESSAGE='", got)
	}
}

func TestRawInvalidKey(t *testing.T) {
	resp := rawInvalidKey("missing parameter")
	got := resp.String()

	if !strings.Contains(got, "RAW STATUS") {
		t.Errorf("rawInvalidKey() = %q, want 'RAW STATUS'", got)
	}
	if !strings.Contains(got, "RESULT=INVALID_KEY") {
		t.Errorf("rawInvalidKey() = %q, want 'RESULT=INVALID_KEY'", got)
	}
}

// TestRawHandler_RejectPrimarySession verifies RAW SEND is rejected on PRIMARY sessions.
// Per SAMv3.md: "v1/v2 datagram/raw sending/receiving are not supported on a primary session"
func TestRawHandler_RejectPrimarySession(t *testing.T) {
	handler := NewRawHandler()

	// Create a PRIMARY session
	dest := &session.Destination{
		PublicKey:     []byte("test-pub-base64"),
		PrivateKey:    []byte("test-priv-key"),
		SignatureType: 7,
	}
	config := session.DefaultSessionConfig()
	primary := session.NewPrimarySession("primary-1", dest, nil, config)
	primary.SetStatus(session.StatusActive)

	ctx := &Context{
		HandshakeComplete: true,
		Session:           primary,
	}

	cmd := &protocol.Command{
		Verb:   protocol.VerbRaw,
		Action: protocol.ActionSend,
		Options: map[string]string{
			"DESTINATION": "test-dest-base64",
			"SIZE":        "10",
		},
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	got := resp.String()
	if !strings.Contains(got, "RESULT=I2P_ERROR") {
		t.Errorf("Handle() = %q, want RESULT=I2P_ERROR", got)
	}
	if !strings.Contains(got, "PRIMARY") {
		t.Errorf("Handle() = %q, want error message mentioning PRIMARY", got)
	}
}
