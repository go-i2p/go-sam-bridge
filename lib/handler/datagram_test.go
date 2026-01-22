package handler

import (
	"net"
	"strings"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockDatagramSession implements session.DatagramSession for testing
type mockDatagramSession struct {
	*session.BaseSession
	sendErr        error
	lastSendDest   string
	lastSendData   []byte
	lastSendOpts   session.DatagramSendOptions
	forwardingAddr net.Addr
}

func newMockDatagramSession(id string) *mockDatagramSession {
	return &mockDatagramSession{
		BaseSession: session.NewBaseSession(id, session.StyleDatagram, nil, nil, nil),
	}
}

func (m *mockDatagramSession) Send(dest string, data []byte, opts session.DatagramSendOptions) error {
	m.lastSendDest = dest
	m.lastSendData = data
	m.lastSendOpts = opts
	return m.sendErr
}

func (m *mockDatagramSession) Receive() <-chan session.ReceivedDatagram {
	return make(chan session.ReceivedDatagram)
}

func (m *mockDatagramSession) ForwardingAddr() net.Addr {
	return m.forwardingAddr
}

func TestDatagramHandler_Handle(t *testing.T) {
	handler := NewDatagramHandler()

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
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: false,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "no session bound",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
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
			name: "session not DATAGRAM style",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
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
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"SIZE": "5",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "missing SIZE",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - non-numeric",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "abc",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - zero",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "0",
				},
				Payload: []byte{},
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - negative",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "-1",
				},
				Payload: []byte{},
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid SIZE - exceeds maximum",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "40000", // > MaxDatagramSize (31744)
				},
				Payload: make([]byte, 40000),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid FROM_PORT - too large",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"FROM_PORT":   "99999",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid TO_PORT - negative",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"TO_PORT":     "-1",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "invalid FROM_PORT - non-numeric",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
					"FROM_PORT":   "abc",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		{
			name: "payload size mismatch",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: protocol.ActionSend,
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "10",
				},
				Payload: []byte("hello"), // only 5 bytes, not 10
			},
			session:       newMockDatagramSession("test"),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "unknown action",
			command: &protocol.Command{
				Verb:   protocol.VerbDatagram,
				Action: "UNKNOWN",
				Options: map[string]string{
					"DESTINATION": "test.i2p",
					"SIZE":        "5",
				},
				Payload: []byte("hello"),
			},
			session:       newMockDatagramSession("test"),
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

func TestDatagramHandler_HandleSend_Success(t *testing.T) {
	handler := NewDatagramHandler()
	mockSess := newMockDatagramSession("test-datagram")

	// Test basic successful send (returns nil on success per SAM spec)
	cmd := &protocol.Command{
		Verb:   protocol.VerbDatagram,
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

	// Mock session doesn't return error, so expect nil response (success)
	if resp != nil {
		t.Errorf("Handle() = %v, want nil for success", resp)
	}

	// Verify send was called with correct parameters
	if mockSess.lastSendDest != "test.i2p" {
		t.Errorf("Send() dest = %q, want %q", mockSess.lastSendDest, "test.i2p")
	}
	if string(mockSess.lastSendData) != "hello" {
		t.Errorf("Send() data = %q, want %q", mockSess.lastSendData, "hello")
	}
}

func TestDatagramHandler_HandleSend_WithOptions(t *testing.T) {
	handler := NewDatagramHandler()
	mockSess := newMockDatagramSession("test-datagram")

	// Test with FROM_PORT and TO_PORT options
	cmd := &protocol.Command{
		Verb:   protocol.VerbDatagram,
		Action: protocol.ActionSend,
		Options: map[string]string{
			"DESTINATION": "test.i2p",
			"SIZE":        "5",
			"FROM_PORT":   "1234",
			"TO_PORT":     "5678",
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

	// Mock session doesn't return error, so expect nil response (success)
	if resp != nil {
		t.Errorf("Handle() = %v, want nil for success", resp)
	}

	// Verify options were parsed correctly
	if mockSess.lastSendOpts.FromPort != 1234 {
		t.Errorf("Send() FromPort = %d, want %d", mockSess.lastSendOpts.FromPort, 1234)
	}
	if mockSess.lastSendOpts.ToPort != 5678 {
		t.Errorf("Send() ToPort = %d, want %d", mockSess.lastSendOpts.ToPort, 5678)
	}
}

func TestDatagramHandler_HandleSend_WithSAM33Options(t *testing.T) {
	handler := NewDatagramHandler()
	mockSess := newMockDatagramSession("test-datagram")

	// Test with SAM 3.3 options (parsed but not yet fully implemented)
	cmd := &protocol.Command{
		Verb:   protocol.VerbDatagram,
		Action: protocol.ActionSend,
		Options: map[string]string{
			"DESTINATION":   "test.i2p",
			"SIZE":          "5",
			"SEND_TAGS":     "10",
			"TAG_THRESHOLD": "5",
			"EXPIRES":       "3600",
			"SEND_LEASESET": "true",
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

	// Should succeed even with SAM 3.3 options (they're parsed but unused currently)
	if resp != nil {
		t.Errorf("Handle() = %v, want nil for success", resp)
	}
}

func TestDatagramHandler_HandleSend_SendError(t *testing.T) {
	handler := NewDatagramHandler()
	mockSess := newMockDatagramSession("test-datagram")
	mockSess.sendErr = session.ErrDatagramSendNotImplemented

	cmd := &protocol.Command{
		Verb:   protocol.VerbDatagram,
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

	if resp == nil {
		t.Fatal("Handle() returned nil, want error response")
	}

	respStr := resp.String()
	if !strings.Contains(respStr, "RESULT="+protocol.ResultI2PError) {
		t.Errorf("Handle() = %q, want RESULT=%s", respStr, protocol.ResultI2PError)
	}
	if !strings.Contains(respStr, "send failed") {
		t.Errorf("Handle() = %q, want message containing 'send failed'", respStr)
	}
}

func TestParseDatagramPort(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		want    int
		wantErr bool
	}{
		{"0", "PORT", 0, false},
		{"1234", "PORT", 1234, false},
		{"65535", "PORT", 65535, false},
		{"", "PORT", 0, true},      // empty
		{"-1", "PORT", 0, true},    // negative
		{"65536", "PORT", 0, true}, // too large
		{"abc", "PORT", 0, true},   // non-numeric
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseDatagramPort(tt.input, tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDatagramPort(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDatagramPort(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatDatagramReceived(t *testing.T) {
	// Test SAM 3.2+ (with ports)
	t.Run("SAM 3.2+ includes ports", func(t *testing.T) {
		tests := []struct {
			name    string
			dg      session.ReceivedDatagram
			version string
			want    string
		}{
			{
				name: "basic datagram 3.2",
				dg: session.ReceivedDatagram{
					Source:   "test-destination.i2p",
					Data:     []byte("hello"),
					FromPort: 0,
					ToPort:   0,
				},
				version: "3.2",
				want:    "DATAGRAM RECEIVED DESTINATION=test-destination.i2p SIZE=5 FROM_PORT=0 TO_PORT=0",
			},
			{
				name: "with ports 3.3",
				dg: session.ReceivedDatagram{
					Source:   "sender.i2p",
					Data:     []byte("test message"),
					FromPort: 1234,
					ToPort:   5678,
				},
				version: "3.3",
				want:    "DATAGRAM RECEIVED DESTINATION=sender.i2p SIZE=12 FROM_PORT=1234 TO_PORT=5678",
			},
			{
				name: "empty version defaults to include ports",
				dg: session.ReceivedDatagram{
					Source:   "empty-version.i2p",
					Data:     []byte("x"),
					FromPort: 100,
					ToPort:   200,
				},
				version: "",
				want:    "DATAGRAM RECEIVED DESTINATION=empty-version.i2p SIZE=1 FROM_PORT=100 TO_PORT=200",
			},
			{
				name: "max ports",
				dg: session.ReceivedDatagram{
					Source:   "maxports.i2p",
					Data:     []byte("x"),
					FromPort: 65535,
					ToPort:   65535,
				},
				version: "3.2",
				want:    "DATAGRAM RECEIVED DESTINATION=maxports.i2p SIZE=1 FROM_PORT=65535 TO_PORT=65535",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := FormatDatagramReceived(tt.dg, tt.version)
				if got != tt.want {
					t.Errorf("FormatDatagramReceived() = %q, want %q", got, tt.want)
				}
			})
		}
	})

	// Test SAM 3.0/3.1 (without ports)
	t.Run("SAM 3.0/3.1 excludes ports", func(t *testing.T) {
		tests := []struct {
			name    string
			dg      session.ReceivedDatagram
			version string
			want    string
		}{
			{
				name: "SAM 3.0 no ports",
				dg: session.ReceivedDatagram{
					Source:   "test.i2p",
					Data:     []byte("hello"),
					FromPort: 1234,
					ToPort:   5678,
				},
				version: "3.0",
				want:    "DATAGRAM RECEIVED DESTINATION=test.i2p SIZE=5",
			},
			{
				name: "SAM 3.1 no ports",
				dg: session.ReceivedDatagram{
					Source:   "sender.i2p",
					Data:     []byte("test"),
					FromPort: 100,
					ToPort:   200,
				},
				version: "3.1",
				want:    "DATAGRAM RECEIVED DESTINATION=sender.i2p SIZE=4",
			},
			{
				name: "empty data SAM 3.0",
				dg: session.ReceivedDatagram{
					Source:   "empty.i2p",
					Data:     []byte{},
					FromPort: 0,
					ToPort:   0,
				},
				version: "3.0",
				want:    "DATAGRAM RECEIVED DESTINATION=empty.i2p SIZE=0",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := FormatDatagramReceived(tt.dg, tt.version)
				if got != tt.want {
					t.Errorf("FormatDatagramReceived() = %q, want %q", got, tt.want)
				}
			})
		}
	})
}

func TestFormatDatagramForward(t *testing.T) {
	tests := []struct {
		name string
		dg   session.ReceivedDatagram
		want string
	}{
		{
			name: "basic forward",
			dg: session.ReceivedDatagram{
				Source:   "sender-destination.i2p",
				Data:     []byte("test"),
				FromPort: 1234,
				ToPort:   5678,
			},
			want: "sender-destination.i2p",
		},
		{
			name: "long destination",
			dg: session.ReceivedDatagram{
				Source:   "verylong-destination-name-for-testing-purposes.i2p",
				Data:     []byte{},
				FromPort: 0,
				ToPort:   0,
			},
			want: "verylong-destination-name-for-testing-purposes.i2p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDatagramForward(tt.dg)
			if got != tt.want {
				t.Errorf("FormatDatagramForward() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDatagramError(t *testing.T) {
	resp := datagramError("test error message")
	if resp == nil {
		t.Fatal("datagramError() returned nil")
	}

	respStr := resp.String()
	if !strings.Contains(respStr, "DATAGRAM STATUS") {
		t.Errorf("datagramError() = %q, want DATAGRAM STATUS", respStr)
	}
	if !strings.Contains(respStr, "RESULT="+protocol.ResultI2PError) {
		t.Errorf("datagramError() = %q, want RESULT=%s", respStr, protocol.ResultI2PError)
	}
	if !strings.Contains(respStr, "test error message") {
		t.Errorf("datagramError() = %q, want message 'test error message'", respStr)
	}
}

func TestDatagramInvalidKey(t *testing.T) {
	resp := datagramInvalidKey("invalid parameter")
	if resp == nil {
		t.Fatal("datagramInvalidKey() returned nil")
	}

	respStr := resp.String()
	if !strings.Contains(respStr, "DATAGRAM STATUS") {
		t.Errorf("datagramInvalidKey() = %q, want DATAGRAM STATUS", respStr)
	}
	if !strings.Contains(respStr, "RESULT="+protocol.ResultInvalidKey) {
		t.Errorf("datagramInvalidKey() = %q, want RESULT=%s", respStr, protocol.ResultInvalidKey)
	}
	if !strings.Contains(respStr, "invalid parameter") {
		t.Errorf("datagramInvalidKey() = %q, want message 'invalid parameter'", respStr)
	}
}

func TestNewDatagramHandler(t *testing.T) {
	h := NewDatagramHandler()
	if h == nil {
		t.Fatal("NewDatagramHandler() returned nil")
	}
}

func TestRegisterDatagramHandler(t *testing.T) {
	router := NewRouter()

	// Should not panic
	RegisterDatagramHandler(router)

	// Verify handler is registered
	cmd := &protocol.Command{
		Verb:   protocol.VerbDatagram,
		Action: protocol.ActionSend,
	}

	h := router.Route(cmd)
	if h == nil {
		t.Fatal("RegisterDatagramHandler() did not register handler")
	}
}

// TestDatagramHandler_RejectPrimarySession verifies DATAGRAM SEND is rejected on PRIMARY sessions.
// Per SAMv3.md: "v1/v2 datagram/raw sending/receiving are not supported on a primary session"
func TestDatagramHandler_RejectPrimarySession(t *testing.T) {
	handler := NewDatagramHandler()

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
		Verb:   protocol.VerbDatagram,
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
