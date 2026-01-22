package handler

import (
	"errors"
	"strings"
	"testing"

	commondest "github.com/go-i2p/common/destination"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// mockSessionRegistry implements session.Registry for testing
type mockSessionRegistry struct {
	sessions    map[string]session.Session
	registerErr error
}

func newMockRegistry() *mockSessionRegistry {
	return &mockSessionRegistry{
		sessions: make(map[string]session.Session),
	}
}

func (r *mockSessionRegistry) Register(s session.Session) error {
	if r.registerErr != nil {
		return r.registerErr
	}
	if _, exists := r.sessions[s.ID()]; exists {
		return util.ErrDuplicateID
	}
	r.sessions[s.ID()] = s
	return nil
}

func (r *mockSessionRegistry) Unregister(id string) error {
	if _, exists := r.sessions[id]; !exists {
		return util.ErrSessionNotFound
	}
	delete(r.sessions, id)
	return nil
}

func (r *mockSessionRegistry) Get(id string) session.Session {
	return r.sessions[id]
}

func (r *mockSessionRegistry) GetByDestination(destHash string) session.Session {
	return nil
}

func (r *mockSessionRegistry) All() []string {
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	return ids
}

func (r *mockSessionRegistry) Count() int {
	return len(r.sessions)
}

func (r *mockSessionRegistry) Close() error {
	r.sessions = make(map[string]session.Session)
	return nil
}

func (r *mockSessionRegistry) MostRecentByStyle(style session.Style) session.Session {
	// Simple implementation - return nil (no tracking in mock)
	return nil
}

func TestSessionHandler_Handle(t *testing.T) {
	mockDest := &commondest.Destination{}
	mockPrivKey := []byte("test-private-key")

	successManager := &mockManager{
		dest:        mockDest,
		privateKey:  mockPrivKey,
		pubEncoded:  "test-pub-base64",
		privEncoded: "test-priv-base64",
	}

	tests := []struct {
		name          string
		command       *protocol.Command
		manager       *mockManager
		registry      *mockSessionRegistry
		handshakeDone bool
		sessionBound  bool
		wantResult    string
		wantSession   bool
	}{
		{
			name: "successful STREAM session with TRANSIENT",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "test-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful with Ed25519 signature type",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":          "STREAM",
					"ID":             "test-session-2",
					"DESTINATION":    "TRANSIENT",
					"SIGNATURE_TYPE": "7",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "missing handshake",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "test-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: false,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "session already bound",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "test-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			sessionBound:  true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "missing STYLE",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"ID":          "test-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "invalid STYLE",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "INVALID",
					"ID":          "test-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "missing ID",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "ID with whitespace",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "test session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "missing DESTINATION",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "test-session",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "duplicate session ID",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "existing-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager: successManager,
			registry: func() *mockSessionRegistry {
				reg := newMockRegistry()
				reg.registerErr = util.ErrDuplicateID
				return reg
			}(),
			handshakeDone: true,
			wantResult:    protocol.ResultDuplicatedID,
		},
		{
			name: "duplicate destination",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "new-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager: successManager,
			registry: func() *mockSessionRegistry {
				reg := newMockRegistry()
				reg.registerErr = util.ErrDuplicateDest
				return reg
			}(),
			handshakeDone: true,
			wantResult:    protocol.ResultDuplicatedDest,
		},
		{
			name: "key generation failure",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "test-session",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager: &mockManager{
				generateErr: errors.New("generation failed"),
			},
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidKey,
		},
		// RAW session creation tests
		{
			name: "successful RAW session with TRANSIENT",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "RAW",
					"ID":          "raw-session-1",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful RAW session with custom protocol",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "RAW",
					"ID":          "raw-session-2",
					"DESTINATION": "TRANSIENT",
					"PROTOCOL":    "18",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful RAW session with HEADER enabled",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "RAW",
					"ID":          "raw-session-3",
					"DESTINATION": "TRANSIENT",
					"HEADER":      "true",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful RAW session with forwarding",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "RAW",
					"ID":          "raw-session-4",
					"DESTINATION": "TRANSIENT",
					"PORT":        "7655",
					"HOST":        "127.0.0.1",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "RAW session with disallowed protocol 6",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "RAW",
					"ID":          "raw-session-bad-proto",
					"DESTINATION": "TRANSIENT",
					"PROTOCOL":    "6",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "RAW session with disallowed protocol 17",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "RAW",
					"ID":          "raw-session-bad-proto2",
					"DESTINATION": "TRANSIENT",
					"PROTOCOL":    "17",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "successful DATAGRAM session with TRANSIENT",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM",
					"ID":          "datagram-session-1",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful DATAGRAM session with forwarding",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM",
					"ID":          "datagram-session-2",
					"DESTINATION": "TRANSIENT",
					"PORT":        "7655",
					"HOST":        "127.0.0.1",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful DATAGRAM session with port options",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM",
					"ID":          "datagram-session-3",
					"DESTINATION": "TRANSIENT",
					"FROM_PORT":   "1234",
					"TO_PORT":     "5678",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		// DATAGRAM2 session creation tests (SAM 3.3)
		{
			name: "successful DATAGRAM2 session with TRANSIENT",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM2",
					"ID":          "datagram2-session-1",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful DATAGRAM2 session with forwarding",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM2",
					"ID":          "datagram2-session-2",
					"DESTINATION": "TRANSIENT",
					"PORT":        "7655",
					"HOST":        "127.0.0.1",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful DATAGRAM2 session with port options",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM2",
					"ID":          "datagram2-session-3",
					"DESTINATION": "TRANSIENT",
					"FROM_PORT":   "1234",
					"TO_PORT":     "5678",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		// DATAGRAM3 session creation tests (SAM 3.3)
		{
			name: "successful DATAGRAM3 session with TRANSIENT",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM3",
					"ID":          "datagram3-session-1",
					"DESTINATION": "TRANSIENT",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful DATAGRAM3 session with forwarding",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM3",
					"ID":          "datagram3-session-2",
					"DESTINATION": "TRANSIENT",
					"PORT":        "7655",
					"HOST":        "127.0.0.1",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		{
			name: "successful DATAGRAM3 session with port options",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "DATAGRAM3",
					"ID":          "datagram3-session-3",
					"DESTINATION": "TRANSIENT",
					"FROM_PORT":   "1234",
					"TO_PORT":     "5678",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultOK,
			wantSession:   true,
		},
		// Style-specific option validation tests
		{
			name: "STREAM rejects PORT option",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "stream-with-port",
					"DESTINATION": "TRANSIENT",
					"PORT":        "7655",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "STREAM rejects HOST option",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "stream-with-host",
					"DESTINATION": "TRANSIENT",
					"HOST":        "127.0.0.1",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "PRIMARY rejects PORT option",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "PRIMARY",
					"ID":          "primary-with-port",
					"DESTINATION": "TRANSIENT",
					"PORT":        "7655",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "PRIMARY rejects FROM_PORT option",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "PRIMARY",
					"ID":          "primary-with-fromport",
					"DESTINATION": "TRANSIENT",
					"FROM_PORT":   "1234",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name: "PRIMARY rejects PROTOCOL option",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "CREATE",
				Options: map[string]string{
					"STYLE":       "PRIMARY",
					"ID":          "primary-with-protocol",
					"DESTINATION": "TRANSIENT",
					"PROTOCOL":    "18",
				},
			},
			manager:       successManager,
			registry:      newMockRegistry(),
			handshakeDone: true,
			wantResult:    protocol.ResultI2PError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewSessionHandler(tt.manager)
			ctx := NewContext(&mockConn{}, tt.registry)
			ctx.HandshakeComplete = tt.handshakeDone

			if tt.sessionBound {
				// Simulate already bound session
				ctx.Session = session.NewBaseSession("existing", session.StyleStream, nil, nil, nil)
			}

			resp, err := handler.Handle(ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("Handle() = %q, want RESULT=%s", respStr, tt.wantResult)
			}

			if tt.wantSession && ctx.Session == nil {
				t.Error("Handle() did not bind session")
			}

			if tt.wantSession && !strings.Contains(respStr, "DESTINATION=") {
				t.Errorf("Handle() = %q, want DESTINATION=", respStr)
			}
		})
	}
}

func TestSessionHandler_ParseConfig(t *testing.T) {
	handler := NewSessionHandler(&mockManager{})

	tests := []struct {
		name      string
		options   map[string]string
		style     session.Style
		wantErr   bool
		errSubstr string
		check     func(*session.SessionConfig) bool
	}{
		{
			name:    "defaults",
			options: map[string]string{},
			style:   session.StyleStream,
			check: func(c *session.SessionConfig) bool {
				return c.InboundQuantity == 3 && c.OutboundQuantity == 3
			},
		},
		{
			name: "custom tunnel quantities",
			options: map[string]string{
				"inbound.quantity":  "5",
				"outbound.quantity": "5",
			},
			style: session.StyleStream,
			check: func(c *session.SessionConfig) bool {
				return c.InboundQuantity == 5 && c.OutboundQuantity == 5
			},
		},
		{
			name: "custom tunnel lengths",
			options: map[string]string{
				"inbound.length":  "2",
				"outbound.length": "4",
			},
			style: session.StyleStream,
			check: func(c *session.SessionConfig) bool {
				return c.InboundLength == 2 && c.OutboundLength == 4
			},
		},
		{
			name: "valid port options",
			options: map[string]string{
				"FROM_PORT": "1234",
				"TO_PORT":   "5678",
			},
			style: session.StyleStream,
			check: func(c *session.SessionConfig) bool {
				return c.FromPort == 1234 && c.ToPort == 5678
			},
		},
		{
			name: "valid edge port 0",
			options: map[string]string{
				"FROM_PORT": "0",
				"TO_PORT":   "0",
			},
			style: session.StyleStream,
			check: func(c *session.SessionConfig) bool {
				return c.FromPort == 0 && c.ToPort == 0
			},
		},
		{
			name: "valid edge port 65535",
			options: map[string]string{
				"FROM_PORT": "65535",
				"TO_PORT":   "65535",
			},
			style: session.StyleStream,
			check: func(c *session.SessionConfig) bool {
				return c.FromPort == 65535 && c.ToPort == 65535
			},
		},
		{
			name: "invalid FROM_PORT - negative",
			options: map[string]string{
				"FROM_PORT": "-1",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "FROM_PORT",
		},
		{
			name: "invalid FROM_PORT - too large",
			options: map[string]string{
				"FROM_PORT": "99999",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "FROM_PORT",
		},
		{
			name: "invalid FROM_PORT - non-numeric",
			options: map[string]string{
				"FROM_PORT": "notaport",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "FROM_PORT",
		},
		{
			name: "invalid TO_PORT - negative",
			options: map[string]string{
				"TO_PORT": "-1",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "TO_PORT",
		},
		{
			name: "invalid TO_PORT - too large",
			options: map[string]string{
				"TO_PORT": "70000",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "TO_PORT",
		},
		{
			name: "valid RAW protocol",
			options: map[string]string{
				"PROTOCOL": "18",
				"HEADER":   "true",
			},
			style: session.StyleRaw,
			check: func(c *session.SessionConfig) bool {
				return c.Protocol == 18 && c.HeaderEnabled
			},
		},
		{
			name: "invalid PROTOCOL - disallowed 6 (TCP)",
			options: map[string]string{
				"PROTOCOL": "6",
			},
			style:     session.StyleRaw,
			wantErr:   true,
			errSubstr: "PROTOCOL",
		},
		{
			name: "invalid PROTOCOL - disallowed 17 (UDP)",
			options: map[string]string{
				"PROTOCOL": "17",
			},
			style:     session.StyleRaw,
			wantErr:   true,
			errSubstr: "PROTOCOL",
		},
		{
			name: "invalid PROTOCOL - too large",
			options: map[string]string{
				"PROTOCOL": "256",
			},
			style:     session.StyleRaw,
			wantErr:   true,
			errSubstr: "PROTOCOL",
		},
		{
			name: "invalid PROTOCOL - negative",
			options: map[string]string{
				"PROTOCOL": "-1",
			},
			style:     session.StyleRaw,
			wantErr:   true,
			errSubstr: "PROTOCOL",
		},
		{
			name: "PROTOCOL not allowed for STREAM",
			options: map[string]string{
				"PROTOCOL": "18",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "PROTOCOL option is only valid for STYLE=RAW",
		},
		{
			name: "HEADER not allowed for STREAM",
			options: map[string]string{
				"HEADER": "true",
			},
			style:     session.StyleStream,
			wantErr:   true,
			errSubstr: "HEADER option is only valid for STYLE=RAW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &protocol.Command{
				Verb:    "SESSION",
				Action:  "CREATE",
				Options: tt.options,
			}

			config, err := handler.parseConfig(cmd, tt.style)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseConfig() expected error containing %q, got nil", tt.errSubstr)
					return
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("parseConfig() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseConfig() unexpected error = %v", err)
			}
			if !tt.check(config) {
				t.Errorf("parseConfig() returned unexpected config")
			}
		})
	}
}

func TestContainsWhitespace(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", false},
		{"hello world", true},
		{"hello\tworld", true},
		{"hello\nworld", true},
		{"hello\rworld", true},
		{"", false},
		{" ", true},
		{"  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := containsWhitespace(tt.input)
			if got != tt.want {
				t.Errorf("containsWhitespace(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSessionResponses(t *testing.T) {
	t.Run("sessionOK", func(t *testing.T) {
		resp := sessionOK("test-dest")
		got := resp.String()
		if !strings.Contains(got, "SESSION STATUS") {
			t.Errorf("sessionOK() = %q, want 'SESSION STATUS'", got)
		}
		if !strings.Contains(got, "RESULT=OK") {
			t.Errorf("sessionOK() = %q, want 'RESULT=OK'", got)
		}
		if !strings.Contains(got, "DESTINATION=test-dest") {
			t.Errorf("sessionOK() = %q, want 'DESTINATION=test-dest'", got)
		}
	})

	t.Run("sessionDuplicatedID", func(t *testing.T) {
		resp := sessionDuplicatedID()
		got := resp.String()
		if !strings.Contains(got, "RESULT=DUPLICATED_ID") {
			t.Errorf("sessionDuplicatedID() = %q, want 'RESULT=DUPLICATED_ID'", got)
		}
	})

	t.Run("sessionDuplicatedDest", func(t *testing.T) {
		resp := sessionDuplicatedDest()
		got := resp.String()
		if !strings.Contains(got, "RESULT=DUPLICATED_DEST") {
			t.Errorf("sessionDuplicatedDest() = %q, want 'RESULT=DUPLICATED_DEST'", got)
		}
	})

	t.Run("sessionInvalidKey", func(t *testing.T) {
		resp := sessionInvalidKey("bad key")
		got := resp.String()
		if !strings.Contains(got, "RESULT=INVALID_KEY") {
			t.Errorf("sessionInvalidKey() = %q, want 'RESULT=INVALID_KEY'", got)
		}
	})

	t.Run("sessionError", func(t *testing.T) {
		resp := sessionError("test error")
		got := resp.String()
		if !strings.Contains(got, "RESULT=I2P_ERROR") {
			t.Errorf("sessionError() = %q, want 'RESULT=I2P_ERROR'", got)
		}
		if !strings.Contains(got, "MESSAGE=") {
			t.Errorf("sessionError() = %q, want 'MESSAGE='", got)
		}
	})
}

func TestSessionErr(t *testing.T) {
	err := &sessionErr{msg: "test error"}
	if err.Error() != "test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error")
	}
}

// TestSessionHandler_HandleAdd tests SESSION ADD command handling.
func TestSessionHandler_HandleAdd(t *testing.T) {
	mockDest := &commondest.Destination{}
	mockPrivKey := []byte("test-private-key")

	successManager := &mockManager{
		dest:        mockDest,
		privateKey:  mockPrivKey,
		pubEncoded:  "test-pub-base64",
		privEncoded: "test-priv-base64",
	}

	// Create a PRIMARY session for testing
	createPrimarySession := func() *session.PrimarySessionImpl {
		dest := &session.Destination{
			PublicKey:     []byte("test-pub-base64"),
			PrivateKey:    []byte("test-priv-key"),
			SignatureType: 7,
		}
		config := session.DefaultSessionConfig()
		return session.NewPrimarySession("primary-1", dest, nil, config)
	}

	tests := []struct {
		name        string
		command     *protocol.Command
		ctx         *Context
		wantResult  string
		wantMessage string
	}{
		{
			name: "handshake not complete",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "sub-1",
				},
			},
			ctx: &Context{
				HandshakeComplete: false,
			},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "no session bound",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "sub-1",
				},
			},
			ctx: &Context{
				HandshakeComplete: true,
				Session:           nil,
			},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "not a PRIMARY session",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "sub-1",
				},
			},
			ctx: func() *Context {
				// Create a non-PRIMARY session
				dest := &session.Destination{
					PublicKey:     []byte("test-pub-base64"),
					PrivateKey:    []byte("test-priv-key"),
					SignatureType: 7,
				}
				baseSession := session.NewBaseSession("stream-1", session.StyleStream, dest, nil, nil)
				baseSession.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           baseSession,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "successful STREAM subsession",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":     "STREAM",
					"ID":        "stream-sub",
					"FROM_PORT": "1234",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultOK,
		},
		{
			name: "successful DATAGRAM subsession with PORT/HOST",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":       "DATAGRAM",
					"ID":          "datagram-sub",
					"PORT":        "7655",
					"HOST":        "localhost",
					"LISTEN_PORT": "5000",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultOK,
		},
		{
			name: "successful RAW subsession",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":           "RAW",
					"ID":              "raw-sub",
					"PORT":            "7656",
					"PROTOCOL":        "18",
					"LISTEN_PROTOCOL": "18",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultOK,
		},
		{
			name: "reject PRIMARY style",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "PRIMARY",
					"ID":    "sub-primary",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "reject MASTER style",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "MASTER",
					"ID":    "sub-master",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "missing STYLE",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"ID": "sub-1",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "missing ID",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "ID with whitespace",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "sub with space",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "DESTINATION not allowed",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":       "STREAM",
					"ID":          "sub-1",
					"DESTINATION": "some-dest",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "PORT invalid for STREAM",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "stream-sub",
					"PORT":  "7655",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "HOST invalid for STREAM",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE": "STREAM",
					"ID":    "stream-sub",
					"HOST":  "localhost",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "PROTOCOL invalid for DATAGRAM",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":    "DATAGRAM",
					"ID":       "datagram-sub",
					"PORT":     "7655",
					"PROTOCOL": "18",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "RAW with LISTEN_PROTOCOL=6 is disallowed",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":           "RAW",
					"ID":              "raw-sub",
					"PORT":            "7656",
					"LISTEN_PROTOCOL": "6",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "duplicate subsession ID",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "ADD",
				Options: map[string]string{
					"STYLE":     "STREAM",
					"ID":        "existing-sub",
					"FROM_PORT": "2000",
				},
			},
			ctx: func() *Context {
				primary := createPrimarySession()
				primary.SetStatus(session.StatusActive)
				// Add a subsession first
				primary.AddSubsession("existing-sub", session.StyleStream, session.SubsessionOptions{
					FromPort:   1000,
					ListenPort: 1000,
				})
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultDuplicatedID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewSessionHandler(successManager)
			resp, err := handler.Handle(tt.ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp == nil {
				t.Fatal("Handle() response = nil")
			}

			got := resp.String()
			if !strings.Contains(got, "RESULT="+tt.wantResult) {
				t.Errorf("Handle() = %q, want RESULT=%s", got, tt.wantResult)
			}
		})
	}
}

// TestSessionHandler_HandleRemove tests SESSION REMOVE command handling.
func TestSessionHandler_HandleRemove(t *testing.T) {
	mockDest := &commondest.Destination{}
	mockPrivKey := []byte("test-private-key")

	successManager := &mockManager{
		dest:        mockDest,
		privateKey:  mockPrivKey,
		pubEncoded:  "test-pub-base64",
		privEncoded: "test-priv-base64",
	}

	// Create a PRIMARY session with a subsession for testing
	createPrimaryWithSubsession := func() *session.PrimarySessionImpl {
		dest := &session.Destination{
			PublicKey:     []byte("test-pub-base64"),
			PrivateKey:    []byte("test-priv-key"),
			SignatureType: 7,
		}
		config := session.DefaultSessionConfig()
		primary := session.NewPrimarySession("primary-1", dest, nil, config)
		primary.SetStatus(session.StatusActive)
		primary.AddSubsession("sub-1", session.StyleStream, session.SubsessionOptions{
			FromPort:   1234,
			ListenPort: 1234,
		})
		return primary
	}

	tests := []struct {
		name       string
		command    *protocol.Command
		ctx        *Context
		wantResult string
	}{
		{
			name: "handshake not complete",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "REMOVE",
				Options: map[string]string{
					"ID": "sub-1",
				},
			},
			ctx: &Context{
				HandshakeComplete: false,
			},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "no session bound",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "REMOVE",
				Options: map[string]string{
					"ID": "sub-1",
				},
			},
			ctx: &Context{
				HandshakeComplete: true,
				Session:           nil,
			},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "not a PRIMARY session",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "REMOVE",
				Options: map[string]string{
					"ID": "sub-1",
				},
			},
			ctx: func() *Context {
				dest := &session.Destination{
					PublicKey:     []byte("test-pub-base64"),
					PrivateKey:    []byte("test-priv-key"),
					SignatureType: 7,
				}
				baseSession := session.NewBaseSession("stream-1", session.StyleStream, dest, nil, nil)
				baseSession.SetStatus(session.StatusActive)
				return &Context{
					HandshakeComplete: true,
					Session:           baseSession,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "successful remove",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "REMOVE",
				Options: map[string]string{
					"ID": "sub-1",
				},
			},
			ctx: func() *Context {
				primary := createPrimaryWithSubsession()
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultOK,
		},
		{
			name: "missing ID",
			command: &protocol.Command{
				Verb:    "SESSION",
				Action:  "REMOVE",
				Options: map[string]string{},
			},
			ctx: func() *Context {
				primary := createPrimaryWithSubsession()
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "subsession not found",
			command: &protocol.Command{
				Verb:   "SESSION",
				Action: "REMOVE",
				Options: map[string]string{
					"ID": "nonexistent",
				},
			},
			ctx: func() *Context {
				primary := createPrimaryWithSubsession()
				return &Context{
					HandshakeComplete: true,
					Session:           primary,
				}
			}(),
			wantResult: protocol.ResultI2PError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewSessionHandler(successManager)
			resp, err := handler.Handle(tt.ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp == nil {
				t.Fatal("Handle() response = nil")
			}

			got := resp.String()
			if !strings.Contains(got, "RESULT="+tt.wantResult) {
				t.Errorf("Handle() = %q, want RESULT=%s", got, tt.wantResult)
			}
		})
	}
}

// TestParseSubsessionOptions tests subsession options parsing.
func TestParseSubsessionOptions(t *testing.T) {
	handler := NewSessionHandler(nil)

	tests := []struct {
		name      string
		command   *protocol.Command
		style     session.Style
		wantErr   bool
		checkOpts func(t *testing.T, opts *session.SubsessionOptions)
	}{
		{
			name: "STREAM with FROM_PORT",
			command: &protocol.Command{
				Options: map[string]string{
					"FROM_PORT": "1234",
				},
			},
			style:   session.StyleStream,
			wantErr: false,
			checkOpts: func(t *testing.T, opts *session.SubsessionOptions) {
				if opts.FromPort != 1234 {
					t.Errorf("FromPort = %d, want 1234", opts.FromPort)
				}
				if opts.ListenPort != 1234 {
					t.Errorf("ListenPort = %d, want 1234 (defaulted from FROM_PORT)", opts.ListenPort)
				}
			},
		},
		{
			name: "RAW with all options",
			command: &protocol.Command{
				Options: map[string]string{
					"PORT":            "7655",
					"HOST":            "192.168.1.1",
					"FROM_PORT":       "1000",
					"TO_PORT":         "2000",
					"PROTOCOL":        "18",
					"LISTEN_PORT":     "3000",
					"LISTEN_PROTOCOL": "18",
					"HEADER":          "true",
				},
			},
			style:   session.StyleRaw,
			wantErr: false,
			checkOpts: func(t *testing.T, opts *session.SubsessionOptions) {
				if opts.Port != 7655 {
					t.Errorf("Port = %d, want 7655", opts.Port)
				}
				if opts.Host != "192.168.1.1" {
					t.Errorf("Host = %s, want 192.168.1.1", opts.Host)
				}
				if opts.FromPort != 1000 {
					t.Errorf("FromPort = %d, want 1000", opts.FromPort)
				}
				if opts.ToPort != 2000 {
					t.Errorf("ToPort = %d, want 2000", opts.ToPort)
				}
				if opts.Protocol != 18 {
					t.Errorf("Protocol = %d, want 18", opts.Protocol)
				}
				if opts.ListenPort != 3000 {
					t.Errorf("ListenPort = %d, want 3000", opts.ListenPort)
				}
				if opts.ListenProtocol != 18 {
					t.Errorf("ListenProtocol = %d, want 18", opts.ListenProtocol)
				}
				if !opts.HeaderEnabled {
					t.Error("HeaderEnabled = false, want true")
				}
			},
		},
		{
			name: "DATAGRAM with default HOST",
			command: &protocol.Command{
				Options: map[string]string{
					"PORT": "7655",
				},
			},
			style:   session.StyleDatagram,
			wantErr: false,
			checkOpts: func(t *testing.T, opts *session.SubsessionOptions) {
				if opts.Host != "127.0.0.1" {
					t.Errorf("Host = %s, want 127.0.0.1 (default)", opts.Host)
				}
			},
		},
		{
			name: "invalid STREAM LISTEN_PORT",
			command: &protocol.Command{
				Options: map[string]string{
					"FROM_PORT":   "1234",
					"LISTEN_PORT": "5678", // Must be 0 or FROM_PORT for STREAM
				},
			},
			style:   session.StyleStream,
			wantErr: true,
		},
		{
			name: "STREAM LISTEN_PORT=0 is allowed",
			command: &protocol.Command{
				Options: map[string]string{
					"FROM_PORT":   "1234",
					"LISTEN_PORT": "0",
				},
			},
			style:   session.StyleStream,
			wantErr: false,
			checkOpts: func(t *testing.T, opts *session.SubsessionOptions) {
				if opts.ListenPort != 0 {
					t.Errorf("ListenPort = %d, want 0", opts.ListenPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := handler.parseSubsessionOptions(tt.command, tt.style)

			if tt.wantErr {
				if err == nil {
					t.Error("parseSubsessionOptions() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseSubsessionOptions() error = %v", err)
			}

			if tt.checkOpts != nil {
				tt.checkOpts(t, opts)
			}
		})
	}
}

// TestSessionHandler_UnknownAction tests unknown SESSION action handling.
func TestSessionHandler_UnknownAction(t *testing.T) {
	handler := NewSessionHandler(nil)
	ctx := &Context{
		HandshakeComplete: true,
	}
	cmd := &protocol.Command{
		Verb:   "SESSION",
		Action: "UNKNOWN",
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	got := resp.String()
	if !strings.Contains(got, "RESULT=I2P_ERROR") {
		t.Errorf("Handle() = %q, want RESULT=I2P_ERROR", got)
	}
	if !strings.Contains(got, "unknown SESSION action") {
		t.Errorf("Handle() = %q, want 'unknown SESSION action' in message", got)
	}
}
