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
