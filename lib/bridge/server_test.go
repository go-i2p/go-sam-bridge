package bridge

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockSession implements session.Session for testing.
type mockSession struct {
	id          string
	style       session.Style
	destination *session.Destination
	status      session.Status
}

func (m *mockSession) ID() string                        { return m.id }
func (m *mockSession) Style() session.Style              { return m.style }
func (m *mockSession) Destination() *session.Destination { return m.destination }
func (m *mockSession) Status() session.Status            { return m.status }
func (m *mockSession) Close() error                      { return nil }
func (m *mockSession) ControlConn() net.Conn             { return nil }

// mockRegistry implements session.Registry for testing.
type mockRegistry struct {
	mu       sync.RWMutex
	sessions map[string]session.Session
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{
		sessions: make(map[string]session.Session),
	}
}

func (r *mockRegistry) Register(s session.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID()] = s
	return nil
}

func (r *mockRegistry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	return nil
}

func (r *mockRegistry) Get(id string) session.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[id]
}

func (r *mockRegistry) GetByDestination(destHash string) session.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		if s.Destination() != nil && s.Destination().Hash() == destHash {
			return s
		}
	}
	return nil
}

func (r *mockRegistry) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		result = append(result, id)
	}
	return result
}

func (r *mockRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *mockRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = make(map[string]session.Session)
	return nil
}

func TestNewServer(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server.Config() != config {
		t.Error("Config() returned different config")
	}
	if server.Registry() != registry {
		t.Error("Registry() returned different registry")
	}
	if server.Router() == nil {
		t.Error("Router() = nil, want non-nil")
	}
	if server.ConnectionCount() != 0 {
		t.Errorf("ConnectionCount() = %d, want 0", server.ConnectionCount())
	}
}

func TestNewServer_InvalidConfig(t *testing.T) {
	registry := newMockRegistry()
	config := &Config{} // Empty config is invalid

	_, err := NewServer(config, registry)
	if err == nil {
		t.Error("NewServer() with invalid config should return error")
	}
}

func TestServer_Addr(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Before listening
	if addr := server.Addr(); addr != "" {
		t.Errorf("Addr() before listen = %q, want empty", addr)
	}

	// Start listening
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	go server.Serve(listener)
	defer server.Close()

	// Give it time to start
	time.Sleep(10 * time.Millisecond)

	if addr := server.Addr(); addr == "" {
		t.Error("Addr() after listen = empty, want address")
	}
}

func TestServer_Close(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	go server.Serve(listener)

	// Give it time to start
	time.Sleep(10 * time.Millisecond)

	// Close should return nil on first call
	if err := server.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Done channel should be closed
	select {
	case <-server.Done():
		// Good
	default:
		t.Error("Done() channel not closed after Close()")
	}

	// Close should be idempotent
	if err := server.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

func TestServer_HandleConnection(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	config.Timeouts.Handshake = 100 * time.Millisecond

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Register a HELLO handler
	server.Router().RegisterFunc("HELLO", func(ctx *handler.Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("HELLO").
			WithAction("REPLY").
			WithResult("OK").
			WithVersion("3.3"), nil
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	go server.Serve(listener)
	defer server.Close()

	// Connect and send HELLO
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("HELLO VERSION MIN=3.0 MAX=3.3\n"))

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}

	if !strings.Contains(line, "RESULT=OK") {
		t.Errorf("response = %q, want RESULT=OK", line)
	}
	if !strings.Contains(line, "VERSION=3.3") {
		t.Errorf("response = %q, want VERSION=3.3", line)
	}
}

func TestServer_HandshakeRequired(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	config.Timeouts.Handshake = 100 * time.Millisecond

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Register handlers
	server.Router().RegisterFunc("HELLO", func(ctx *handler.Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("HELLO").
			WithAction("REPLY").
			WithResult("OK").
			WithVersion("3.3"), nil
	})
	server.Router().RegisterFunc("SESSION CREATE", func(ctx *handler.Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("SESSION").
			WithAction("STATUS").
			WithResult("OK"), nil
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	go server.Serve(listener)
	defer server.Close()

	// Connect and try SESSION CREATE before HELLO
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("SESSION CREATE STYLE=STREAM ID=test\n"))

	// Read response - should get error about handshake
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}

	if !strings.Contains(line, "I2P_ERROR") {
		t.Errorf("response = %q, want I2P_ERROR", line)
	}
	if !strings.Contains(line, "handshake") {
		t.Errorf("response = %q, want handshake message", line)
	}
}

func TestServer_Authentication(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	config.Auth.Required = true
	config.Auth.Users = map[string]string{"admin": "secret"}
	config.Timeouts.Handshake = 100 * time.Millisecond

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Register handlers
	server.Router().RegisterFunc("HELLO", func(ctx *handler.Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("HELLO").
			WithAction("REPLY").
			WithResult("OK").
			WithVersion("3.3"), nil
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	go server.Serve(listener)
	defer server.Close()

	// Connect and send HELLO with authentication
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("HELLO VERSION MIN=3.0 MAX=3.3 USER=admin PASSWORD=secret\n"))

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}

	if !strings.Contains(line, "RESULT=OK") {
		t.Errorf("response = %q, want RESULT=OK", line)
	}
}

func TestServer_MaxConnections(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	config.Limits.MaxConnections = 1
	config.Timeouts.Handshake = 50 * time.Millisecond

	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	server.Router().RegisterFunc("HELLO", func(ctx *handler.Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("HELLO").
			WithAction("REPLY").
			WithResult("OK").
			WithVersion("3.3"), nil
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	go server.Serve(listener)
	defer server.Close()

	// First connection should succeed
	conn1, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("first net.Dial() error = %v", err)
	}
	defer conn1.Close()

	// Send HELLO to keep connection active
	conn1.Write([]byte("HELLO VERSION MIN=3.0 MAX=3.3\n"))
	reader1 := bufio.NewReader(conn1)
	reader1.ReadString('\n') // Read response

	// Give server time to register the connection
	time.Sleep(10 * time.Millisecond)

	// Second connection should be rejected (closed immediately)
	conn2, err := net.DialTimeout("tcp", listener.Addr().String(), 50*time.Millisecond)
	if err != nil {
		return // Connection rejected as expected
	}
	defer conn2.Close()

	// Try to read - should get EOF quickly
	conn2.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn2.Read(buf)
	if err == nil {
		t.Error("second connection should have been closed")
	}
}

func TestGetOptionValue(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		key     string
		want    string
	}{
		{
			name:    "simple value",
			options: []string{"RESULT=OK", "VERSION=3.3"},
			key:     "RESULT",
			want:    "OK",
		},
		{
			name:    "quoted value",
			options: []string{"MESSAGE=\"hello world\""},
			key:     "MESSAGE",
			want:    "hello world",
		},
		{
			name:    "not found",
			options: []string{"RESULT=OK"},
			key:     "VERSION",
			want:    "",
		},
		{
			name:    "empty options",
			options: []string{},
			key:     "RESULT",
			want:    "",
		},
		{
			name:    "empty value",
			options: []string{"KEY="},
			key:     "KEY",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getOptionValue(tt.options, tt.key)
			if got != tt.want {
				t.Errorf("getOptionValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maxLen  int
		want    string
		wantErr bool
	}{
		{
			name:   "simple line",
			input:  "HELLO VERSION\n",
			maxLen: 1024,
			want:   "HELLO VERSION",
		},
		{
			name:   "with carriage return",
			input:  "HELLO VERSION\r\n",
			maxLen: 1024,
			want:   "HELLO VERSION",
		},
		{
			name:    "exceeds max length",
			input:   "HELLO VERSION WITH LONG OPTIONS\n",
			maxLen:  10,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			got, err := ReadLine(reader, tt.maxLen)

			if tt.wantErr {
				if err == nil {
					t.Error("ReadLine() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Errorf("ReadLine() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("ReadLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsHandshakeCommand(t *testing.T) {
	tests := []struct {
		verb string
		want bool
	}{
		{"HELLO", true},
		{"hello", true},
		{"Hello", true},
		{"SESSION", false},
		{"STREAM", false},
	}

	for _, tt := range tests {
		t.Run(tt.verb, func(t *testing.T) {
			cmd := &protocol.Command{Verb: tt.verb}
			got := isHandshakeCommand(cmd)
			if got != tt.want {
				t.Errorf("isHandshakeCommand(%q) = %v, want %v", tt.verb, got, tt.want)
			}
		})
	}
}

func TestIsAuthCommand(t *testing.T) {
	tests := []struct {
		verb string
		want bool
	}{
		{"HELLO", true},
		{"hello", true},
		{"SESSION", false},
	}

	for _, tt := range tests {
		t.Run(tt.verb, func(t *testing.T) {
			cmd := &protocol.Command{Verb: tt.verb}
			got := isAuthCommand(cmd)
			if got != tt.want {
				t.Errorf("isAuthCommand(%q) = %v, want %v", tt.verb, got, tt.want)
			}
		})
	}
}

// mockTimeoutError implements net.Error with timeout behavior.
type mockTimeoutError struct {
	timeout   bool
	temporary bool
}

func (e *mockTimeoutError) Error() string   { return "mock timeout error" }
func (e *mockTimeoutError) Timeout() bool   { return e.timeout }
func (e *mockTimeoutError) Temporary() bool { return e.temporary }

func TestIsTimeoutError(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "timeout error",
			err:  &mockTimeoutError{timeout: true},
			want: true,
		},
		{
			name: "non-timeout error",
			err:  &mockTimeoutError{timeout: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := server.isTimeoutError(tt.err)
			if got != tt.want {
				t.Errorf("isTimeoutError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSendTimeoutError(t *testing.T) {
	tests := []struct {
		name          string
		state         ConnectionState
		wantVerb      string
		wantSubstring string
	}{
		{
			name:          "new connection",
			state:         StateNew,
			wantVerb:      "HELLO",
			wantSubstring: "HELLO not received",
		},
		{
			name:          "handshaking",
			state:         StateHandshaking,
			wantVerb:      "HELLO",
			wantSubstring: "HELLO not received",
		},
		{
			name:          "ready",
			state:         StateReady,
			wantVerb:      "SESSION",
			wantSubstring: "no command received",
		},
		{
			name:          "session bound",
			state:         StateSessionBound,
			wantVerb:      "SESSION",
			wantSubstring: "no command received",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := newMockRegistry()
			config := DefaultConfig()
			server, err := NewServer(config, registry)
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}

			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			conn := NewConnection(serverConn, 1024)
			conn.SetState(tt.state)

			// Read in goroutine
			done := make(chan string)
			go func() {
				reader := bufio.NewReader(clientConn)
				line, _ := reader.ReadString('\n')
				done <- line
			}()

			server.sendTimeoutError(conn)

			select {
			case line := <-done:
				if !strings.Contains(line, tt.wantVerb) {
					t.Errorf("response = %q, want verb %s", line, tt.wantVerb)
				}
				if !strings.Contains(line, "I2P_ERROR") {
					t.Errorf("response = %q, want I2P_ERROR", line)
				}
				if !strings.Contains(line, tt.wantSubstring) {
					t.Errorf("response = %q, want substring %q", line, tt.wantSubstring)
				}
			case <-time.After(time.Second):
				t.Error("timeout waiting for response")
			}
		})
	}
}

func TestSendPongTimeoutError(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	conn := NewConnection(serverConn, 1024)

	// Read in goroutine
	done := make(chan string)
	go func() {
		reader := bufio.NewReader(clientConn)
		line, _ := reader.ReadString('\n')
		done <- line
	}()

	server.sendPongTimeoutError(conn)

	select {
	case line := <-done:
		if !strings.Contains(line, "SESSION") {
			t.Errorf("response = %q, want SESSION", line)
		}
		if !strings.Contains(line, "I2P_ERROR") {
			t.Errorf("response = %q, want I2P_ERROR", line)
		}
		if !strings.Contains(line, "PONG not received") {
			t.Errorf("response = %q, want 'PONG not received'", line)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for response")
	}
}

func TestSendPing(t *testing.T) {
	registry := newMockRegistry()
	config := DefaultConfig()
	server, err := NewServer(config, registry)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	tests := []struct {
		name     string
		text     string
		wantLine string
	}{
		{
			name:     "ping without text",
			text:     "",
			wantLine: "PING",
		},
		{
			name:     "ping with text",
			text:     "keepalive",
			wantLine: "PING keepalive",
		},
		{
			name:     "ping with multiple words",
			text:     "hello world",
			wantLine: "PING hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			conn := NewConnection(serverConn, 1024)

			// Read in goroutine
			done := make(chan string)
			go func() {
				reader := bufio.NewReader(clientConn)
				line, _ := reader.ReadString('\n')
				done <- strings.TrimSpace(line)
			}()

			err := server.SendPing(conn, tt.text)
			if err != nil {
				t.Fatalf("SendPing() error = %v", err)
			}

			// Verify pending ping is set
			pending := conn.GetPendingPing()
			if pending == nil {
				t.Error("pending ping not set")
			} else if pending.Text != tt.text {
				t.Errorf("pending ping text = %q, want %q", pending.Text, tt.text)
			}

			select {
			case line := <-done:
				if line != tt.wantLine {
					t.Errorf("sent = %q, want %q", line, tt.wantLine)
				}
			case <-time.After(time.Second):
				t.Error("timeout waiting for ping")
			}
		})
	}
}
