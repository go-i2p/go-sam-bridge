// Package datagram implements SAM v3.0-3.3 datagram handling.
// Tests for UDP listener that handles incoming SAM datagrams on port 7655.
package datagram

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
}

// mockSession implements session.Session interface for testing.
type mockSession struct {
	id          string
	style       session.Style
	status      session.Status
	dest        *session.Destination
	controlConn net.Conn
	closed      bool
	mu          sync.Mutex
}

func newMockSession(id string, style session.Style) *mockSession {
	return &mockSession{
		id:     id,
		style:  style,
		status: session.StatusActive,
		dest:   &session.Destination{PublicKey: []byte("test-dest-" + id)},
	}
}

func (m *mockSession) ID() string                        { return m.id }
func (m *mockSession) Style() session.Style              { return m.style }
func (m *mockSession) Status() session.Status            { return m.status }
func (m *mockSession) Destination() *session.Destination { return m.dest }
func (m *mockSession) ControlConn() net.Conn             { return m.controlConn }

func (m *mockSession) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.status = session.StatusClosed
	return nil
}

// mockSessionRegistry implements session.Registry interface for testing.
type mockSessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]session.Session
}

func newMockSessionRegistry() *mockSessionRegistry {
	return &mockSessionRegistry{
		sessions: make(map[string]session.Session),
	}
}

func (r *mockSessionRegistry) Register(s session.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID()] = s
	return nil
}

func (r *mockSessionRegistry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	return nil
}

func (r *mockSessionRegistry) Get(id string) session.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[id]
}

func (r *mockSessionRegistry) GetByDestination(destHash string) session.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		if s.Destination() != nil && s.Destination().Hash() == destHash {
			return s
		}
	}
	return nil
}

func (r *mockSessionRegistry) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	return ids
}

func (r *mockSessionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *mockSessionRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		s.Close()
	}
	r.sessions = make(map[string]session.Session)
	return nil
}

func (r *mockSessionRegistry) MostRecentByStyle(style session.Style) session.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Simple implementation - return nil (no tracking in mock)
	return nil
}

// TestNewUDPListener tests UDPListener creation.
func TestNewUDPListener(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)
	if listener == nil {
		t.Fatal("NewUDPListener returned nil")
	}
	if listener.registry != registry {
		t.Error("Registry not set correctly")
	}
}

// TestUDPListenerStartClose tests Start and Close lifecycle.
func TestUDPListenerStartClose(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify we're listening
	addr := listener.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after Start()")
	}

	// Close should work cleanly
	if err := listener.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// TestUDPListenerAddr tests address retrieval.
func TestUDPListenerAddr(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	// Before Start, Addr should be nil
	if listener.Addr() != nil {
		t.Error("Addr() should be nil before Start()")
	}

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after Start()")
	}

	// Should be able to get network
	if addr.Network() != "udp" {
		t.Errorf("Expected network 'udp', got %q", addr.Network())
	}
}

// TestParseDatagramHeader tests header parsing.
func TestParseDatagramHeader(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantVersion string
		wantNick    string
		wantDest    string
		wantPayload []byte
		wantErr     bool
	}{
		{
			name:        "valid SAM 3.0 header",
			data:        []byte("3.0 testnick AAAA~\nHello World"),
			wantVersion: "3.0",
			wantNick:    "testnick",
			wantDest:    "AAAA~",
			wantPayload: []byte("Hello World"),
			wantErr:     false,
		},
		{
			name:        "valid SAM 3.2 header",
			data:        []byte("3.2 mysession destB64encoded~\nPayload here"),
			wantVersion: "3.2",
			wantNick:    "mysession",
			wantDest:    "destB64encoded~",
			wantPayload: []byte("Payload here"),
			wantErr:     false,
		},
		{
			name:        "valid SAM 3.3 header",
			data:        []byte("3.3 rawsession dest123~\nRaw payload"),
			wantVersion: "3.3",
			wantNick:    "rawsession",
			wantDest:    "dest123~",
			wantPayload: []byte("Raw payload"),
			wantErr:     false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "no newline",
			data:    []byte("3.0 nick dest"),
			wantErr: true,
		},
		{
			name:    "missing fields",
			data:    []byte("3.0\n"),
			wantErr: true,
		},
		{
			name:    "missing destination",
			data:    []byte("3.0 nick\n"),
			wantErr: true,
		},
		{
			name:        "empty payload",
			data:        []byte("3.0 nick dest~\n"),
			wantVersion: "3.0",
			wantNick:    "nick",
			wantDest:    "dest~",
			wantPayload: []byte{},
			wantErr:     false,
		},
		{
			name:        "payload with newlines",
			data:        []byte("3.0 nick dest~\nLine1\nLine2\nLine3"),
			wantVersion: "3.0",
			wantNick:    "nick",
			wantDest:    "dest~",
			wantPayload: []byte("Line1\nLine2\nLine3"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, payload, err := ParseDatagramHeader(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if header.Version != tt.wantVersion {
				t.Errorf("Version: got %q, want %q", header.Version, tt.wantVersion)
			}
			if header.Nickname != tt.wantNick {
				t.Errorf("Nickname: got %q, want %q", header.Nickname, tt.wantNick)
			}
			if header.Destination != tt.wantDest {
				t.Errorf("Destination: got %q, want %q", header.Destination, tt.wantDest)
			}
			if string(payload) != string(tt.wantPayload) {
				t.Errorf("Payload: got %q, want %q", string(payload), string(tt.wantPayload))
			}
		})
	}
}

// TestParseDatagramHeaderOptions tests option parsing.
func TestParseDatagramHeaderOptions(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantFromPort int
		wantToPort   int
		wantProtocol int
		wantErr      bool
	}{
		{
			name:         "with FROM_PORT option",
			data:         []byte("3.2 nick dest~ FROM_PORT=1234\nPayload"),
			wantFromPort: 1234,
			wantToPort:   0,
			wantProtocol: 0,
			wantErr:      false,
		},
		{
			name:         "with TO_PORT option",
			data:         []byte("3.2 nick dest~ TO_PORT=5678\nPayload"),
			wantFromPort: 0,
			wantToPort:   5678,
			wantProtocol: 0,
			wantErr:      false,
		},
		{
			name:         "with PROTOCOL option",
			data:         []byte("3.2 nick dest~ PROTOCOL=18\nPayload"),
			wantFromPort: 0,
			wantToPort:   0,
			wantProtocol: 18,
			wantErr:      false,
		},
		{
			name:         "with multiple options",
			data:         []byte("3.2 nick dest~ FROM_PORT=100 TO_PORT=200 PROTOCOL=42\nPayload"),
			wantFromPort: 100,
			wantToPort:   200,
			wantProtocol: 42,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, _, err := ParseDatagramHeader(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if header.FromPort != tt.wantFromPort {
				t.Errorf("FromPort: got %d, want %d", header.FromPort, tt.wantFromPort)
			}
			if header.ToPort != tt.wantToPort {
				t.Errorf("ToPort: got %d, want %d", header.ToPort, tt.wantToPort)
			}
			if header.Protocol != tt.wantProtocol {
				t.Errorf("Protocol: got %d, want %d", header.Protocol, tt.wantProtocol)
			}
		})
	}
}

// TestUDPListenerSendReceive tests sending a datagram and verifying it's handled.
func TestUDPListenerSendReceive(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer listener.Close()

	// Get the listener address
	addr := listener.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}

	// Create a client UDP connection
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Send a datagram (won't be routed since no session exists, but tests receive loop)
	datagram := []byte("3.0 testnick dest~\nHello")
	if _, err := conn.Write(datagram); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Give it time to process
	time.Sleep(50 * time.Millisecond)
}

// TestUDPListenerConcurrency tests concurrent operations.
func TestUDPListenerConcurrency(t *testing.T) {
	registry := newMockSessionRegistry()

	// Register a session
	rawSession := newMockSession("concurrent-raw", session.StyleRaw)
	registry.Register(rawSession)

	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr()

	// Send multiple datagrams concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			conn, err := net.Dial("udp", addr.String())
			if err != nil {
				t.Errorf("Failed to dial: %v", err)
				return
			}
			defer conn.Close()
			datagram := []byte("3.0 concurrent-raw dest~\nMessage")
			if _, err := conn.Write(datagram); err != nil {
				t.Errorf("Failed to write: %v", err)
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)
}

// TestUDPListenerGracefulShutdown tests that Close shuts down cleanly.
func TestUDPListenerGracefulShutdown(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	addr := listener.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}

	// Start sending datagrams in background
	done := make(chan struct{})
	go func() {
		conn, err := net.Dial("udp", addr.String())
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			select {
			case <-done:
				return
			default:
				conn.Write([]byte("3.0 test dest~\nKeepAlive"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Allow some datagrams to be sent
	time.Sleep(50 * time.Millisecond)

	// Close should complete without hanging
	closeComplete := make(chan error)
	go func() {
		closeComplete <- listener.Close()
	}()

	select {
	case err := <-closeComplete:
		if err != nil {
			t.Errorf("Close returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Close() timed out")
	}

	close(done)
}

// TestDatagramHeaderStruct tests DatagramHeader fields.
func TestDatagramHeaderStruct(t *testing.T) {
	header := &DatagramHeader{
		Version:      "3.3",
		Nickname:     "testSession",
		Destination:  "AAAA~",
		FromPort:     1234,
		ToPort:       5678,
		Protocol:     18,
		SendTags:     40,
		TagThreshold: 10,
		Expires:      3600,
		SendLeaseSet: boolPtr(true),
	}

	if header.Version != "3.3" {
		t.Errorf("Version: got %q, want %q", header.Version, "3.3")
	}
	if header.Nickname != "testSession" {
		t.Errorf("Nickname: got %q, want %q", header.Nickname, "testSession")
	}
	if header.Destination != "AAAA~" {
		t.Errorf("Destination: got %q, want %q", header.Destination, "AAAA~")
	}
	if header.FromPort != 1234 {
		t.Errorf("FromPort: got %d, want %d", header.FromPort, 1234)
	}
	if header.ToPort != 5678 {
		t.Errorf("ToPort: got %d, want %d", header.ToPort, 5678)
	}
	if header.Protocol != 18 {
		t.Errorf("Protocol: got %d, want %d", header.Protocol, 18)
	}
	if header.SendTags != 40 {
		t.Errorf("SendTags: got %d, want %d", header.SendTags, 40)
	}
	if header.TagThreshold != 10 {
		t.Errorf("TagThreshold: got %d, want %d", header.TagThreshold, 10)
	}
	if header.Expires != 3600 {
		t.Errorf("Expires: got %d, want %d", header.Expires, 3600)
	}
	if header.SendLeaseSet == nil || !*header.SendLeaseSet {
		t.Error("SendLeaseSet: got nil or false, want true")
	}
}

// TestDefaultUDPPort verifies the default UDP port constant.
func TestDefaultUDPPort(t *testing.T) {
	// Per SAMv3.md, the default UDP port is 7655
	if DefaultUDPPort != 7655 {
		t.Errorf("DefaultUDPPort: got %d, want %d", DefaultUDPPort, 7655)
	}
}

// TestDoubleStart tests that starting twice returns an error.
func TestDoubleStart(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("First Start failed: %v", err)
	}
	defer listener.Close()

	// Second start should fail
	if err := listener.Start(); err == nil {
		t.Error("Expected error on second Start(), got nil")
	}
}

// TestDoubleClose tests that closing twice is safe.
func TestDoubleClose(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}

	// Second close should be safe (may return nil or an error)
	_ = listener.Close()
}

// TestFormatDatagramHeader tests formatting a header back to string.
func TestFormatDatagramHeader(t *testing.T) {
	tests := []struct {
		name   string
		header *DatagramHeader
		want   string
	}{
		{
			name: "basic header",
			header: &DatagramHeader{
				Version:     "3.0",
				Nickname:    "testnick",
				Destination: "dest~",
			},
			want: "3.0 testnick dest~",
		},
		{
			name: "with ports",
			header: &DatagramHeader{
				Version:     "3.2",
				Nickname:    "session1",
				Destination: "targetdest~",
				FromPort:    1234,
				ToPort:      5678,
			},
			want: "3.2 session1 targetdest~ FROM_PORT=1234 TO_PORT=5678",
		},
		{
			name: "with protocol",
			header: &DatagramHeader{
				Version:     "3.2",
				Nickname:    "rawsess",
				Destination: "rawdest~",
				Protocol:    18,
			},
			want: "3.2 rawsess rawdest~ PROTOCOL=18",
		},
		{
			name: "with SAM 3.3 options",
			header: &DatagramHeader{
				Version:      "3.3",
				Nickname:     "advanced",
				Destination:  "fulldest~",
				FromPort:     100,
				ToPort:       200,
				SendTags:     40,
				TagThreshold: 10,
				Expires:      3600,
				SendLeaseSet: boolPtr(true),
			},
			want: "3.3 advanced fulldest~ FROM_PORT=100 TO_PORT=200 SEND_TAGS=40 TAG_THRESHOLD=10 EXPIRES=3600 SEND_LEASESET=true",
		},
		{
			name: "with SendLeaseSet false",
			header: &DatagramHeader{
				Version:      "3.3",
				Nickname:     "sess",
				Destination:  "d~",
				SendLeaseSet: boolPtr(false),
			},
			want: "3.3 sess d~ SEND_LEASESET=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDatagramHeader(tt.header)
			if got != tt.want {
				t.Errorf("FormatDatagramHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestIsValidSAMVersion tests SAM version validation.
func TestIsValidSAMVersion(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"3.0", true},
		{"3.1", true},
		{"3.2", true},
		{"3.3", true},
		{"3.10", true},
		{"3.99", true},
		{"2.0", false}, // Wrong major version
		{"4.0", false}, // Wrong major version
		{"3.", false},  // Missing minor
		{"3", false},   // Too short
		{"3.x", false}, // Non-numeric minor
		{"", false},    // Empty
		{"ab", false},  // Not a version
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			// We can't test isValidSAMVersion directly since it's unexported,
			// but we test it indirectly through ParseDatagramHeader
			data := []byte(tt.version + " nick dest~\nPayload")
			_, _, err := ParseDatagramHeader(data)
			if tt.valid && err != nil {
				t.Errorf("version %q should be valid, got error: %v", tt.version, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("version %q should be invalid, but no error", tt.version)
			}
		})
	}
}

// TestParseHeaderOptionEdgeCases tests edge cases in option parsing.
func TestParseHeaderOptionEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		check   func(*DatagramHeader) bool
		wantErr bool
	}{
		{
			name:    "invalid FROM_PORT value",
			data:    []byte("3.2 nick dest~ FROM_PORT=invalid\nPayload"),
			wantErr: true,
		},
		{
			name:    "invalid TO_PORT value",
			data:    []byte("3.2 nick dest~ TO_PORT=abc\nPayload"),
			wantErr: true,
		},
		{
			name:    "invalid PROTOCOL value",
			data:    []byte("3.2 nick dest~ PROTOCOL=xyz\nPayload"),
			wantErr: true,
		},
		{
			name:    "port out of range high",
			data:    []byte("3.2 nick dest~ FROM_PORT=70000\nPayload"),
			wantErr: true,
		},
		{
			name:    "port negative",
			data:    []byte("3.2 nick dest~ FROM_PORT=-1\nPayload"),
			wantErr: true,
		},
		{
			name:    "protocol out of range",
			data:    []byte("3.2 nick dest~ PROTOCOL=300\nPayload"),
			wantErr: true,
		},
		{
			name:  "SEND_TAGS option",
			data:  []byte("3.3 nick dest~ SEND_TAGS=50\nPayload"),
			check: func(h *DatagramHeader) bool { return h.SendTags == 50 },
		},
		{
			name:  "TAG_THRESHOLD option",
			data:  []byte("3.3 nick dest~ TAG_THRESHOLD=15\nPayload"),
			check: func(h *DatagramHeader) bool { return h.TagThreshold == 15 },
		},
		{
			name:  "EXPIRES option",
			data:  []byte("3.3 nick dest~ EXPIRES=7200\nPayload"),
			check: func(h *DatagramHeader) bool { return h.Expires == 7200 },
		},
		{
			name:  "SEND_LEASESET true",
			data:  []byte("3.3 nick dest~ SEND_LEASESET=true\nPayload"),
			check: func(h *DatagramHeader) bool { return h.SendLeaseSet != nil && *h.SendLeaseSet == true },
		},
		{
			name:  "SEND_LEASESET false",
			data:  []byte("3.3 nick dest~ SEND_LEASESET=false\nPayload"),
			check: func(h *DatagramHeader) bool { return h.SendLeaseSet != nil && *h.SendLeaseSet == false },
		},
		{
			name:  "unknown option ignored",
			data:  []byte("3.2 nick dest~ UNKNOWN_OPT=value\nPayload"),
			check: func(h *DatagramHeader) bool { return h.Nickname == "nick" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, _, err := ParseDatagramHeader(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.check != nil && !tt.check(header) {
				t.Error("Check function returned false")
			}
		})
	}
}

// TestStartAfterClose tests that starting after close returns an error.
func TestStartAfterClose(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Start after close should fail
	if err := listener.Start(); err == nil {
		t.Error("Expected error when starting after close, got nil")
	}
}

// TestCloseWithoutStart tests closing without starting.
func TestCloseWithoutStart(t *testing.T) {
	registry := newMockSessionRegistry()
	listener := NewUDPListener("127.0.0.1:0", registry)

	// Close without start should be safe
	if err := listener.Close(); err != nil {
		t.Errorf("Close without start returned error: %v", err)
	}
}
