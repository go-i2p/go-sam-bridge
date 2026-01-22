package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockStreamManager implements StreamManager for testing.
type mockStreamManager struct {
	dialError   error
	listenError error
	lookupError error
	dialCount   int
	listenCount int
	lookupCount int
	lastDest    interface{}
	lastPort    uint16
}

func (m *mockStreamManager) LookupDestination(ctx context.Context, hostname string) (interface{}, error) {
	m.lookupCount++
	if m.lookupError != nil {
		return nil, m.lookupError
	}
	return "resolved-" + hostname, nil
}

func (m *mockStreamManager) Dial(dest interface{}, port uint16, mtu int) (net.Conn, error) {
	m.dialCount++
	m.lastDest = dest
	m.lastPort = port
	if m.dialError != nil {
		return nil, m.dialError
	}
	// Return a mock connection
	server, client := net.Pipe()
	go func() { server.Close() }()
	return client, nil
}

func (m *mockStreamManager) Listen(port uint16, mtu int) (net.Listener, error) {
	m.listenCount++
	if m.listenError != nil {
		return nil, m.listenError
	}
	// Return a mock listener
	return &streamMockListener{}, nil
}

func (m *mockStreamManager) Destination() interface{} {
	return "test-destination"
}

func (m *mockStreamManager) Close() error {
	return nil
}

// streamMockListener implements net.Listener for testing.
// Named differently from mockListener in stream_test.go to avoid conflicts.
type streamMockListener struct {
	acceptError error
	closed      bool
	acceptCount int
}

func (l *streamMockListener) Accept() (net.Conn, error) {
	l.acceptCount++
	if l.acceptError != nil {
		return nil, l.acceptError
	}
	server, client := net.Pipe()
	go func() { server.Close() }()
	return client, nil
}

func (l *streamMockListener) Close() error {
	l.closed = true
	return nil
}

func (l *streamMockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

// streamMockSession implements session.Session for testing.
// Named differently from mockSession in stream_test.go to avoid conflicts.
type streamMockSession struct {
	id    string
	style session.Style
}

func (s *streamMockSession) ID() string                        { return s.id }
func (s *streamMockSession) Style() session.Style              { return s.style }
func (s *streamMockSession) Destination() *session.Destination { return nil }
func (s *streamMockSession) Status() session.Status            { return session.StatusActive }
func (s *streamMockSession) ControlConn() net.Conn             { return nil }
func (s *streamMockSession) Close() error                      { return nil }

// TestStreamingConnector_Connect tests the Connect method.
func TestStreamingConnector_Connect(t *testing.T) {
	connector := NewStreamingConnector()
	manager := &mockStreamManager{}
	sess := &streamMockSession{id: "test-session", style: session.StyleStream}

	// Register manager
	connector.RegisterManager("test-session", manager)

	t.Run("successful connect to base64 destination", func(t *testing.T) {
		conn, err := connector.Connect(sess, "base64destination", 0, 80)
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		if conn == nil {
			t.Fatal("Expected connection, got nil")
		}
		conn.Close()

		if manager.dialCount != 1 {
			t.Errorf("Expected 1 dial, got %d", manager.dialCount)
		}
		if manager.lookupCount != 0 {
			t.Errorf("Expected 0 lookups for base64, got %d", manager.lookupCount)
		}
	})

	manager.dialCount = 0
	manager.lookupCount = 0

	t.Run("successful connect with hostname lookup", func(t *testing.T) {
		conn, err := connector.Connect(sess, "example.i2p", 0, 80)
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		if conn == nil {
			t.Fatal("Expected connection, got nil")
		}
		conn.Close()

		if manager.lookupCount != 1 {
			t.Errorf("Expected 1 lookup, got %d", manager.lookupCount)
		}
		if manager.dialCount != 1 {
			t.Errorf("Expected 1 dial, got %d", manager.dialCount)
		}
	})

	t.Run("connect with b32 lookup", func(t *testing.T) {
		manager.dialCount = 0
		manager.lookupCount = 0

		conn, err := connector.Connect(sess, "aaaa.b32.i2p", 0, 80)
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		if conn == nil {
			t.Fatal("Expected connection, got nil")
		}
		conn.Close()

		if manager.lookupCount != 1 {
			t.Errorf("Expected 1 lookup for b32, got %d", manager.lookupCount)
		}
	})

	t.Run("connect fails with no manager", func(t *testing.T) {
		unknownSess := &streamMockSession{id: "unknown", style: session.StyleStream}
		_, err := connector.Connect(unknownSess, "dest", 0, 80)
		if err == nil {
			t.Error("Expected error for unregistered session")
		}
	})

	t.Run("connect fails with dial error", func(t *testing.T) {
		manager.dialError = errors.New("dial failed")
		defer func() { manager.dialError = nil }()

		_, err := connector.Connect(sess, "base64dest", 0, 80)
		if err == nil {
			t.Error("Expected dial error")
		}
	})

	t.Run("connect fails with lookup error", func(t *testing.T) {
		manager.lookupError = errors.New("lookup failed")
		defer func() { manager.lookupError = nil }()

		_, err := connector.Connect(sess, "example.i2p", 0, 80)
		if err == nil {
			t.Error("Expected lookup error")
		}
	})
}

// TestStreamingAcceptor_Accept tests the Accept method.
func TestStreamingAcceptor_Accept(t *testing.T) {
	acceptor := NewStreamingAcceptor()
	manager := &mockStreamManager{}
	sess := &streamMockSession{id: "test-session", style: session.StyleStream}

	t.Run("accept fails without registered manager", func(t *testing.T) {
		_, _, err := acceptor.Accept(sess)
		if err == nil {
			t.Error("Expected error for unregistered session")
		}
	})

	t.Run("successful accept", func(t *testing.T) {
		err := acceptor.RegisterManager("test-session", manager)
		if err != nil {
			t.Fatalf("RegisterManager failed: %v", err)
		}

		conn, info, err := acceptor.Accept(sess)
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		if conn == nil {
			t.Fatal("Expected connection, got nil")
		}
		if info == nil {
			t.Fatal("Expected info, got nil")
		}
		conn.Close()
	})

	t.Run("unregister cleans up listener", func(t *testing.T) {
		acceptor.UnregisterManager("test-session")

		_, _, err := acceptor.Accept(sess)
		if err == nil {
			t.Error("Expected error after unregister")
		}
	})
}

// TestStreamingForwarder_Forward tests the Forward method.
func TestStreamingForwarder_Forward(t *testing.T) {
	forwarder := NewStreamingForwarder()
	manager := &mockStreamManager{}
	sess := &streamMockSession{id: "test-session", style: session.StyleStream}

	forwarder.RegisterManager("test-session", manager)

	t.Run("successful forward setup", func(t *testing.T) {
		listener, err := forwarder.Forward(sess, "127.0.0.1", 8080, false)
		if err != nil {
			t.Fatalf("Forward failed: %v", err)
		}
		if listener == nil {
			t.Fatal("Expected listener, got nil")
		}

		if manager.listenCount != 1 {
			t.Errorf("Expected 1 listen call, got %d", manager.listenCount)
		}
	})

	t.Run("duplicate forward fails", func(t *testing.T) {
		_, err := forwarder.Forward(sess, "127.0.0.1", 8081, false)
		if err == nil {
			t.Error("Expected error for duplicate forward")
		}
	})

	t.Run("forward with SSL", func(t *testing.T) {
		forwarder.UnregisterManager("test-session")
		forwarder.RegisterManager("test-session", manager)

		listener, err := forwarder.Forward(sess, "127.0.0.1", 443, true)
		if err != nil {
			t.Fatalf("Forward with SSL failed: %v", err)
		}
		if listener == nil {
			t.Fatal("Expected listener, got nil")
		}
	})

	t.Run("forward fails without manager", func(t *testing.T) {
		unknownSess := &streamMockSession{id: "unknown", style: session.StyleStream}
		_, err := forwarder.Forward(unknownSess, "127.0.0.1", 8080, false)
		if err == nil {
			t.Error("Expected error for unregistered session")
		}
	})
}

// TestIsHostnameOrB32 tests the hostname/b32 detection.
func TestIsHostnameOrB32(t *testing.T) {
	tests := []struct {
		dest     string
		expected bool
	}{
		{"example.i2p", true},
		{"aaaa.b32.i2p", true},
		{"longbase64destinationstring", false},
		{"AAAA", false},
		{"", false},
		{"abc", false},
		{".i2p", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("dest=%s", tt.dest), func(t *testing.T) {
			result := isHostnameOrB32(tt.dest)
			if result != tt.expected {
				t.Errorf("isHostnameOrB32(%q) = %v, want %v", tt.dest, result, tt.expected)
			}
		})
	}
}
