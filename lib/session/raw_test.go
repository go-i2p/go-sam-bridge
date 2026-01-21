// Package session implements SAM v3.0-3.3 session management.
package session

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewRawSession(t *testing.T) {
	t.Run("creates raw session with nil dependencies", func(t *testing.T) {
		session := NewRawSession("test-raw", nil, nil, nil)

		if session == nil {
			t.Fatal("NewRawSession returned nil")
		}

		if session.ID() != "test-raw" {
			t.Errorf("expected ID 'test-raw', got %s", session.ID())
		}

		if session.Style() != StyleRaw {
			t.Errorf("expected style RAW, got %s", session.Style())
		}

		if session.Status() != StatusCreating {
			t.Errorf("expected status CREATING, got %s", session.Status())
		}
	})

	t.Run("uses default protocol when not specified", func(t *testing.T) {
		session := NewRawSession("test-raw-default", nil, nil, nil)

		if session.Protocol() != DefaultRawProtocol {
			t.Errorf("expected default protocol %d, got %d", DefaultRawProtocol, session.Protocol())
		}
	})

	t.Run("uses custom protocol from config", func(t *testing.T) {
		cfg := &SessionConfig{
			Protocol: 42,
		}
		session := NewRawSession("test-raw-protocol", nil, nil, cfg)

		if session.Protocol() != 42 {
			t.Errorf("expected protocol 42, got %d", session.Protocol())
		}
	})

	t.Run("uses header setting from config", func(t *testing.T) {
		cfg := &SessionConfig{
			HeaderEnabled: true,
		}
		session := NewRawSession("test-raw-header", nil, nil, cfg)

		if !session.HeaderEnabled() {
			t.Error("expected HeaderEnabled to be true")
		}
	})

	t.Run("creates with destination", func(t *testing.T) {
		dest := &Destination{
			PublicKey:     []byte("test-public-key"),
			SignatureType: 7,
		}
		session := NewRawSession("test-raw-dest", dest, nil, nil)

		if session.Destination() == nil {
			t.Fatal("Destination should not be nil")
		}
		if session.Destination().SignatureType != 7 {
			t.Errorf("expected signature type 7, got %d", session.Destination().SignatureType)
		}
	})
}

func TestRawSessionImpl_Protocol(t *testing.T) {
	t.Run("returns default protocol 18", func(t *testing.T) {
		session := NewRawSession("test-protocol", nil, nil, nil)

		if session.Protocol() != 18 {
			t.Errorf("expected protocol 18, got %d", session.Protocol())
		}
	})

	t.Run("returns custom protocol", func(t *testing.T) {
		cfg := &SessionConfig{Protocol: 100}
		session := NewRawSession("test-protocol-custom", nil, nil, cfg)

		if session.Protocol() != 100 {
			t.Errorf("expected protocol 100, got %d", session.Protocol())
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewRawSession("test-protocol-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = session.Protocol()
			}()
		}
		wg.Wait()
	})
}

func TestRawSessionImpl_HeaderEnabled(t *testing.T) {
	t.Run("returns false by default", func(t *testing.T) {
		session := NewRawSession("test-header", nil, nil, nil)

		if session.HeaderEnabled() {
			t.Error("expected HeaderEnabled to be false by default")
		}
	})

	t.Run("returns true when enabled", func(t *testing.T) {
		cfg := &SessionConfig{HeaderEnabled: true}
		session := NewRawSession("test-header-enabled", nil, nil, cfg)

		if !session.HeaderEnabled() {
			t.Error("expected HeaderEnabled to be true")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		cfg := &SessionConfig{HeaderEnabled: true}
		session := NewRawSession("test-header-concurrent", nil, nil, cfg)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = session.HeaderEnabled()
			}()
		}
		wg.Wait()
	})
}

func TestRawSessionImpl_Send_NotActive(t *testing.T) {
	session := NewRawSession("test-send", nil, nil, nil)

	// Session is in Creating state, not Active
	err := session.Send("test.i2p", []byte("hello"), RawSendOptions{})
	if err == nil {
		t.Error("expected error when session not active")
	}
	if err != ErrSessionNotActive {
		t.Errorf("expected ErrSessionNotActive, got %v", err)
	}
}

func TestRawSessionImpl_Send_EmptyData(t *testing.T) {
	session := NewRawSession("test-send-empty", nil, nil, nil)
	session.Activate()

	err := session.Send("test.i2p", []byte{}, RawSendOptions{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestRawSessionImpl_Send_TooLargeData(t *testing.T) {
	session := NewRawSession("test-send-large", nil, nil, nil)
	session.Activate()

	// Create data larger than MaxRawDatagramSize
	largeData := make([]byte, MaxRawDatagramSize+1)
	err := session.Send("test.i2p", largeData, RawSendOptions{})
	if err == nil {
		t.Error("expected error for data exceeding max size")
	}
}

func TestRawSessionImpl_Send_InvalidProtocol(t *testing.T) {
	session := NewRawSession("test-send-invalid-protocol", nil, nil, nil)
	session.Activate()

	// Protocol 6 (TCP) is disallowed per SAM spec
	err := session.Send("test.i2p", []byte("hello"), RawSendOptions{Protocol: 6})
	if err != ErrInvalidProtocol {
		t.Errorf("expected ErrInvalidProtocol for protocol 6, got %v", err)
	}

	// Protocol 17 (UDP) is disallowed per SAM spec
	err = session.Send("test.i2p", []byte("hello"), RawSendOptions{Protocol: 17})
	if err != ErrInvalidProtocol {
		t.Errorf("expected ErrInvalidProtocol for protocol 17, got %v", err)
	}
}

func TestRawSessionImpl_Send_NotImplemented(t *testing.T) {
	session := NewRawSession("test-send-stub", nil, nil, nil)
	session.Activate()

	// Valid send should return not implemented (until go-datagrams integration)
	err := session.Send("test.i2p", []byte("hello"), RawSendOptions{})
	if err != ErrRawSendNotImplemented {
		t.Errorf("expected ErrRawSendNotImplemented, got %v", err)
	}
}

func TestRawSessionImpl_Receive(t *testing.T) {
	t.Run("returns non-nil channel", func(t *testing.T) {
		session := NewRawSession("test-receive", nil, nil, nil)

		ch := session.Receive()
		if ch == nil {
			t.Fatal("Receive() should return a channel")
		}
	})

	t.Run("channel is readable", func(t *testing.T) {
		session := NewRawSession("test-receive-read", nil, nil, nil)

		ch := session.Receive()

		// Deliver a test datagram
		session.deliverDatagram(ReceivedRawDatagram{
			FromPort: 1234,
			ToPort:   5678,
			Protocol: 18,
			Data:     []byte("test data"),
		})

		select {
		case dg := <-ch:
			if dg.FromPort != 1234 {
				t.Errorf("expected FromPort 1234, got %d", dg.FromPort)
			}
			if dg.ToPort != 5678 {
				t.Errorf("expected ToPort 5678, got %d", dg.ToPort)
			}
			if string(dg.Data) != "test data" {
				t.Errorf("expected 'test data', got %s", string(dg.Data))
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timeout waiting for datagram")
		}
	})
}

func TestRawSessionImpl_SetForwarding(t *testing.T) {
	t.Run("sets forwarding configuration", func(t *testing.T) {
		session := NewRawSession("test-forward-set", nil, nil, nil)

		err := session.SetForwarding("192.168.1.1", 9000)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if !session.IsForwarding() {
			t.Error("expected IsForwarding to be true")
		}
	})

	t.Run("uses default host when empty", func(t *testing.T) {
		session := NewRawSession("test-forward-default-host", nil, nil, nil)

		err := session.SetForwarding("", 9000)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Should use 127.0.0.1 as default
		session.mu.RLock()
		host := session.forwardHost
		session.mu.RUnlock()

		if host != "127.0.0.1" {
			t.Errorf("expected host '127.0.0.1', got '%s'", host)
		}
	})

	t.Run("rejects invalid port", func(t *testing.T) {
		session := NewRawSession("test-forward-invalid-port", nil, nil, nil)

		err := session.SetForwarding("127.0.0.1", -1)
		if err != ErrInvalidPort {
			t.Errorf("expected ErrInvalidPort, got %v", err)
		}

		err = session.SetForwarding("127.0.0.1", 65536)
		if err != ErrInvalidPort {
			t.Errorf("expected ErrInvalidPort, got %v", err)
		}
	})

	t.Run("fails when session closed", func(t *testing.T) {
		session := NewRawSession("test-forward-closed", nil, nil, nil)
		session.Close()

		err := session.SetForwarding("127.0.0.1", 9000)
		if err != ErrSessionNotActive {
			t.Errorf("expected ErrSessionNotActive, got %v", err)
		}
	})
}

func TestRawSessionImpl_IsForwarding(t *testing.T) {
	t.Run("returns false by default", func(t *testing.T) {
		session := NewRawSession("test-is-forward", nil, nil, nil)

		if session.IsForwarding() {
			t.Error("new session should not be forwarding")
		}
	})

	t.Run("returns true after SetForwarding", func(t *testing.T) {
		session := NewRawSession("test-is-forward-set", nil, nil, nil)
		session.SetForwarding("127.0.0.1", 9000)

		if !session.IsForwarding() {
			t.Error("expected IsForwarding to be true")
		}
	})
}

func TestRawSessionImpl_DeliverDatagram(t *testing.T) {
	t.Run("delivers to channel when not forwarding", func(t *testing.T) {
		session := NewRawSession("test-deliver", nil, nil, nil)

		dg := ReceivedRawDatagram{
			FromPort: 100,
			ToPort:   200,
			Protocol: 18,
			Data:     []byte("test"),
		}
		session.deliverDatagram(dg)

		select {
		case received := <-session.Receive():
			if received.FromPort != 100 {
				t.Errorf("expected FromPort 100, got %d", received.FromPort)
			}
		case <-time.After(50 * time.Millisecond):
			t.Fatal("datagram not delivered to channel")
		}
	})

	t.Run("drops datagram when channel full", func(t *testing.T) {
		session := NewRawSession("test-deliver-full", nil, nil, nil)

		// Fill the channel
		for i := 0; i < 100; i++ {
			session.deliverDatagram(ReceivedRawDatagram{Data: []byte{byte(i)}})
		}

		// This should not block or panic
		session.deliverDatagram(ReceivedRawDatagram{Data: []byte{0xFF}})
	})
}

func TestRawSessionImpl_Close(t *testing.T) {
	t.Run("closes new session", func(t *testing.T) {
		session := NewRawSession("test-close", nil, nil, nil)

		err := session.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if session.Status() != StatusClosed {
			t.Errorf("expected status CLOSED, got %s", session.Status())
		}
	})

	t.Run("close is idempotent", func(t *testing.T) {
		session := NewRawSession("test-close-idem", nil, nil, nil)

		err := session.Close()
		if err != nil {
			t.Errorf("first close error: %v", err)
		}

		err = session.Close()
		if err != nil {
			t.Errorf("second close error: %v", err)
		}
	})

	t.Run("close cancels context", func(t *testing.T) {
		session := NewRawSession("test-close-ctx", nil, nil, nil)

		session.Close()

		select {
		case <-session.ctx.Done():
			// Expected
		default:
			t.Error("context should be cancelled after close")
		}
	})

	t.Run("close closes receive channel", func(t *testing.T) {
		session := NewRawSession("test-close-chan", nil, nil, nil)
		ch := session.Receive()

		session.Close()

		// Channel should be closed
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("channel should be closed")
			}
		case <-time.After(50 * time.Millisecond):
			t.Error("channel should be closed and readable")
		}
	})

	t.Run("concurrent close is safe", func(t *testing.T) {
		session := NewRawSession("test-close-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				session.Close()
			}()
		}
		wg.Wait()

		if session.Status() != StatusClosed {
			t.Errorf("expected status CLOSED, got %s", session.Status())
		}
	})
}

func TestRawSessionImpl_ConcurrentAccess(t *testing.T) {
	session := NewRawSession("test-concurrent", nil, nil, &SessionConfig{
		Protocol:      42,
		HeaderEnabled: true,
	})
	session.Activate()

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = session.Protocol()
			_ = session.HeaderEnabled()
			_ = session.IsForwarding()
			_ = session.Status()
			_ = session.Style()
		}()
	}

	// Concurrent datagram delivery
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			session.deliverDatagram(ReceivedRawDatagram{
				FromPort: n,
				Data:     []byte{byte(n)},
			})
		}(i)
	}

	wg.Wait()
}

func TestFormatRawHeader(t *testing.T) {
	tests := []struct {
		name     string
		fromPort int
		toPort   int
		protocol int
		expected string
	}{
		{
			name:     "default ports and protocol",
			fromPort: 0,
			toPort:   0,
			protocol: 18,
			expected: "FROM_PORT=0 TO_PORT=0 PROTOCOL=18\n",
		},
		{
			name:     "custom ports",
			fromPort: 1234,
			toPort:   5678,
			protocol: 42,
			expected: "FROM_PORT=1234 TO_PORT=5678 PROTOCOL=42\n",
		},
		{
			name:     "max port values",
			fromPort: 65535,
			toPort:   65535,
			protocol: 255,
			expected: "FROM_PORT=65535 TO_PORT=65535 PROTOCOL=255\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatRawHeader(tc.fromPort, tc.toPort, tc.protocol)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{65535, "65535"},
		{-1, "-1"},
		{-123, "-123"},
	}

	for _, tc := range tests {
		result := itoa(tc.input)
		if result != tc.expected {
			t.Errorf("itoa(%d): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

// mockPacketConn is a simple mock for net.PacketConn for testing forwarding.
type mockPacketConn struct {
	writtenData []byte
	writtenAddr net.Addr
	closed      bool
	mu          sync.Mutex
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writtenData = append([]byte{}, p...)
	m.writtenAddr = addr
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7655}
}

func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRawSessionImpl_ForwardDatagram(t *testing.T) {
	t.Run("forwards without header", func(t *testing.T) {
		session := NewRawSession("test-forward-dg", nil, nil, &SessionConfig{
			HeaderEnabled: false,
		})
		session.SetForwarding("127.0.0.1", 9000)

		mockConn := &mockPacketConn{}
		session.SetUDPConn(mockConn)

		dg := ReceivedRawDatagram{
			FromPort: 1234,
			ToPort:   5678,
			Protocol: 18,
			Data:     []byte("payload"),
		}
		session.forwardDatagram(dg, false)

		mockConn.mu.Lock()
		data := mockConn.writtenData
		mockConn.mu.Unlock()

		if string(data) != "payload" {
			t.Errorf("expected 'payload', got %q", string(data))
		}
	})

	t.Run("forwards with header", func(t *testing.T) {
		session := NewRawSession("test-forward-header", nil, nil, &SessionConfig{
			HeaderEnabled: true,
		})
		session.SetForwarding("127.0.0.1", 9000)

		mockConn := &mockPacketConn{}
		session.SetUDPConn(mockConn)

		dg := ReceivedRawDatagram{
			FromPort: 1234,
			ToPort:   5678,
			Protocol: 18,
			Data:     []byte("payload"),
		}
		session.forwardDatagram(dg, true)

		mockConn.mu.Lock()
		data := mockConn.writtenData
		mockConn.mu.Unlock()

		expected := "FROM_PORT=1234 TO_PORT=5678 PROTOCOL=18\npayload"
		if string(data) != expected {
			t.Errorf("expected %q, got %q", expected, string(data))
		}
	})
}

// Ensure RawSessionImpl implements RawSession interface.
func TestRawSessionImpl_ImplementsInterface(t *testing.T) {
	var _ RawSession = (*RawSessionImpl)(nil)
}
