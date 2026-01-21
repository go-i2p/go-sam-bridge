// Package session implements SAM v3.0-3.3 session management.
package session

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewDatagramSession(t *testing.T) {
	t.Run("creates datagram session with nil dependencies", func(t *testing.T) {
		session := NewDatagramSession("test-dg", nil, nil, nil)

		if session == nil {
			t.Fatal("NewDatagramSession returned nil")
		}

		if session.ID() != "test-dg" {
			t.Errorf("expected ID 'test-dg', got %s", session.ID())
		}

		if session.Style() != StyleDatagram {
			t.Errorf("expected style DATAGRAM, got %s", session.Style())
		}

		if session.Status() != StatusCreating {
			t.Errorf("expected status CREATING, got %s", session.Status())
		}
	})

	t.Run("creates with destination", func(t *testing.T) {
		dest := &Destination{
			PublicKey:     []byte("test-public-key"),
			SignatureType: 7,
		}
		session := NewDatagramSession("test-dg-dest", dest, nil, nil)

		if session.Destination() == nil {
			t.Fatal("Destination should not be nil")
		}
		if session.Destination().SignatureType != 7 {
			t.Errorf("expected signature type 7, got %d", session.Destination().SignatureType)
		}
	})

	t.Run("creates with custom config", func(t *testing.T) {
		cfg := &SessionConfig{
			FromPort:        1234,
			ToPort:          5678,
			InboundQuantity: 5,
		}
		session := NewDatagramSession("test-dg-cfg", nil, nil, cfg)

		if session.Config().FromPort != 1234 {
			t.Errorf("expected FromPort 1234, got %d", session.Config().FromPort)
		}
		if session.Config().ToPort != 5678 {
			t.Errorf("expected ToPort 5678, got %d", session.Config().ToPort)
		}
	})

	t.Run("creates receive channel", func(t *testing.T) {
		session := NewDatagramSession("test-dg-chan", nil, nil, nil)

		ch := session.Receive()
		if ch == nil {
			t.Fatal("Receive channel should not be nil")
		}
	})
}

func TestDatagramSessionImpl_Send(t *testing.T) {
	t.Run("returns error when session not active", func(t *testing.T) {
		session := NewDatagramSession("test-send", nil, nil, nil)
		// Session is in CREATING state, not ACTIVE

		err := session.Send("test-dest", []byte("test"), DatagramSendOptions{})
		if err != ErrSessionNotActive {
			t.Errorf("expected ErrSessionNotActive, got %v", err)
		}
	})

	t.Run("returns error for empty data", func(t *testing.T) {
		session := NewDatagramSession("test-send-empty", nil, nil, nil)
		session.Activate()

		err := session.Send("test-dest", []byte{}, DatagramSendOptions{})
		if err == nil {
			t.Error("expected error for empty data")
		}
	})

	t.Run("returns error for data exceeding max size", func(t *testing.T) {
		session := NewDatagramSession("test-send-large", nil, nil, nil)
		session.Activate()

		// Create data larger than MaxDatagramSize
		largeData := make([]byte, MaxDatagramSize+1)
		err := session.Send("test-dest", largeData, DatagramSendOptions{})
		if err == nil {
			t.Error("expected error for oversized data")
		}
	})

	t.Run("returns error for invalid FromPort", func(t *testing.T) {
		session := NewDatagramSession("test-send-port", nil, nil, nil)
		session.Activate()

		err := session.Send("test-dest", []byte("test"), DatagramSendOptions{
			FromPort: -1,
		})
		if err != ErrInvalidPort {
			t.Errorf("expected ErrInvalidPort, got %v", err)
		}
	})

	t.Run("returns error for invalid ToPort", func(t *testing.T) {
		session := NewDatagramSession("test-send-toport", nil, nil, nil)
		session.Activate()

		err := session.Send("test-dest", []byte("test"), DatagramSendOptions{
			ToPort: 70000,
		})
		if err != ErrInvalidPort {
			t.Errorf("expected ErrInvalidPort, got %v", err)
		}
	})

	t.Run("returns not implemented for valid send", func(t *testing.T) {
		session := NewDatagramSession("test-send-valid", nil, nil, nil)
		session.Activate()

		err := session.Send("test-dest", []byte("test data"), DatagramSendOptions{
			FromPort: 1234,
			ToPort:   5678,
		})
		if err != ErrDatagramSendNotImplemented {
			t.Errorf("expected ErrDatagramSendNotImplemented, got %v", err)
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-send-concurrent", nil, nil, nil)
		session.Activate()

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = session.Send("test-dest", []byte("test"), DatagramSendOptions{})
			}()
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_Receive(t *testing.T) {
	t.Run("returns receive channel", func(t *testing.T) {
		session := NewDatagramSession("test-receive", nil, nil, nil)

		ch := session.Receive()
		if ch == nil {
			t.Fatal("Receive() should return non-nil channel")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-receive-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = session.Receive()
			}()
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_SetForwarding(t *testing.T) {
	t.Run("sets forwarding when creating", func(t *testing.T) {
		session := NewDatagramSession("test-fwd-creating", nil, nil, nil)

		err := session.SetForwarding("127.0.0.1", 8080)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if !session.IsForwarding() {
			t.Error("expected IsForwarding to be true")
		}
	})

	t.Run("sets forwarding when active", func(t *testing.T) {
		session := NewDatagramSession("test-fwd-active", nil, nil, nil)
		session.Activate()

		err := session.SetForwarding("192.168.1.1", 9000)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if !session.IsForwarding() {
			t.Error("expected IsForwarding to be true")
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		session := NewDatagramSession("test-fwd-closed", nil, nil, nil)
		session.Activate()
		session.Close()

		err := session.SetForwarding("127.0.0.1", 8080)
		if err != ErrSessionNotActive {
			t.Errorf("expected ErrSessionNotActive, got %v", err)
		}
	})

	t.Run("returns error for invalid port", func(t *testing.T) {
		session := NewDatagramSession("test-fwd-invalid", nil, nil, nil)

		err := session.SetForwarding("127.0.0.1", -1)
		if err != ErrInvalidPort {
			t.Errorf("expected ErrInvalidPort, got %v", err)
		}

		err = session.SetForwarding("127.0.0.1", 70000)
		if err != ErrInvalidPort {
			t.Errorf("expected ErrInvalidPort, got %v", err)
		}
	})

	t.Run("uses default host when empty", func(t *testing.T) {
		session := NewDatagramSession("test-fwd-default-host", nil, nil, nil)

		err := session.SetForwarding("", 8080)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Check internal state through IsForwarding
		if !session.IsForwarding() {
			t.Error("expected IsForwarding to be true")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-fwd-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			port := 8000 + i
			go func(p int) {
				defer wg.Done()
				_ = session.SetForwarding("127.0.0.1", p)
			}(port)
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_ForwardingAddr(t *testing.T) {
	t.Run("returns nil when not configured", func(t *testing.T) {
		session := NewDatagramSession("test-addr-none", nil, nil, nil)

		if session.ForwardingAddr() != nil {
			t.Error("expected nil ForwardingAddr")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-addr-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = session.ForwardingAddr()
			}()
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_IsForwarding(t *testing.T) {
	t.Run("returns false by default", func(t *testing.T) {
		session := NewDatagramSession("test-isfwd-default", nil, nil, nil)

		if session.IsForwarding() {
			t.Error("expected IsForwarding to be false by default")
		}
	})

	t.Run("returns true after SetForwarding", func(t *testing.T) {
		session := NewDatagramSession("test-isfwd-set", nil, nil, nil)
		session.SetForwarding("127.0.0.1", 8080)

		if !session.IsForwarding() {
			t.Error("expected IsForwarding to be true")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-isfwd-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = session.IsForwarding()
			}()
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_deliverDatagram(t *testing.T) {
	t.Run("delivers to channel when not forwarding", func(t *testing.T) {
		session := NewDatagramSession("test-deliver-chan", nil, nil, nil)
		session.Activate()

		dg := ReceivedDatagram{
			Source:   "test-source-destination",
			FromPort: 1234,
			ToPort:   5678,
			Data:     []byte("test data"),
		}

		session.deliverDatagram(dg)

		select {
		case received := <-session.Receive():
			if received.Source != dg.Source {
				t.Errorf("expected source %s, got %s", dg.Source, received.Source)
			}
			if string(received.Data) != "test data" {
				t.Errorf("expected data 'test data', got %s", string(received.Data))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("timeout waiting for datagram")
		}
	})

	t.Run("drops datagram when channel full", func(t *testing.T) {
		session := NewDatagramSession("test-deliver-full", nil, nil, nil)
		session.Activate()

		// Fill the channel
		for i := 0; i < 100; i++ {
			session.deliverDatagram(ReceivedDatagram{
				Source: "source",
				Data:   []byte("data"),
			})
		}

		// This should not block
		done := make(chan bool)
		go func() {
			session.deliverDatagram(ReceivedDatagram{
				Source: "overflow",
				Data:   []byte("overflow-data"),
			})
			done <- true
		}()

		select {
		case <-done:
			// Good, didn't block
		case <-time.After(100 * time.Millisecond):
			t.Error("deliverDatagram blocked when channel was full")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-deliver-concurrent", nil, nil, nil)
		session.Activate()

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				session.deliverDatagram(ReceivedDatagram{
					Source: "source",
					Data:   []byte("data"),
				})
			}(i)
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_SetUDPConn(t *testing.T) {
	t.Run("sets UDP connection", func(t *testing.T) {
		session := NewDatagramSession("test-udp", nil, nil, nil)

		// Create a mock packet conn
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create packet conn: %v", err)
		}
		defer conn.Close()

		session.SetUDPConn(conn)

		// Verify through IsForwarding test (with forwarding set)
		session.SetForwarding("127.0.0.1", 9999)
		if !session.IsForwarding() {
			t.Error("expected forwarding to be configured")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-udp-concurrent", nil, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				session.SetUDPConn(nil)
			}()
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_Close(t *testing.T) {
	t.Run("closes session", func(t *testing.T) {
		session := NewDatagramSession("test-close", nil, nil, nil)
		session.Activate()

		err := session.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if session.Status() != StatusClosed {
			t.Errorf("expected status CLOSED, got %s", session.Status())
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		session := NewDatagramSession("test-close-multi", nil, nil, nil)
		session.Activate()

		err1 := session.Close()
		err2 := session.Close()
		err3 := session.Close()

		if err1 != nil || err2 != nil || err3 != nil {
			t.Error("Close should be idempotent and not return errors")
		}
	})

	t.Run("closes receive channel", func(t *testing.T) {
		session := NewDatagramSession("test-close-chan", nil, nil, nil)
		session.Activate()

		ch := session.Receive()
		session.Close()

		// Channel should be closed
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("channel should be closed")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("timeout waiting for channel close")
		}
	})

	t.Run("closes UDP connection", func(t *testing.T) {
		session := NewDatagramSession("test-close-udp", nil, nil, nil)
		session.Activate()

		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create packet conn: %v", err)
		}
		session.SetUDPConn(conn)

		session.Close()

		// Try to use the connection - should fail if closed
		_, err = conn.WriteTo([]byte("test"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
		if err == nil {
			t.Error("expected error writing to closed connection")
		}
	})

	t.Run("is thread-safe", func(t *testing.T) {
		session := NewDatagramSession("test-close-concurrent", nil, nil, nil)
		session.Activate()

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				session.Close()
			}()
		}
		wg.Wait()
	})
}

func TestDatagramSessionImpl_InterfaceCompliance(t *testing.T) {
	t.Run("implements DatagramSession interface", func(t *testing.T) {
		var _ DatagramSession = (*DatagramSessionImpl)(nil)
	})

	t.Run("implements Session interface", func(t *testing.T) {
		var _ Session = (*DatagramSessionImpl)(nil)
	})
}

func TestMaxDatagramSize(t *testing.T) {
	t.Run("has correct value", func(t *testing.T) {
		// Per SAM specification, repliable datagrams max at ~31KB due to signature overhead
		if MaxDatagramSize != 31744 {
			t.Errorf("expected MaxDatagramSize 31744, got %d", MaxDatagramSize)
		}
	})
}

func TestErrDatagramSendNotImplemented(t *testing.T) {
	t.Run("has descriptive message", func(t *testing.T) {
		msg := ErrDatagramSendNotImplemented.Error()
		if msg == "" {
			t.Error("error message should not be empty")
		}
		if len(msg) < 20 {
			t.Error("error message should be descriptive")
		}
	})
}
