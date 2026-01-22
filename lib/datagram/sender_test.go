package datagram

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockDatagramConnection implements DatagramConnection for testing.
type mockDatagramConnection struct {
	sendError   error
	sendCount   int
	lastPayload []byte
	lastDest    string
	lastPort    uint16
	lastOpts    *I2PDatagramOptions
	protocol    uint8
	closed      bool
}

func (m *mockDatagramConnection) SendTo(payload []byte, destB64 string, port uint16) error {
	m.sendCount++
	m.lastPayload = payload
	m.lastDest = destB64
	m.lastPort = port
	return m.sendError
}

func (m *mockDatagramConnection) SendToWithOptions(payload []byte, destB64 string, port uint16, opts *I2PDatagramOptions) error {
	m.sendCount++
	m.lastPayload = payload
	m.lastDest = destB64
	m.lastPort = port
	m.lastOpts = opts
	return m.sendError
}

func (m *mockDatagramConnection) Protocol() uint8 {
	return m.protocol
}

func (m *mockDatagramConnection) Close() error {
	m.closed = true
	return nil
}

// TestI2CPDatagramSender_SendDatagram tests datagram sending.
func TestI2CPDatagramSender_SendDatagram(t *testing.T) {
	conn := &mockDatagramConnection{protocol: 17} // Datagram1
	sender := NewI2CPDatagramSender(conn)

	t.Run("simple send", func(t *testing.T) {
		opts := DatagramSendOptions{
			FromPort: 1234,
			ToPort:   80,
		}

		err := sender.SendDatagram("dest123", []byte("hello"), opts)
		if err != nil {
			t.Fatalf("SendDatagram failed: %v", err)
		}

		if conn.sendCount != 1 {
			t.Errorf("Expected 1 send, got %d", conn.sendCount)
		}
		if string(conn.lastPayload) != "hello" {
			t.Errorf("Expected payload 'hello', got %q", conn.lastPayload)
		}
		if conn.lastDest != "dest123" {
			t.Errorf("Expected dest 'dest123', got %q", conn.lastDest)
		}
		if conn.lastPort != 80 {
			t.Errorf("Expected port 80, got %d", conn.lastPort)
		}
	})

	conn.sendCount = 0

	t.Run("send with SAM 3.3 options", func(t *testing.T) {
		sendLeaseset := true
		opts := DatagramSendOptions{
			ToPort:       8080,
			SendTags:     10,
			TagThreshold: 5,
			Expires:      60,
			SendLeaseSet: &sendLeaseset,
		}

		err := sender.SendDatagram("dest456", []byte("data"), opts)
		if err != nil {
			t.Fatalf("SendDatagram failed: %v", err)
		}

		if conn.lastOpts == nil {
			t.Fatal("Expected options, got nil")
		}
		if conn.lastOpts.SendTags != 10 {
			t.Errorf("Expected SendTags 10, got %d", conn.lastOpts.SendTags)
		}
		if conn.lastOpts.TagThreshold != 5 {
			t.Errorf("Expected TagThreshold 5, got %d", conn.lastOpts.TagThreshold)
		}
		if conn.lastOpts.Expires != 60 {
			t.Errorf("Expected Expires 60, got %d", conn.lastOpts.Expires)
		}
		if !conn.lastOpts.SendLeaseSet {
			t.Error("Expected SendLeaseSet true")
		}
	})

	t.Run("send error propagates", func(t *testing.T) {
		conn.sendError = errors.New("send failed")
		defer func() { conn.sendError = nil }()

		err := sender.SendDatagram("dest", []byte("data"), DatagramSendOptions{})
		if err == nil {
			t.Error("Expected error to propagate")
		}
	})
}

// TestI2CPDatagramSender_SendRaw tests raw datagram sending.
func TestI2CPDatagramSender_SendRaw(t *testing.T) {
	conn := &mockDatagramConnection{protocol: 18} // Raw
	sender := NewI2CPDatagramSender(conn)

	t.Run("simple raw send", func(t *testing.T) {
		opts := RawSendOptions{
			FromPort: 1234,
			ToPort:   80,
			Protocol: 18,
		}

		err := sender.SendRaw("dest123", []byte("rawdata"), opts)
		if err != nil {
			t.Fatalf("SendRaw failed: %v", err)
		}

		if string(conn.lastPayload) != "rawdata" {
			t.Errorf("Expected payload 'rawdata', got %q", conn.lastPayload)
		}
	})

	conn.sendCount = 0

	t.Run("raw send with SAM 3.3 options", func(t *testing.T) {
		sendLeaseset := false
		opts := RawSendOptions{
			ToPort:       9000,
			SendTags:     20,
			TagThreshold: 10,
			Expires:      120,
			SendLeaseSet: &sendLeaseset,
		}

		err := sender.SendRaw("dest789", []byte("data"), opts)
		if err != nil {
			t.Fatalf("SendRaw failed: %v", err)
		}

		if conn.lastOpts == nil {
			t.Fatal("Expected options, got nil")
		}
		if conn.lastOpts.SendTags != 20 {
			t.Errorf("Expected SendTags 20, got %d", conn.lastOpts.SendTags)
		}
		if conn.lastOpts.SendLeaseSet {
			t.Error("Expected SendLeaseSet false")
		}
	})
}

// TestI2CPDatagramSender_Close tests sender cleanup.
func TestI2CPDatagramSender_Close(t *testing.T) {
	conn := &mockDatagramConnection{protocol: 18}
	sender := NewI2CPDatagramSender(conn)

	err := sender.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !conn.closed {
		t.Error("Expected connection to be closed")
	}
}

// senderMockSession implements session.Session for testing DatagramSender.
// This is separate from mockSession in udp_test.go to avoid conflicts.
type senderMockSession struct {
	id    string
	style session.Style
}

func (s *senderMockSession) ID() string                        { return s.id }
func (s *senderMockSession) Style() session.Style              { return s.style }
func (s *senderMockSession) Destination() *session.Destination { return nil }
func (s *senderMockSession) Status() session.Status            { return session.StatusActive }
func (s *senderMockSession) ControlConn() net.Conn             { return nil }
func (s *senderMockSession) Close() error                      { return nil }

// mockSenderFactory implements DatagramSenderFactory for testing.
type mockSenderFactory struct {
	createError     error
	createdPort     int
	createdProtocol uint8
}

func (f *mockSenderFactory) Create(ctx context.Context, sess session.Session, port int, protocol uint8) (DatagramSender, error) {
	f.createdPort = port
	f.createdProtocol = protocol
	if f.createError != nil {
		return nil, f.createError
	}
	conn := &mockDatagramConnection{protocol: protocol}
	return NewI2CPDatagramSender(conn), nil
}

// TestSessionDatagramManager tests per-session datagram management.
func TestSessionDatagramManager(t *testing.T) {
	factory := &mockSenderFactory{}
	manager := NewSessionDatagramManager(factory)
	sess := &senderMockSession{id: "test-session", style: session.StyleDatagram}
	ctx := context.Background()

	t.Run("register session creates sender", func(t *testing.T) {
		err := manager.RegisterSession(ctx, sess, 7655, 17)
		if err != nil {
			t.Fatalf("RegisterSession failed: %v", err)
		}

		if factory.createdPort != 7655 {
			t.Errorf("Expected port 7655, got %d", factory.createdPort)
		}
		if factory.createdProtocol != 17 {
			t.Errorf("Expected protocol 17, got %d", factory.createdProtocol)
		}

		sender := manager.GetSender("test-session")
		if sender == nil {
			t.Error("Expected sender, got nil")
		}
	})

	t.Run("duplicate registration fails", func(t *testing.T) {
		err := manager.RegisterSession(ctx, sess, 7656, 17)
		if err == nil {
			t.Error("Expected error for duplicate registration")
		}
	})

	t.Run("get sender for unknown session returns nil", func(t *testing.T) {
		sender := manager.GetSender("unknown")
		if sender != nil {
			t.Error("Expected nil for unknown session")
		}
	})

	t.Run("unregister removes sender", func(t *testing.T) {
		err := manager.UnregisterSession("test-session")
		if err != nil {
			t.Fatalf("UnregisterSession failed: %v", err)
		}

		sender := manager.GetSender("test-session")
		if sender != nil {
			t.Error("Expected nil after unregister")
		}
	})

	t.Run("factory error propagates", func(t *testing.T) {
		factory.createError = errors.New("factory error")
		defer func() { factory.createError = nil }()

		err := manager.RegisterSession(ctx, sess, 7655, 17)
		if err == nil {
			t.Error("Expected factory error to propagate")
		}
	})
}
