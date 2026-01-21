package bridge

import (
	"net"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	readData   []byte
	readOffset int
	writeData  []byte
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
}

func newMockConn() *mockConn {
	return &mockConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7656},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readOffset >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readOffset:])
	m.readOffset += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr  { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr { return m.remoteAddr }

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConnectionState_String(t *testing.T) {
	tests := []struct {
		state ConnectionState
		want  string
	}{
		{StateNew, "NEW"},
		{StateHandshaking, "HANDSHAKING"},
		{StateReady, "READY"},
		{StateSessionBound, "SESSION_BOUND"},
		{StateClosed, "CLOSED"},
		{ConnectionState(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewConnection(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	if c.State() != StateNew {
		t.Errorf("State() = %v, want %v", c.State(), StateNew)
	}
	if c.Conn() != conn {
		t.Error("Conn() did not return the underlying connection")
	}
	if c.Reader() == nil {
		t.Error("Reader() = nil, want non-nil")
	}
	if c.RemoteAddr() != "127.0.0.1:12345" {
		t.Errorf("RemoteAddr() = %q, want %q", c.RemoteAddr(), "127.0.0.1:12345")
	}
	if c.CreatedAt().IsZero() {
		t.Error("CreatedAt() is zero")
	}
	if c.LastActivity().IsZero() {
		t.Error("LastActivity() is zero")
	}
	if c.Version() != "" {
		t.Errorf("Version() = %q, want empty", c.Version())
	}
	if c.IsAuthenticated() {
		t.Error("IsAuthenticated() = true, want false")
	}
	if c.SessionID() != "" {
		t.Errorf("SessionID() = %q, want empty", c.SessionID())
	}
}

func TestConnection_SetState(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	c.SetState(StateHandshaking)
	if c.State() != StateHandshaking {
		t.Errorf("State() = %v, want %v", c.State(), StateHandshaking)
	}

	c.SetState(StateReady)
	if c.State() != StateReady {
		t.Errorf("State() = %v, want %v", c.State(), StateReady)
	}
}

func TestConnection_SetVersion(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	c.SetVersion("3.3")
	if c.Version() != "3.3" {
		t.Errorf("Version() = %q, want %q", c.Version(), "3.3")
	}
}

func TestConnection_Authentication(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	if c.IsAuthenticated() {
		t.Error("IsAuthenticated() = true, want false")
	}
	if c.Username() != "" {
		t.Errorf("Username() = %q, want empty", c.Username())
	}

	c.SetAuthenticated("testuser")

	if !c.IsAuthenticated() {
		t.Error("IsAuthenticated() = false, want true")
	}
	if c.Username() != "testuser" {
		t.Errorf("Username() = %q, want %q", c.Username(), "testuser")
	}
}

func TestConnection_BindSession(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	c.SetState(StateReady)
	c.BindSession("session123")

	if c.SessionID() != "session123" {
		t.Errorf("SessionID() = %q, want %q", c.SessionID(), "session123")
	}
	if c.State() != StateSessionBound {
		t.Errorf("State() = %v, want %v", c.State(), StateSessionBound)
	}
}

func TestConnection_UnbindSession(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	c.SetState(StateReady)
	c.BindSession("session123")
	c.UnbindSession()

	if c.SessionID() != "" {
		t.Errorf("SessionID() = %q, want empty", c.SessionID())
	}
	if c.State() != StateReady {
		t.Errorf("State() = %v, want %v", c.State(), StateReady)
	}
}

func TestConnection_UnbindSession_NotBound(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	c.SetState(StateReady)
	c.UnbindSession() // Should not panic or change state

	if c.State() != StateReady {
		t.Errorf("State() = %v, want %v", c.State(), StateReady)
	}
}

func TestConnection_UpdateActivity(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	initial := c.LastActivity()
	time.Sleep(10 * time.Millisecond)
	c.UpdateActivity()

	if !c.LastActivity().After(initial) {
		t.Error("LastActivity() was not updated")
	}
}

func TestConnection_IdleDuration(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	time.Sleep(10 * time.Millisecond)
	idle := c.IdleDuration()

	if idle < 10*time.Millisecond {
		t.Errorf("IdleDuration() = %v, want >= 10ms", idle)
	}
}

func TestConnection_Age(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	time.Sleep(10 * time.Millisecond)
	age := c.Age()

	if age < 10*time.Millisecond {
		t.Errorf("Age() = %v, want >= 10ms", age)
	}
}

func TestConnection_Close(t *testing.T) {
	mc := newMockConn()
	c := NewConnection(mc, 1024)

	err := c.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
	if !mc.closed {
		t.Error("underlying connection was not closed")
	}
	if c.State() != StateClosed {
		t.Errorf("State() = %v, want %v", c.State(), StateClosed)
	}
	if !c.IsClosed() {
		t.Error("IsClosed() = false, want true")
	}
}

func TestConnection_Write(t *testing.T) {
	mc := newMockConn()
	c := NewConnection(mc, 1024)

	n, err := c.Write([]byte("test data"))
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}
	if n != 9 {
		t.Errorf("Write() = %d, want 9", n)
	}
	if string(mc.writeData) != "test data" {
		t.Errorf("written data = %q, want %q", string(mc.writeData), "test data")
	}
}

func TestConnection_WriteString(t *testing.T) {
	mc := newMockConn()
	c := NewConnection(mc, 1024)

	n, err := c.WriteString("hello")
	if err != nil {
		t.Errorf("WriteString() error = %v", err)
	}
	if n != 5 {
		t.Errorf("WriteString() = %d, want 5", n)
	}
	if string(mc.writeData) != "hello" {
		t.Errorf("written data = %q, want %q", string(mc.writeData), "hello")
	}
}

func TestConnection_WriteLine(t *testing.T) {
	mc := newMockConn()
	c := NewConnection(mc, 1024)

	n, err := c.WriteLine("HELLO REPLY RESULT=OK")
	if err != nil {
		t.Errorf("WriteLine() error = %v", err)
	}
	expected := "HELLO REPLY RESULT=OK\n"
	if n != len(expected) {
		t.Errorf("WriteLine() = %d, want %d", n, len(expected))
	}
	if string(mc.writeData) != expected {
		t.Errorf("written data = %q, want %q", string(mc.writeData), expected)
	}
}

func TestConnection_SetDeadlines(t *testing.T) {
	mc := newMockConn()
	c := NewConnection(mc, 1024)

	deadline := time.Now().Add(time.Second)

	err := c.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("SetReadDeadline() error = %v", err)
	}

	err = c.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline() error = %v", err)
	}
}

func TestConnection_ConcurrentAccess(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	done := make(chan bool)

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			_ = c.State()
			_ = c.Version()
			_ = c.IsAuthenticated()
			_ = c.SessionID()
		}
		done <- true
	}()

	// Concurrent writes
	go func() {
		for i := 0; i < 100; i++ {
			c.SetState(StateReady)
			c.SetVersion("3.3")
			c.UpdateActivity()
		}
		done <- true
	}()

	<-done
	<-done
}

func TestConnection_PendingPing(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	// Initially no pending ping
	if pending := c.GetPendingPing(); pending != nil {
		t.Error("expected no pending ping initially")
	}

	// Set pending ping
	c.SetPendingPing("test-ping")
	pending := c.GetPendingPing()
	if pending == nil {
		t.Fatal("expected pending ping")
	}
	if pending.Text != "test-ping" {
		t.Errorf("pending text = %q, want %q", pending.Text, "test-ping")
	}
	if time.Since(pending.SentAt) > time.Second {
		t.Error("pending SentAt should be recent")
	}

	// Clear pending ping
	c.ClearPendingPing()
	if c.GetPendingPing() != nil {
		t.Error("expected no pending ping after clear")
	}
}

func TestConnection_IsPongOverdue(t *testing.T) {
	conn := newMockConn()
	c := NewConnection(conn, 1024)

	// No pending ping - not overdue
	if c.IsPongOverdue(time.Second) {
		t.Error("expected not overdue with no pending ping")
	}

	// Set pending ping
	c.SetPendingPing("test")

	// Just set - not overdue
	if c.IsPongOverdue(time.Second) {
		t.Error("expected not overdue immediately after setting")
	}

	// Zero timeout - never overdue
	if c.IsPongOverdue(0) {
		t.Error("expected not overdue with zero timeout")
	}

	// Simulate old pending ping by manually setting SentAt
	c.mu.Lock()
	c.pendingPing.SentAt = time.Now().Add(-2 * time.Second)
	c.mu.Unlock()

	// Now should be overdue with 1 second timeout
	if !c.IsPongOverdue(time.Second) {
		t.Error("expected overdue after timeout elapsed")
	}

	// But not overdue with longer timeout
	if c.IsPongOverdue(5 * time.Second) {
		t.Error("expected not overdue with longer timeout")
	}
}
