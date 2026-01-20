// Package session implements SAM v3.0-3.3 session management.
package session

import (
	"testing"
	"time"
)

func TestNewStreamSession(t *testing.T) {
	t.Run("creates stream session with nil dependencies", func(t *testing.T) {
		session := NewStreamSession("test-stream", nil, nil, nil, nil, nil)

		if session == nil {
			t.Fatal("NewStreamSession returned nil")
		}

		if session.ID() != "test-stream" {
			t.Errorf("expected ID 'test-stream', got %s", session.ID())
		}

		if session.Style() != StyleStream {
			t.Errorf("expected style STREAM, got %s", session.Style())
		}

		if session.Status() != StatusCreating {
			t.Errorf("expected status CREATING, got %s", session.Status())
		}
	})

	t.Run("creates stream session with config", func(t *testing.T) {
		cfg := &SessionConfig{
			FromPort: 1234,
			ToPort:   5678,
		}
		session := NewStreamSession("test-stream-cfg", nil, nil, cfg, nil, nil)

		if session.Config() == nil {
			t.Fatal("Config should not be nil")
		}

		if session.Config().FromPort != 1234 {
			t.Errorf("expected FromPort 1234, got %d", session.Config().FromPort)
		}
	})

	t.Run("uses default config when nil", func(t *testing.T) {
		session := NewStreamSession("test-stream-default", nil, nil, nil, nil, nil)

		if session.Config() == nil {
			t.Fatal("Config should default when nil")
		}
	})
}

func TestStreamSessionImpl_IsForwarding(t *testing.T) {
	session := NewStreamSession("test-forward", nil, nil, nil, nil, nil)

	if session.IsForwarding() {
		t.Error("new session should not be forwarding")
	}
}

func TestStreamSessionImpl_Connect_NotActive(t *testing.T) {
	session := NewStreamSession("test-connect", nil, nil, nil, nil, nil)

	// Session is in Creating state, not Active
	_, err := session.Connect("test.i2p", ConnectOptions{})
	if err == nil {
		t.Error("expected error when session not active")
	}
	if err != ErrSessionNotActive {
		t.Errorf("expected ErrSessionNotActive, got %v", err)
	}
}

func TestStreamSessionImpl_Accept_NotActive(t *testing.T) {
	session := NewStreamSession("test-accept", nil, nil, nil, nil, nil)

	// Session is in Creating state, not Active
	_, _, err := session.Accept(AcceptOptions{})
	if err == nil {
		t.Error("expected error when session not active")
	}
	if err != ErrSessionNotActive {
		t.Errorf("expected ErrSessionNotActive, got %v", err)
	}
}

func TestStreamSessionImpl_Forward_NotActive(t *testing.T) {
	session := NewStreamSession("test-forward", nil, nil, nil, nil, nil)

	// Session is in Creating state, not Active
	err := session.Forward("127.0.0.1", 8080, ForwardOptions{})
	if err == nil {
		t.Error("expected error when session not active")
	}
	if err != ErrSessionNotActive {
		t.Errorf("expected ErrSessionNotActive, got %v", err)
	}
}

func TestStreamSessionImpl_Connect_NoManager(t *testing.T) {
	session := NewStreamSession("test-connect-no-mgr", nil, nil, nil, nil, nil)
	session.Activate() // Make it active

	_, err := session.Connect("test.i2p", ConnectOptions{})
	if err == nil {
		t.Error("expected error when stream manager is nil")
	}
}

func TestStreamSessionImpl_Accept_NoManager(t *testing.T) {
	session := NewStreamSession("test-accept-no-mgr", nil, nil, nil, nil, nil)
	session.Activate() // Make it active

	_, _, err := session.Accept(AcceptOptions{})
	if err == nil {
		t.Error("expected error when stream manager is nil")
	}
}

func TestStreamSessionImpl_Forward_NoManager(t *testing.T) {
	session := NewStreamSession("test-forward-no-mgr", nil, nil, nil, nil, nil)
	session.Activate() // Make it active

	err := session.Forward("127.0.0.1", 8080, ForwardOptions{})
	if err == nil {
		t.Error("expected error when stream manager is nil")
	}
}

func TestStreamSessionImpl_Close(t *testing.T) {
	t.Run("close new session", func(t *testing.T) {
		session := NewStreamSession("test-close", nil, nil, nil, nil, nil)

		err := session.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if session.Status() != StatusClosed {
			t.Errorf("expected status CLOSED, got %s", session.Status())
		}
	})

	t.Run("close is idempotent", func(t *testing.T) {
		session := NewStreamSession("test-close-idem", nil, nil, nil, nil, nil)

		err := session.Close()
		if err != nil {
			t.Errorf("first close error: %v", err)
		}

		err = session.Close()
		if err != nil {
			t.Errorf("second close error: %v", err)
		}
	})

	t.Run("close active session", func(t *testing.T) {
		session := NewStreamSession("test-close-active", nil, nil, nil, nil, nil)
		session.Activate()

		err := session.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if session.Status() != StatusClosed {
			t.Errorf("expected status CLOSED, got %s", session.Status())
		}
	})
}

func TestStreamSessionImpl_I2CPSession(t *testing.T) {
	session := NewStreamSession("test-i2cp", nil, nil, nil, nil, nil)

	if session.I2CPSession() != nil {
		t.Error("I2CPSession should be nil when not set")
	}
}

func TestStreamSessionImpl_StreamManager(t *testing.T) {
	session := NewStreamSession("test-mgr", nil, nil, nil, nil, nil)

	if session.StreamManager() != nil {
		t.Error("StreamManager should be nil when not set")
	}
}

func TestStreamSessionImpl_CloseWithControlConn(t *testing.T) {
	conn := &mockConn{}
	session := NewStreamSession("test-close-conn", nil, conn, nil, nil, nil)
	session.Activate()

	err := session.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !conn.closed {
		t.Error("control connection should be closed")
	}
}

func TestConnectOptionsTimeout(t *testing.T) {
	opts := ConnectOptions{
		FromPort: 1234,
		ToPort:   5678,
		Timeout:  30 * time.Second,
	}

	if opts.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", opts.Timeout)
	}
}

func TestAcceptOptionsTimeout(t *testing.T) {
	opts := AcceptOptions{
		Silent:  true,
		Timeout: 60 * time.Second,
	}

	if opts.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", opts.Timeout)
	}
}

func TestStreamSessionImplementsInterface(t *testing.T) {
	// Compile-time check that StreamSessionImpl implements StreamSession
	var _ StreamSession = (*StreamSessionImpl)(nil)
}
