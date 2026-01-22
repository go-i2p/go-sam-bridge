package i2cp

import (
	"fmt"
	"testing"
)

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultClientConfig()

	if config == nil {
		t.Fatal("DefaultClientConfig returned nil")
	}

	if config.RouterAddr != "127.0.0.1:7654" {
		t.Errorf("expected router address 127.0.0.1:7654, got %s", config.RouterAddr)
	}

	if config.ConnectTimeout != 30*1e9 { // 30 seconds in nanoseconds
		t.Errorf("expected connect timeout 30s, got %v", config.ConnectTimeout)
	}

	if config.SessionTimeout != 60*1e9 { // 60 seconds in nanoseconds
		t.Errorf("expected session timeout 60s, got %v", config.SessionTimeout)
	}
}

func TestNewClient(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		client := NewClient(nil)

		if client == nil {
			t.Fatal("NewClient returned nil")
		}

		if client.config.RouterAddr != "127.0.0.1:7654" {
			t.Errorf("expected default router address, got %s", client.config.RouterAddr)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &ClientConfig{
			RouterAddr: "192.168.1.1:7654",
			Username:   "testuser",
			Password:   "testpass",
		}
		client := NewClient(config)

		if client == nil {
			t.Fatal("NewClient returned nil")
		}

		if client.config.RouterAddr != "192.168.1.1:7654" {
			t.Errorf("expected custom router address, got %s", client.config.RouterAddr)
		}
	})

	t.Run("initializes sessions map", func(t *testing.T) {
		client := NewClient(nil)

		if client.sessions == nil {
			t.Error("sessions map not initialized")
		}
	})
}

func TestClient_IsConnected(t *testing.T) {
	client := NewClient(nil)

	if client.IsConnected() {
		t.Error("new client should not be connected")
	}
}

func TestClient_I2CPClient(t *testing.T) {
	client := NewClient(nil)

	if client.I2CPClient() != nil {
		t.Error("I2CPClient should be nil when not connected")
	}
}

func TestClient_RouterVersion(t *testing.T) {
	client := NewClient(nil)

	version := client.RouterVersion()
	if version != "" {
		t.Errorf("expected empty version when not connected, got %s", version)
	}
}

func TestClient_SessionManagement(t *testing.T) {
	client := NewClient(nil)

	t.Run("GetSession returns nil for unknown ID", func(t *testing.T) {
		sess := client.GetSession("unknown")
		if sess != nil {
			t.Error("expected nil for unknown session ID")
		}
	})

	t.Run("Register and Get session", func(t *testing.T) {
		session := &I2CPSession{
			samSessionID: "test-session",
		}
		client.RegisterSession("test-session", session)

		retrieved := client.GetSession("test-session")
		if retrieved != session {
			t.Error("retrieved session does not match registered session")
		}
	})

	t.Run("Unregister session", func(t *testing.T) {
		session := &I2CPSession{
			samSessionID: "test-session-2",
		}
		client.RegisterSession("test-session-2", session)
		client.UnregisterSession("test-session-2")

		retrieved := client.GetSession("test-session-2")
		if retrieved != nil {
			t.Error("session should be nil after unregistering")
		}
	})
}

func TestClient_SetCallbacks(t *testing.T) {
	client := NewClient(nil)

	callbacks := &ClientCallbacks{
		OnConnected: func() {
			// Test callback
		},
	}
	client.SetCallbacks(callbacks)

	if client.callbacks != callbacks {
		t.Error("callbacks not set correctly")
	}
}

func TestClient_Close_NotConnected(t *testing.T) {
	client := NewClient(nil)

	err := client.Close()
	if err != nil {
		t.Errorf("closing unconnected client should not error: %v", err)
	}
}

func TestClient_Close_WithSessions(t *testing.T) {
	client := NewClient(nil)
	client.connected = true // Simulate connected state

	// Register some sessions
	sess1 := &I2CPSession{samSessionID: "session-1", active: true}
	sess2 := &I2CPSession{samSessionID: "session-2", active: true}
	client.RegisterSession("session-1", sess1)
	client.RegisterSession("session-2", sess2)

	err := client.Close()
	if err != nil {
		t.Errorf("close should not error: %v", err)
	}

	if client.connected {
		t.Error("client should be disconnected after close")
	}

	// Verify sessions are removed
	if len(client.sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(client.sessions))
	}

	// Verify sessions were closed
	if sess1.active {
		t.Error("session 1 should be inactive")
	}
	if sess2.active {
		t.Error("session 2 should be inactive")
	}
}

func TestClient_onConnect(t *testing.T) {
	client := NewClient(nil)

	// Test without callbacks - should not panic
	client.onConnect(nil)

	// Test with callback
	called := false
	client.SetCallbacks(&ClientCallbacks{
		OnConnected: func() {
			called = true
		},
	})
	client.onConnect(nil)

	if !called {
		t.Error("OnConnected callback should have been called")
	}
}

func TestClient_onDisconnect(t *testing.T) {
	client := NewClient(nil)
	client.connected = true

	// Test without callbacks - should not panic
	client.onDisconnect(nil, "", nil)

	if client.connected {
		t.Error("client should be disconnected after onDisconnect")
	}

	// Reset connected state
	client.connected = true

	// Test with callback and reason
	var receivedErr error
	client.SetCallbacks(&ClientCallbacks{
		OnDisconnected: func(err error) {
			receivedErr = err
		},
	})
	client.onDisconnect(nil, "test reason", nil)

	if receivedErr == nil {
		t.Error("expected error to be passed to OnDisconnected")
	}
	if receivedErr.Error() != "disconnected: test reason" {
		t.Errorf("unexpected error message: %v", receivedErr)
	}
}

func TestClient_onDisconnect_EmptyReason(t *testing.T) {
	client := NewClient(nil)
	client.connected = true

	var receivedErr error
	client.SetCallbacks(&ClientCallbacks{
		OnDisconnected: func(err error) {
			receivedErr = err
		},
	})
	client.onDisconnect(nil, "", nil)

	if receivedErr != nil {
		t.Errorf("expected nil error for empty reason, got: %v", receivedErr)
	}
}

func TestClient_RouterVersion_Concurrent(t *testing.T) {
	client := NewClient(nil)

	// Test concurrent access to RouterVersion - should be thread-safe
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = client.RouterVersion()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestClient_SessionManagement_Concurrent(t *testing.T) {
	client := NewClient(nil)

	// Test concurrent session registration and retrieval
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(n int) {
			id := fmt.Sprintf("session-%d", n)
			sess := &I2CPSession{samSessionID: id}
			client.RegisterSession(id, sess)
			_ = client.GetSession(id)
			client.UnregisterSession(id)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
