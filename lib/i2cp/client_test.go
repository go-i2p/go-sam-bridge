package i2cp

import (
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
