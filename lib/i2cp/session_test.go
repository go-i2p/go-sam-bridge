package i2cp

import (
	"testing"
)

func TestDefaultSessionConfig(t *testing.T) {
	config := DefaultSessionConfig()

	if config == nil {
		t.Fatal("DefaultSessionConfig returned nil")
	}

	if config.SignatureType != 7 {
		t.Errorf("expected signature type 7 (Ed25519), got %d", config.SignatureType)
	}

	if len(config.EncryptionTypes) != 1 || config.EncryptionTypes[0] != 4 {
		t.Errorf("expected encryption types [4], got %v", config.EncryptionTypes)
	}

	if config.InboundQuantity != 3 {
		t.Errorf("expected inbound quantity 3, got %d", config.InboundQuantity)
	}

	if config.OutboundQuantity != 3 {
		t.Errorf("expected outbound quantity 3, got %d", config.OutboundQuantity)
	}

	if config.InboundLength != 3 {
		t.Errorf("expected inbound length 3, got %d", config.InboundLength)
	}

	if config.OutboundLength != 3 {
		t.Errorf("expected outbound length 3, got %d", config.OutboundLength)
	}

	if !config.FastReceive {
		t.Error("expected fast receive to be enabled by default")
	}
}

func TestI2CPSession_IsActive(t *testing.T) {
	sess := &I2CPSession{
		active: false,
	}

	if sess.IsActive() {
		t.Error("new session should not be active")
	}

	sess.active = true
	if !sess.IsActive() {
		t.Error("session should be active after setting active=true")
	}
}

func TestI2CPSession_SAMSessionID(t *testing.T) {
	sess := &I2CPSession{
		samSessionID: "test-sam-session",
	}

	if sess.SAMSessionID() != "test-sam-session" {
		t.Errorf("expected SAM session ID 'test-sam-session', got '%s'", sess.SAMSessionID())
	}
}

func TestI2CPSession_Config(t *testing.T) {
	config := DefaultSessionConfig()
	sess := &I2CPSession{
		config: config,
	}

	if sess.Config() != config {
		t.Error("Config() should return the session's config")
	}
}

func TestI2CPSession_SetCallbacks(t *testing.T) {
	sess := &I2CPSession{}

	callbacks := &SessionCallbacks{
		OnDestroyed: func() {
			// Callback for testing
		},
	}

	sess.SetCallbacks(callbacks)

	if sess.callbacks != callbacks {
		t.Error("callbacks not set correctly")
	}

	// Verify callback is accessible
	if sess.callbacks.OnDestroyed == nil {
		t.Error("OnDestroyed callback should not be nil")
	}
}

func TestI2CPSession_Close_Inactive(t *testing.T) {
	sess := &I2CPSession{
		active: false,
	}

	err := sess.Close()
	if err != nil {
		t.Errorf("closing inactive session should not error, got: %v", err)
	}
}

func TestI2CPSession_Close_WithCallbacks(t *testing.T) {
	called := false
	sess := &I2CPSession{
		active: true,
		callbacks: &SessionCallbacks{
			OnDestroyed: func() {
				called = true
			},
		},
	}

	err := sess.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !called {
		t.Error("OnDestroyed callback should have been called")
	}

	if sess.active {
		t.Error("session should be inactive after close")
	}
}

func TestI2CPSession_Close_WithClient(t *testing.T) {
	client := NewClient(nil)
	sess := &I2CPSession{
		active:       true,
		client:       client,
		samSessionID: "test-session",
	}

	// Register the session first
	client.RegisterSession("test-session", sess)

	err := sess.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify session was unregistered
	if client.GetSession("test-session") != nil {
		t.Error("session should be unregistered from client after close")
	}
}
