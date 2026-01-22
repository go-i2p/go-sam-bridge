package i2cp

import (
	"testing"

	go_i2cp "github.com/go-i2p/go-i2cp"
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

func TestI2CPSession_Destination(t *testing.T) {
	sess := &I2CPSession{}

	// Should return nil when no destination set
	dest := sess.Destination()
	if dest != nil {
		t.Error("expected nil destination when not set")
	}
}

func TestI2CPSession_Session(t *testing.T) {
	sess := &I2CPSession{}

	// Should return nil when no underlying session
	underlying := sess.Session()
	if underlying != nil {
		t.Error("expected nil session when not set")
	}
}

func TestI2CPSession_Close_MultipleTimesIsSafe(t *testing.T) {
	sess := &I2CPSession{
		active: true,
	}

	// First close
	err := sess.Close()
	if err != nil {
		t.Errorf("first close should not error: %v", err)
	}

	// Second close should also succeed
	err = sess.Close()
	if err != nil {
		t.Errorf("second close should not error: %v", err)
	}
}

func TestI2CPSession_onMessage_NoCallbacks(t *testing.T) {
	sess := &I2CPSession{}

	// Should not panic when no callbacks set
	sess.onMessage(nil, nil, 0, 0, 0, nil)
}

func TestI2CPSession_onMessage_WithCallback(t *testing.T) {
	var receivedProtocol uint8
	var receivedSrcPort, receivedDestPort uint16
	var receivedPayload []byte

	sess := &I2CPSession{
		callbacks: &SessionCallbacks{
			OnMessage: func(srcDest *go_i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload []byte) {
				receivedProtocol = protocol
				receivedSrcPort = srcPort
				receivedDestPort = destPort
				receivedPayload = payload
			},
		},
	}

	// Call onMessage - we can't easily test with a real Stream but we can test the callback path
	sess.onMessage(nil, nil, 17, 1234, 5678, nil)

	if receivedProtocol != 17 {
		t.Errorf("expected protocol 17, got %d", receivedProtocol)
	}
	if receivedSrcPort != 1234 {
		t.Errorf("expected src port 1234, got %d", receivedSrcPort)
	}
	if receivedDestPort != 5678 {
		t.Errorf("expected dest port 5678, got %d", receivedDestPort)
	}
	if receivedPayload != nil {
		t.Errorf("expected nil payload, got %v", receivedPayload)
	}
}

func TestI2CPSession_onMessage_WithPayload(t *testing.T) {
	var receivedPayload []byte

	sess := &I2CPSession{
		callbacks: &SessionCallbacks{
			OnMessage: func(srcDest *go_i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload []byte) {
				receivedPayload = payload
			},
		},
	}

	// Create a real stream with test data
	testData := []byte("hello i2p")
	stream := go_i2cp.NewStream(testData)
	sess.onMessage(nil, nil, 17, 1234, 5678, stream)

	if receivedPayload == nil {
		t.Error("expected payload, got nil")
	} else if string(receivedPayload) != "hello i2p" {
		t.Errorf("expected 'hello i2p', got '%s'", string(receivedPayload))
	}
}

func TestI2CPSession_onMessageStatus_NoCallbacks(t *testing.T) {
	sess := &I2CPSession{}

	// Should not panic when no callbacks set
	sess.onMessageStatus(nil, 0, 0, 0, 0)
}

func TestI2CPSession_onMessageStatus_WithCallback(t *testing.T) {
	var receivedNonce uint32
	var receivedStatus int

	sess := &I2CPSession{
		callbacks: &SessionCallbacks{
			OnMessageStatus: func(nonce uint32, status int) {
				receivedNonce = nonce
				receivedStatus = status
			},
		},
	}

	sess.onMessageStatus(nil, 12345, 1, 100, 42)

	if receivedNonce != 42 {
		t.Errorf("expected nonce 42, got %d", receivedNonce)
	}
	if receivedStatus != 1 {
		t.Errorf("expected status 1, got %d", receivedStatus)
	}
}

func TestI2CPSession_onStatus_NoCallbacks(t *testing.T) {
	sess := &I2CPSession{}

	// Should not panic when no callbacks set
	sess.onStatus(nil, 0)
}

func TestI2CPSession_onStatus_WithCreatedCallback(t *testing.T) {
	called := false
	sess := &I2CPSession{
		callbacks: &SessionCallbacks{
			OnCreated: func(dest *go_i2cp.Destination) {
				called = true
			},
		},
	}

	// Trigger with I2CP_SESSION_STATUS_CREATED (value 0)
	sess.onStatus(nil, go_i2cp.I2CP_SESSION_STATUS_CREATED)

	if !called {
		t.Error("OnCreated callback should have been called")
	}
}

func TestI2CPSession_onStatus_WithNonCreatedStatus(t *testing.T) {
	called := false
	sess := &I2CPSession{
		callbacks: &SessionCallbacks{
			OnCreated: func(dest *go_i2cp.Destination) {
				called = true
			},
		},
	}

	// Trigger with a different status (not CREATED)
	sess.onStatus(nil, go_i2cp.I2CP_SESSION_STATUS_DESTROYED)

	if called {
		t.Error("OnCreated callback should NOT have been called for non-created status")
	}
}

func TestI2CPSession_SendMessage_InactiveSession(t *testing.T) {
	sess := &I2CPSession{
		active: false,
	}

	err := sess.SendMessage(nil, 0, 0, 0, nil, 0)
	if err == nil {
		t.Error("expected error when session is not active")
	}
	if err.Error() != "session is not active" {
		t.Errorf("expected 'session is not active' error, got: %v", err)
	}
}
