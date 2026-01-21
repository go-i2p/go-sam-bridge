// Package session implements SAM v3.0-3.3 session management.
// Tests for Datagram2SessionImpl.
package session

import (
	"testing"
	"time"
)

func TestNewDatagram2Session(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		config *SessionConfig
	}{
		{
			name:   "basic creation",
			id:     "test-dg2",
			config: DefaultSessionConfig(),
		},
		{
			name:   "nil config uses defaults",
			id:     "test-dg2-nil",
			config: nil,
		},
		{
			name:   "empty id",
			id:     "",
			config: DefaultSessionConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewDatagram2Session(tt.id, nil, nil, tt.config)
			if sess == nil {
				t.Fatal("NewDatagram2Session returned nil")
			}

			if sess.ID() != tt.id {
				t.Errorf("ID() = %q, want %q", sess.ID(), tt.id)
			}

			if sess.Style() != StyleDatagram2 {
				t.Errorf("Style() = %v, want %v", sess.Style(), StyleDatagram2)
			}

			if sess.Status() != StatusCreating {
				t.Errorf("Status() = %v, want %v", sess.Status(), StatusCreating)
			}

			// Clean up
			if err := sess.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestDatagram2Session_Send(t *testing.T) {
	sess := NewDatagram2Session("test-send", nil, nil, nil)
	defer sess.Close()

	// Session must be active to send
	sess.SetStatus(StatusActive)

	tests := []struct {
		name    string
		dest    string
		data    []byte
		wantErr error
	}{
		{
			name:    "empty payload",
			dest:    "test.i2p",
			data:    []byte{},
			wantErr: ErrEmptyPayload,
		},
		{
			name:    "too large payload",
			dest:    "test.i2p",
			data:    make([]byte, MaxDatagram2Size+1),
			wantErr: ErrPayloadTooLarge,
		},
		{
			name:    "valid payload returns not implemented",
			dest:    "test.i2p",
			data:    []byte("hello world"),
			wantErr: ErrDatagram2SendNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sess.Send(tt.dest, tt.data, DatagramSendOptions{})
			if err != tt.wantErr {
				t.Errorf("Send() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDatagram2Session_Send_NotActive(t *testing.T) {
	sess := NewDatagram2Session("test-inactive", nil, nil, nil)
	defer sess.Close()

	// Session is in StatusCreating by default, not StatusActive
	err := sess.Send("test.i2p", []byte("hello"), DatagramSendOptions{})
	if err != ErrSessionNotActive {
		t.Errorf("Send() error = %v, want %v", err, ErrSessionNotActive)
	}
}

func TestDatagram2Session_Receive(t *testing.T) {
	sess := NewDatagram2Session("test-receive", nil, nil, nil)
	defer sess.Close()

	ch := sess.Receive()
	if ch == nil {
		t.Fatal("Receive() returned nil channel")
	}
}

func TestDatagram2Session_SetForwarding(t *testing.T) {
	sess := NewDatagram2Session("test-forward", nil, nil, nil)
	defer sess.Close()

	tests := []struct {
		name    string
		host    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid config",
			host:    "127.0.0.1",
			port:    12345,
			wantErr: false,
		},
		{
			name:    "empty host uses default",
			host:    "",
			port:    12345,
			wantErr: false,
		},
		{
			name:    "zero port",
			host:    "127.0.0.1",
			port:    0,
			wantErr: true,
		},
		{
			name:    "negative port",
			host:    "127.0.0.1",
			port:    -1,
			wantErr: true,
		},
		{
			name:    "port too high",
			host:    "127.0.0.1",
			port:    65536,
			wantErr: true,
		},
		{
			name:    "max valid port",
			host:    "127.0.0.1",
			port:    65535,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sess.SetForwarding(tt.host, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetForwarding() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if !sess.IsForwarding() {
					t.Error("IsForwarding() should be true after SetForwarding")
				}

				if sess.ForwardingAddr() == nil {
					t.Error("ForwardingAddr() should not be nil after SetForwarding")
				}
			}
		})
	}
}

func TestDatagram2Session_OfflineSignature(t *testing.T) {
	sess := NewDatagram2Session("test-offline-sig", nil, nil, nil)
	defer sess.Close()

	// Initially nil
	if sig := sess.OfflineSignature(); sig != nil {
		t.Errorf("OfflineSignature() = %v, want nil initially", sig)
	}

	// Set signature
	testSig := []byte("test-signature-data-12345")
	sess.SetOfflineSignature(testSig)

	// Retrieve and verify
	sig := sess.OfflineSignature()
	if sig == nil {
		t.Fatal("OfflineSignature() returned nil after setting")
	}

	if string(sig) != string(testSig) {
		t.Errorf("OfflineSignature() = %q, want %q", sig, testSig)
	}

	// Verify the returned slice is a copy (modifying it doesn't affect original)
	sig[0] = 'X'
	sig2 := sess.OfflineSignature()
	if sig2[0] == 'X' {
		t.Error("OfflineSignature() should return a copy, not the original slice")
	}
}

func TestDatagram2Session_CheckReplay(t *testing.T) {
	sess := NewDatagram2Session("test-replay", nil, nil, nil)
	defer sess.Close()

	// First check for a nonce should return false (not a replay)
	nonce := uint64(12345)
	if sess.CheckReplay(nonce) {
		t.Error("First CheckReplay should return false (not a replay)")
	}

	// Second check for same nonce should return true (is a replay)
	if !sess.CheckReplay(nonce) {
		t.Error("Second CheckReplay should return true (is a replay)")
	}

	// Different nonce should return false
	nonce2 := uint64(67890)
	if sess.CheckReplay(nonce2) {
		t.Error("Different nonce should return false (not a replay)")
	}
}

func TestDatagram2Session_DeliverDatagram(t *testing.T) {
	sess := NewDatagram2Session("test-deliver", nil, nil, nil)
	defer sess.Close()

	dg := ReceivedDatagram{
		Source:   "sender.i2p",
		FromPort: 1234,
		ToPort:   5678,
		Data:     []byte("test data"),
	}

	// First delivery should succeed
	nonce := uint64(11111)
	if !sess.DeliverDatagram(dg, nonce) {
		t.Error("First DeliverDatagram should return true")
	}

	// Verify datagram was delivered to channel
	select {
	case received := <-sess.Receive():
		if received.Source != dg.Source {
			t.Errorf("Received Source = %q, want %q", received.Source, dg.Source)
		}
		if string(received.Data) != string(dg.Data) {
			t.Errorf("Received Data = %q, want %q", received.Data, dg.Data)
		}
	default:
		t.Error("Expected datagram in receive channel")
	}

	// Replay with same nonce should fail
	if sess.DeliverDatagram(dg, nonce) {
		t.Error("Replay DeliverDatagram should return false")
	}

	// Different nonce should succeed
	nonce2 := uint64(22222)
	if !sess.DeliverDatagram(dg, nonce2) {
		t.Error("Different nonce DeliverDatagram should return true")
	}
}

func TestDatagram2Session_Close(t *testing.T) {
	sess := NewDatagram2Session("test-close", nil, nil, nil)

	// First close should succeed
	if err := sess.Close(); err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Status should be closed
	if sess.Status() != StatusClosed {
		t.Errorf("Status() = %v, want %v after Close", sess.Status(), StatusClosed)
	}

	// Double close should be safe
	if err := sess.Close(); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestDatagram2Session_NonceCleanup(t *testing.T) {
	sess := NewDatagram2Session("test-cleanup", nil, nil, nil)
	// Use a short expiry for testing
	sess.nonceExpiry = 50 * time.Millisecond
	defer sess.Close()

	// Add a nonce
	nonce := uint64(99999)
	if sess.CheckReplay(nonce) {
		t.Error("First CheckReplay should return false")
	}

	// Immediately, it should be a replay
	if !sess.CheckReplay(nonce) {
		t.Error("Immediate CheckReplay should return true (replay)")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup
	sess.cleanupExpiredNonces()

	// After cleanup, the nonce should be removed (not a replay anymore)
	if sess.CheckReplay(nonce) {
		t.Error("After expiry, CheckReplay should return false (nonce expired)")
	}
}

func TestDatagram2Session_MaxSize(t *testing.T) {
	// Verify MaxDatagram2Size matches expectation
	if MaxDatagram2Size != 31744 {
		t.Errorf("MaxDatagram2Size = %d, want 31744", MaxDatagram2Size)
	}
}

func TestDatagram2Session_DefaultNonceExpiry(t *testing.T) {
	// Verify default expiry is 10 minutes
	if DefaultDatagram2NonceExpiry != 10*time.Minute {
		t.Errorf("DefaultDatagram2NonceExpiry = %v, want 10m", DefaultDatagram2NonceExpiry)
	}
}

func TestDatagram2Session_ImplementsInterface(t *testing.T) {
	// This test verifies compile-time interface compliance
	var _ DatagramSession = (*Datagram2SessionImpl)(nil)
}

func TestDatagram2Session_ForwardingAddrInitiallyNil(t *testing.T) {
	sess := NewDatagram2Session("test-nil-forward", nil, nil, nil)
	defer sess.Close()

	if sess.ForwardingAddr() != nil {
		t.Error("ForwardingAddr() should be nil initially")
	}

	if sess.IsForwarding() {
		t.Error("IsForwarding() should be false initially")
	}
}

func TestDatagram2Session_DeliverDropsWhenChannelFull(t *testing.T) {
	sess := NewDatagram2Session("test-channel-full", nil, nil, nil)
	defer sess.Close()

	// Fill the receive channel (capacity is 100)
	for i := 0; i < 100; i++ {
		dg := ReceivedDatagram{
			Source: "sender.i2p",
			Data:   []byte("test"),
		}
		nonce := uint64(i)
		sess.DeliverDatagram(dg, nonce)
	}

	// Next delivery should fail because channel is full
	dg := ReceivedDatagram{
		Source: "sender.i2p",
		Data:   []byte("overflow"),
	}
	// Returns false because datagram was dropped (not because of replay)
	result := sess.DeliverDatagram(dg, 200)
	if result {
		t.Error("DeliverDatagram should return false when channel is full")
	}
}
