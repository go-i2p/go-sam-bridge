package embedding

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockRegistry implements session.Registry for testing.
type mockRegistry struct {
	sessions []session.Session
}

func (m *mockRegistry) Register(s session.Session) error                  { return nil }
func (m *mockRegistry) Unregister(id string) error                        { return nil }
func (m *mockRegistry) Get(id string) session.Session                     { return nil }
func (m *mockRegistry) GetByDestination(h string) session.Session         { return nil }
func (m *mockRegistry) MostRecentByStyle(s session.Style) session.Session { return nil }
func (m *mockRegistry) All() []string                                     { return nil }
func (m *mockRegistry) Count() int                                        { return 0 }
func (m *mockRegistry) Close() error                                      { return nil }

// mockI2CPProvider implements session.I2CPSessionProvider for testing.
type mockI2CPProvider struct{}

func (m *mockI2CPProvider) CreateSessionForSAM(ctx context.Context, samSessionID string, config *session.SessionConfig) (session.I2CPSessionHandle, error) {
	return nil, nil
}

func (m *mockI2CPProvider) IsConnected() bool { return true }

func TestNew(t *testing.T) {
	// Create a listener for testing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer ln.Close()

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name: "default options with listener",
			opts: []Option{
				WithListener(ln),
				WithI2CPProvider(&mockI2CPProvider{}),
			},
			wantErr: false,
		},
		{
			name: "custom listen address",
			opts: []Option{
				WithListenAddr("127.0.0.1:0"),
				WithI2CPProvider(&mockI2CPProvider{}),
			},
			wantErr: false,
		},
		{
			name: "with registry",
			opts: []Option{
				WithListener(ln),
				WithI2CPProvider(&mockI2CPProvider{}),
				WithRegistry(&mockRegistry{}),
			},
			wantErr: false,
		},
		{
			name: "missing listen addr and listener",
			opts: []Option{
				WithListenAddr(""),
				WithI2CPProvider(&mockI2CPProvider{}),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh listener for each test
			testLn, _ := net.Listen("tcp", "127.0.0.1:0")
			if testLn != nil {
				defer testLn.Close()
			}

			bridge, err := New(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && bridge == nil {
				t.Error("New() returned nil bridge without error")
			}
		})
	}
}

func TestBridgeLifecycle(t *testing.T) {
	// Create a test listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}

	bridge, err := New(
		WithListener(ln),
		WithI2CPProvider(&mockI2CPProvider{}),
		WithDebug(true),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify initial state
	if bridge.Running() {
		t.Error("Bridge should not be running initially")
	}

	// Start the bridge
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := bridge.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	if !bridge.Running() {
		t.Error("Bridge should be running after Start()")
	}

	// Starting again should fail
	if err := bridge.Start(ctx); err != ErrBridgeAlreadyRunning {
		t.Errorf("Start() on running bridge should return ErrBridgeAlreadyRunning, got %v", err)
	}

	// Stop the bridge
	if err := bridge.Stop(context.Background()); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Give it a moment to stop
	time.Sleep(10 * time.Millisecond)

	if bridge.Running() {
		t.Error("Bridge should not be running after Stop()")
	}
}

func TestBridgeContextCancellation(t *testing.T) {
	// Create a test listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}

	bridge, err := New(
		WithListener(ln),
		WithI2CPProvider(&mockI2CPProvider{}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	if err := bridge.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	// Cancel the context - should trigger shutdown
	cancel()

	// Give it time to shut down
	time.Sleep(50 * time.Millisecond)

	if bridge.Running() {
		t.Error("Bridge should stop when context is cancelled")
	}
}

func TestBridgeAccessors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer ln.Close()

	bridge, err := New(
		WithListener(ln),
		WithI2CPProvider(&mockI2CPProvider{}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test Server()
	if bridge.Server() == nil {
		t.Error("Server() should not return nil")
	}

	// Test Dependencies()
	if bridge.Dependencies() == nil {
		t.Error("Dependencies() should not return nil")
	}

	// Test Config()
	if bridge.Config() == nil {
		t.Error("Config() should not return nil")
	}
}

// TestBridgeWithUDPListener tests that the UDP listener is properly integrated.
func TestBridgeWithUDPListener(t *testing.T) {
	// Create a test listener for the TCP control socket
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}

	// Use a random high port for UDP to avoid conflicts
	bridge, err := New(
		WithListener(ln),
		WithI2CPProvider(&mockI2CPProvider{}),
		WithDatagramPort(0), // 0 disables UDP listener
		WithDebug(true),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// With port 0, UDP listener should be nil
	if bridge.udpListener != nil {
		t.Error("UDP listener should be nil when port is 0")
	}

	// Create bridge with UDP enabled
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}

	bridge2, err := New(
		WithListener(ln2),
		WithI2CPProvider(&mockI2CPProvider{}),
		WithDatagramPort(17655), // Use a high port to avoid conflicts
		WithDebug(true),
	)
	if err != nil {
		t.Fatalf("New() with UDP error = %v", err)
	}

	// With valid port, UDP listener should be created
	if bridge2.udpListener == nil {
		t.Error("UDP listener should be created when port > 0")
	}

	// Start the bridge - this should also start UDP listener
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := bridge2.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Verify UDP listener is listening
	if bridge2.udpListener.Addr() == nil {
		t.Error("UDP listener should have an address after Start()")
	}

	// Stop the bridge
	if err := bridge2.Stop(context.Background()); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}
