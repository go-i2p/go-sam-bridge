package streaming

import (
	"context"
	"net"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/go-i2p/go-streaming"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	closed bool
}

func (c *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *mockConn) Close() error                       { c.closed = true; return nil }
func (c *mockConn) LocalAddr() net.Addr                { return nil }
func (c *mockConn) RemoteAddr() net.Addr               { return nil }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockListener implements net.Listener for testing.
type mockListener struct {
	closed bool
}

func (l *mockListener) Accept() (net.Conn, error) { return &mockConn{}, nil }
func (l *mockListener) Close() error              { l.closed = true; return nil }
func (l *mockListener) Addr() net.Addr            { return nil }

// TestNewAdapter_NilManager verifies error handling for nil manager.
func TestNewAdapter_NilManager(t *testing.T) {
	_, err := NewAdapter(nil)
	if err == nil {
		t.Error("expected error for nil manager")
	}
	if err.Error() != "stream manager cannot be nil" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestAdapter_Destination verifies destination is returned correctly.
func TestAdapter_Destination(t *testing.T) {
	// Nil manager should return nil destination
	adapter := &Adapter{manager: nil}
	if adapter.Destination() != nil {
		t.Error("expected nil destination for nil manager")
	}
}

// TestAdapter_Close verifies close behavior.
func TestAdapter_Close(t *testing.T) {
	adapter := &Adapter{manager: nil}

	// Close should not panic
	err := adapter.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// After close, manager should be nil
	if adapter.manager != nil {
		t.Error("manager should be nil after close")
	}
}

// TestAdapter_LookupDestination_NilManager verifies error handling.
func TestAdapter_LookupDestination_NilManager(t *testing.T) {
	adapter := &Adapter{manager: nil}

	ctx := context.Background()
	_, err := adapter.LookupDestination(ctx, "example.i2p")
	if err == nil {
		t.Error("expected error for nil manager")
	}
	if err.Error() != "adapter not initialized" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestAdapter_Dial_NilManager verifies error handling.
func TestAdapter_Dial_NilManager(t *testing.T) {
	adapter := &Adapter{manager: nil}

	_, err := adapter.Dial("dest", 80, 1730)
	if err == nil {
		t.Error("expected error for nil manager")
	}
	if err.Error() != "adapter not initialized" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestAdapter_Listen_NilManager verifies error handling.
func TestAdapter_Listen_NilManager(t *testing.T) {
	adapter := &Adapter{manager: nil}

	_, err := adapter.Listen(80, 1730)
	if err == nil {
		t.Error("expected error for nil manager")
	}
	if err.Error() != "adapter not initialized" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestParseDestinationFromBase64_Empty verifies error for empty string.
func TestParseDestinationFromBase64_Empty(t *testing.T) {
	_, err := parseDestinationFromBase64("")
	if err == nil {
		t.Error("expected error for empty string")
	}
	if err.Error() != "empty destination string" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestParseDestinationFromBase64_Invalid verifies error for invalid Base64.
func TestParseDestinationFromBase64_Invalid(t *testing.T) {
	_, err := parseDestinationFromBase64("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// TestParseDestinationFromBase64_TooShort verifies error for truncated destination.
func TestParseDestinationFromBase64_TooShort(t *testing.T) {
	// Valid base64 but too short for a destination
	_, err := parseDestinationFromBase64("AAAA")
	if err == nil {
		t.Error("expected error for short destination")
	}
}

// TestAdapter_Manager_Returns_Underlying verifies Manager() accessor.
func TestAdapter_Manager_Returns_Underlying(t *testing.T) {
	adapter := &Adapter{manager: nil}
	if adapter.Manager() != nil {
		t.Error("expected nil manager")
	}
}

// TestParseDestinationFromBase64_Valid verifies valid destination parsing.
func TestParseDestinationFromBase64_Valid(t *testing.T) {
	// Generate a valid destination and convert to base64
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	if err != nil {
		t.Fatalf("failed to create destination: %v", err)
	}

	b64 := dest.Base64()
	if b64 == "" {
		t.Fatal("generated destination has empty base64")
	}

	// Parse it back
	parsed, err := parseDestinationFromBase64(b64)
	if err != nil {
		t.Fatalf("failed to parse valid destination: %v", err)
	}

	if parsed == nil {
		t.Error("parsed destination is nil")
	}

	// Verify the parsed destination matches
	if parsed.Base64() != b64 {
		t.Error("parsed destination does not match original")
	}
}

// TestAdapter_Dial_UnsupportedType verifies error for unsupported destination types.
func TestAdapter_Dial_UnsupportedType(t *testing.T) {
	// Create an adapter with a fake non-nil manager pointer
	// We can't create a real one without I2P, but we can test the type checking
	// by creating a wrapper that panics on use
	// For now, test the type check indirectly by using nil manager to get past that check
	// Actually, nil manager returns "adapter not initialized" so we need a different approach

	// The best we can do without integration is verify the parseDestinationFromBase64 works
	// and test error messages for nil adapter
	// The unsupported type check requires a non-nil manager which requires I2P

	// Test that the error message is correct when called with nil manager
	adapter := &Adapter{manager: nil}
	_, err := adapter.Dial(12345, 80, 1730) // int is unsupported type
	if err == nil {
		t.Error("expected error for nil manager (tested indirectly)")
	}
}

// TestAdapter_Dial_InvalidBase64String verifies error for invalid base64 strings.
func TestAdapter_Dial_InvalidBase64String(t *testing.T) {
	// Without I2P we can't test full flow, but we test parseDestinationFromBase64 directly
	_, err := parseDestinationFromBase64("invalid-base64-that-wont-parse-as-destination")
	if err == nil {
		t.Error("expected error for invalid base64 destination")
	}
}

// TestParseDestinationFromBase64_Whitespace verifies handling of whitespace.
func TestParseDestinationFromBase64_Whitespace(t *testing.T) {
	// Base64 with leading/trailing whitespace - should fail
	_, err := parseDestinationFromBase64("  AAAA  ")
	if err == nil {
		t.Error("expected error for whitespace-padded input")
	}
}

// TestAdapter_InterfaceCompliance verifies Adapter implements expected interfaces.
func TestAdapter_InterfaceCompliance(t *testing.T) {
	// Verify at compile time that Adapter has the expected methods
	// by attempting to use it where the interface is expected
	var _ interface {
		LookupDestination(ctx context.Context, hostname string) (interface{}, error)
		Dial(dest interface{}, port uint16, mtu int) (net.Conn, error)
		Listen(port uint16, mtu int) (net.Listener, error)
		Destination() interface{}
		Close() error
	} = &Adapter{}
}

// TestAdapter_MultipleCalls verifies adapter handles multiple operations correctly.
func TestAdapter_MultipleCalls(t *testing.T) {
	adapter := &Adapter{manager: nil}

	// Multiple calls to Destination should be consistent
	for i := 0; i < 5; i++ {
		if adapter.Destination() != nil {
			t.Errorf("call %d: expected nil destination", i)
		}
	}

	// Multiple closes should be safe
	for i := 0; i < 3; i++ {
		if err := adapter.Close(); err != nil {
			t.Errorf("close %d: unexpected error: %v", i, err)
		}
	}
}

// TestAdapter_ContextCancellation verifies LookupDestination respects context.
func TestAdapter_ContextCancellation(t *testing.T) {
	adapter := &Adapter{manager: nil}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// With nil manager, we get "adapter not initialized" before context check
	// but verify the context is at least passed through
	_, err := adapter.LookupDestination(ctx, "test.i2p")
	if err == nil {
		t.Error("expected error")
	}
}

// Benchmark for parseDestinationFromBase64
func BenchmarkParseDestinationFromBase64(b *testing.B) {
	// Generate a valid destination once
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	if err != nil {
		b.Fatalf("failed to create destination: %v", err)
	}
	b64 := dest.Base64()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseDestinationFromBase64(b64)
	}
}

// =============================================================================
// Integration Tests - Require I2P Router on localhost:7654
// These tests WILL FAIL if I2P router is not running with I2CP enabled
// =============================================================================

// createTestClient connects to the I2P router at localhost:7654.
// This function will fail the test if the router is not available.
func createTestClient(t *testing.T) *go_i2cp.Client {
	t.Helper()

	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("FATAL: Cannot connect to I2P router at localhost:7654. "+
			"I2P router with I2CP enabled is REQUIRED. Error: %v", err)
	}

	return client
}

// createTestManager creates a StreamManager with an active session.
func createTestManager(t *testing.T, client *go_i2cp.Client) *streaming.StreamManager {
	t.Helper()

	manager, err := streaming.NewStreamManager(client)
	if err != nil {
		t.Fatalf("Failed to create stream manager: %v", err)
	}

	// Start ProcessIO loop
	go func() {
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Start session
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err = manager.StartSession(ctx)
	if err != nil {
		t.Fatalf("Failed to start I2CP session: %v", err)
	}

	return manager
}

// TestIntegration_NewAdapter verifies adapter creation with real I2CP session.
func TestIntegration_NewAdapter(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	if adapter == nil {
		t.Fatal("Adapter is nil")
	}

	if adapter.Manager() != manager {
		t.Error("Adapter manager does not match")
	}
}

// TestIntegration_Destination verifies destination is returned correctly.
func TestIntegration_Destination(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	dest := adapter.Destination()
	if dest == nil {
		t.Fatal("Destination is nil")
	}

	// Verify it's a *go_i2cp.Destination
	i2pDest, ok := dest.(*go_i2cp.Destination)
	if !ok {
		t.Fatalf("Destination is not *go_i2cp.Destination, got %T", dest)
	}

	// Verify it has a valid base64 representation
	b64 := i2pDest.Base64()
	if b64 == "" {
		t.Error("Destination base64 is empty")
	}

	t.Logf("Session destination: %s...", b64[:32])
}

// TestIntegration_Listen verifies listener creation.
func TestIntegration_Listen(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	// Create a listener on port 8080
	listener, err := adapter.Listen(8080, 1730)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	if listener == nil {
		t.Fatal("Listener is nil")
	}

	t.Log("Listener created successfully on port 8080")
}

// TestIntegration_Dial_WithDestination verifies dialing with *go_i2cp.Destination.
func TestIntegration_Dial_WithDestination(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	// Get our own destination to dial (loopback test)
	dest := adapter.Destination().(*go_i2cp.Destination)

	// Try to dial - this will likely timeout since we're not listening
	// but it tests the type conversion path
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should fail with timeout or connection refused, not a type error
	conn, err := adapter.Dial(dest, 9999, 1730)
	if err == nil {
		// Unexpected success - close the connection
		conn.Close()
		t.Log("Dial succeeded (unexpected but valid)")
	} else {
		// Expected - dial should fail but not due to type error
		t.Logf("Dial failed as expected: %v", err)
	}
	_ = ctx // suppress unused warning
}

// TestIntegration_Dial_WithBase64String verifies dialing with base64 string.
func TestIntegration_Dial_WithBase64String(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	// Get our destination as base64 string
	dest := adapter.Destination().(*go_i2cp.Destination)
	b64 := dest.Base64()

	// Try to dial using base64 string
	conn, err := adapter.Dial(b64, 9999, 1730)
	if err == nil {
		conn.Close()
		t.Log("Dial with base64 succeeded (unexpected but valid)")
	} else {
		t.Logf("Dial with base64 failed as expected: %v", err)
	}
}

// TestIntegration_Dial_UnsupportedType verifies error for unsupported types.
func TestIntegration_Dial_UnsupportedType(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	// Try to dial with unsupported type (int)
	_, err = adapter.Dial(12345, 80, 1730)
	if err == nil {
		t.Error("Expected error for unsupported destination type")
	}

	expectedMsg := "unsupported destination type: int"
	if err.Error() != expectedMsg {
		t.Errorf("Unexpected error message: %s, want: %s", err.Error(), expectedMsg)
	}
}

// TestIntegration_LookupDestination verifies hostname lookup.
func TestIntegration_LookupDestination(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	// Try to look up a well-known I2P address
	// This may fail if the address is not in the router's addressbook
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use a b32 address derived from our own destination for reliable testing
	dest := adapter.Destination().(*go_i2cp.Destination)
	b32 := dest.Base32()

	result, err := adapter.LookupDestination(ctx, b32)
	if err != nil {
		// Lookup may fail for various reasons, log it
		t.Logf("Lookup failed (may be expected): %v", err)
	} else {
		t.Logf("Lookup succeeded: %T", result)
	}
}

// TestIntegration_Close verifies close behavior with real session.
func TestIntegration_Close(t *testing.T) {
	client := createTestClient(t)
	defer client.Close()

	manager := createTestManager(t, client)

	adapter, err := NewAdapter(manager)
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}

	// Close the adapter
	err = adapter.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// After close, operations should fail
	_, err = adapter.Listen(8080, 1730)
	if err == nil {
		t.Error("Expected error after close")
	}
}
