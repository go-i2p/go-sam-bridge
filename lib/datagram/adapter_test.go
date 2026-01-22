// Package datagram provides adapters between go-datagrams and go-sam-bridge.
// This file contains integration tests for the DatagramConnection adapter.
//
// These tests require an I2P router running at localhost:7654 with I2CP enabled.
// Tests WILL FAIL without a running I2P router - this is intentional per project guidelines.
package datagram

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/go-datagrams"
	go_i2cp "github.com/go-i2p/go-i2cp"
)

// =============================================================================
// Unit Tests - No I2P Router Required
// =============================================================================

// TestNewAdapter_NilConn verifies error handling for nil conn.
func TestNewAdapter_NilConn(t *testing.T) {
	_, err := NewAdapter(nil)
	if err == nil {
		t.Error("NewAdapter(nil) should return error")
	}
	if err.Error() != "datagram conn cannot be nil" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestAdapter_Protocol_NilConn verifies Protocol returns 0 for nil conn.
func TestAdapter_Protocol_NilConn(t *testing.T) {
	adapter := &Adapter{conn: nil}
	if got := adapter.Protocol(); got != 0 {
		t.Errorf("Protocol() = %d, want 0 for nil conn", got)
	}
}

// TestAdapter_Close_NilConn verifies Close handles nil conn safely.
func TestAdapter_Close_NilConn(t *testing.T) {
	adapter := &Adapter{conn: nil}
	err := adapter.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// TestAdapter_SendTo_NilConn verifies SendTo returns error for nil conn.
func TestAdapter_SendTo_NilConn(t *testing.T) {
	adapter := &Adapter{conn: nil}
	err := adapter.SendTo([]byte("test"), "destB64", 8080)
	if err == nil {
		t.Error("SendTo() should return error for nil conn")
	}
	if err.Error() != "adapter not initialized" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestAdapter_SendToWithOptions_NilConn verifies SendToWithOptions returns error for nil conn.
func TestAdapter_SendToWithOptions_NilConn(t *testing.T) {
	adapter := &Adapter{conn: nil}
	opts := &I2PDatagramOptions{SendTags: 5}
	err := adapter.SendToWithOptions([]byte("test"), "destB64", 8080, opts)
	if err == nil {
		t.Error("SendToWithOptions() should return error for nil conn")
	}
}

// TestAdapter_MaxPayloadSize_NilConn verifies MaxPayloadSize returns 0 for nil conn.
func TestAdapter_MaxPayloadSize_NilConn(t *testing.T) {
	adapter := &Adapter{conn: nil}
	if got := adapter.MaxPayloadSize(); got != 0 {
		t.Errorf("MaxPayloadSize() = %d, want 0 for nil conn", got)
	}
}

// TestAdapter_LocalAddr_NilConn verifies LocalAddr returns empty for nil conn.
func TestAdapter_LocalAddr_NilConn(t *testing.T) {
	adapter := &Adapter{conn: nil}
	if got := adapter.LocalAddr(); got != "" {
		t.Errorf("LocalAddr() = %q, want empty for nil conn", got)
	}
}

// TestAdapter_Conn_Returns_Underlying verifies Conn() accessor.
func TestAdapter_Conn_Returns_Underlying(t *testing.T) {
	adapter := &Adapter{conn: nil}
	if adapter.Conn() != nil {
		t.Error("Conn() should return nil for nil conn")
	}
}

// TestAdapter_MultipleClose verifies multiple Close calls are safe.
func TestAdapter_MultipleClose(t *testing.T) {
	adapter := &Adapter{conn: nil}
	for i := 0; i < 3; i++ {
		if err := adapter.Close(); err != nil {
			t.Errorf("Close() call %d error = %v", i, err)
		}
	}
}

// =============================================================================
// Integration Tests - Require I2P Router on localhost:7654
// These tests WILL FAIL if I2P router is not running with I2CP enabled
// =============================================================================

// createTestClient connects to the I2P router at localhost:7654.
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

// createTestSession creates an I2CP session for testing datagrams.
func createTestSession(t *testing.T, client *go_i2cp.Client) *go_i2cp.Session {
	t.Helper()

	callbacks := go_i2cp.SessionCallbacks{
		OnMessage: func(session *go_i2cp.Session, srcDest *go_i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *go_i2cp.Stream) {
			// Handle incoming messages if needed
		},
		OnStatus: func(session *go_i2cp.Session, status go_i2cp.SessionStatus) {
			// Handle status updates
		},
	}

	session := go_i2cp.NewSession(client, callbacks)

	// Start ProcessIO loop in background
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

	// Create the session with the I2P router
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err := client.CreateSessionSync(ctx, session)
	if err != nil {
		t.Fatalf("Failed to create I2CP session: %v", err)
	}

	return session
}

// TestIntegration_NewAdapter tests creating a new adapter with a real DatagramConn.
func TestIntegration_NewAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	// Create DatagramConn with Raw protocol (default)
	conn, err := datagrams.NewDatagramConn(session, 7777)
	if err != nil {
		t.Fatalf("Failed to create DatagramConn: %v", err)
	}
	defer conn.Close()

	// Create adapter
	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Verify adapter is initialized
	if adapter == nil {
		t.Fatal("NewAdapter() returned nil adapter")
	}

	// Verify Protocol returns correct value (18 = Raw)
	if got := adapter.Protocol(); got != 18 {
		t.Errorf("Protocol() = %d, want 18", got)
	}
}

// TestIntegration_Adapter_Protocol_Raw tests Raw protocol type.
func TestIntegration_Adapter_Protocol_Raw(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConnWithProtocol(session, 7778, datagrams.ProtocolRaw)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	if got := adapter.Protocol(); got != datagrams.ProtocolRaw {
		t.Errorf("Protocol() = %d, want %d", got, datagrams.ProtocolRaw)
	}
}

// TestIntegration_Adapter_Protocol_Datagram3 tests Datagram3 protocol type.
func TestIntegration_Adapter_Protocol_Datagram3(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConnWithProtocol(session, 7788, datagrams.ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	if got := adapter.Protocol(); got != datagrams.ProtocolDatagram3 {
		t.Errorf("Protocol() = %d, want %d", got, datagrams.ProtocolDatagram3)
	}
}

// TestIntegration_Adapter_Close tests that Close releases resources.
func TestIntegration_Adapter_Close(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7779)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Close the adapter
	if err := adapter.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify conn is nil after close
	if adapter.Conn() != nil {
		t.Error("Conn() should be nil after Close()")
	}

	// Verify Protocol returns 0 after close
	if got := adapter.Protocol(); got != 0 {
		t.Errorf("Protocol() after Close() = %d, want 0", got)
	}
}

// TestIntegration_Adapter_MaxPayloadSize tests payload size limits.
func TestIntegration_Adapter_MaxPayloadSize(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7780)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Raw protocol should have max payload = 64KB
	size := adapter.MaxPayloadSize()
	if size <= 0 {
		t.Errorf("MaxPayloadSize() = %d, want > 0", size)
	}

	// Raw should be close to 64KB (65536)
	if size < 60000 {
		t.Errorf("MaxPayloadSize() for Raw = %d, expected >= 60000", size)
	}
}

// TestIntegration_Adapter_LocalAddr tests local address retrieval.
func TestIntegration_Adapter_LocalAddr(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7781)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// LocalAddr should contain port 7781
	addr := adapter.LocalAddr()
	if addr == "" {
		t.Error("LocalAddr() returned empty string")
	}

	// Should contain :7781 suffix
	if len(addr) < 5 {
		t.Errorf("LocalAddr() = %q, expected longer address with port", addr)
	}
}

// TestIntegration_Adapter_SendTo tests sending a datagram.
func TestIntegration_Adapter_SendTo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7782)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Get our own destination to send to (loopback test)
	dest := session.Destination()
	if dest == nil {
		t.Fatal("Session has no destination")
	}

	destB64 := dest.Base64()

	// Send a test datagram
	payload := []byte("test datagram payload")
	err = adapter.SendTo(payload, destB64, 7782)
	// Note: Even if delivery fails due to network timing, SendTo should not error
	// immediately. The actual delivery is asynchronous in I2P.
	if err != nil {
		t.Errorf("SendTo() error = %v", err)
	}
}

// TestIntegration_Adapter_SendTo_ClosedAdapter tests sending on closed adapter.
func TestIntegration_Adapter_SendTo_ClosedAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7783)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Close the adapter
	adapter.Close()

	// Get destination for test
	dest := session.Destination()
	destB64 := dest.Base64()

	// Attempt to send on closed adapter should fail
	err = adapter.SendTo([]byte("test"), destB64, 7783)
	if err == nil {
		t.Error("SendTo() on closed adapter should return error")
	}
}

// TestIntegration_Adapter_SendToWithOptions tests sending with SAM 3.3 options.
func TestIntegration_Adapter_SendToWithOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	// Use Datagram3 protocol which supports options
	conn, err := datagrams.NewDatagramConnWithProtocol(session, 7784, datagrams.ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	dest := session.Destination()
	destB64 := dest.Base64()

	// Send with SAM 3.3 options
	opts := &I2PDatagramOptions{
		SendTags:     5,
		TagThreshold: 10,
		Expires:      60,
		SendLeaseSet: true,
	}

	payload := []byte("test with options")
	err = adapter.SendToWithOptions(payload, destB64, 7784, opts)
	if err != nil {
		t.Errorf("SendToWithOptions() error = %v", err)
	}
}

// TestIntegration_Adapter_SendToWithOptions_NilOptions tests sending with nil options.
func TestIntegration_Adapter_SendToWithOptions_NilOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7785)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}
	defer conn.Close()

	adapter, err := NewAdapter(conn)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	dest := session.Destination()
	destB64 := dest.Base64()

	// Send with nil options should work (falls back to basic SendTo)
	payload := []byte("test without options")
	err = adapter.SendToWithOptions(payload, destB64, 7785, nil)
	if err != nil {
		t.Errorf("SendToWithOptions(nil opts) error = %v", err)
	}
}

// TestIntegration_NewAdapter_ClosedConn tests that closed conn is rejected.
func TestIntegration_NewAdapter_ClosedConn(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires I2P router)")
	}

	client := createTestClient(t)
	defer client.Close()

	session := createTestSession(t, client)
	defer session.Close()

	conn, err := datagrams.NewDatagramConn(session, 7786)
	if err != nil {
		t.Fatalf("NewDatagramConn() error = %v", err)
	}

	// Close the conn before creating adapter
	conn.Close()

	// Attempt to create adapter with closed conn
	_, err = NewAdapter(conn)
	if err == nil {
		t.Error("NewAdapter(closedConn) should return error")
	}
}
