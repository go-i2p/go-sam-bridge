// Package datagram implements SAM v3.0-3.3 datagram handling.
// Tests for datagram forwarding to client UDP sockets.
package datagram

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewForwarder tests Forwarder creation.
func TestNewForwarder(t *testing.T) {
	tests := []struct {
		name    string
		config  ForwarderConfig
		wantNil bool
	}{
		{
			name: "valid config",
			config: ForwarderConfig{
				Host: "127.0.0.1",
				Port: 12345,
			},
			wantNil: false,
		},
		{
			name: "empty host uses default",
			config: ForwarderConfig{
				Port: 12345,
			},
			wantNil: false,
		},
		{
			name: "zero port returns nil",
			config: ForwarderConfig{
				Host: "127.0.0.1",
				Port: 0,
			},
			wantNil: true,
		},
		{
			name: "negative port returns nil",
			config: ForwarderConfig{
				Host: "127.0.0.1",
				Port: -1,
			},
			wantNil: true,
		},
		{
			name: "port too high returns nil",
			config: ForwarderConfig{
				Host: "127.0.0.1",
				Port: 65536,
			},
			wantNil: true,
		},
		{
			name: "with header enabled",
			config: ForwarderConfig{
				Host:          "127.0.0.1",
				Port:          12345,
				HeaderEnabled: true,
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewForwarder(tt.config)
			if tt.wantNil && f != nil {
				t.Error("Expected nil forwarder, got non-nil")
			}
			if !tt.wantNil && f == nil {
				t.Error("Expected non-nil forwarder, got nil")
			}
		})
	}
}

// TestForwarderStartClose tests Start and Close lifecycle.
func TestForwarderStartClose(t *testing.T) {
	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: 12345,
	})
	if f == nil {
		t.Fatal("NewForwarder returned nil")
	}

	// Should not be started initially
	if f.IsStarted() {
		t.Error("Forwarder should not be started initially")
	}

	// Start should succeed
	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Should be started now
	if !f.IsStarted() {
		t.Error("Forwarder should be started after Start()")
	}

	// Addr should be set
	if f.Addr() == nil {
		t.Error("Addr() should not be nil after Start()")
	}

	// Double start should fail
	if err := f.Start(); err == nil {
		t.Error("Double Start should fail")
	}

	// Close should succeed
	if err := f.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Should not be started after close
	if f.IsStarted() {
		t.Error("Forwarder should not be started after Close()")
	}

	// Double close should be safe
	if err := f.Close(); err != nil {
		t.Errorf("Double Close should be safe, got: %v", err)
	}
}

// TestForwarderStartAfterClose tests that starting after close fails.
func TestForwarderStartAfterClose(t *testing.T) {
	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: 12345,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Start after close should fail
	if err := f.Start(); err != ErrForwarderClosed {
		t.Errorf("Expected ErrForwarderClosed, got: %v", err)
	}
}

// TestForwardRawWithoutStart tests that forwarding before start fails.
func TestForwardRawWithoutStart(t *testing.T) {
	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: 12345,
	})

	err := f.ForwardRaw(100, 200, 18, []byte("test"))
	if err != ErrForwarderNotStarted {
		t.Errorf("Expected ErrForwarderNotStarted, got: %v", err)
	}
}

// TestForwardRawNoHeader tests forwarding without header.
func TestForwardRawNoHeader(t *testing.T) {
	// Create a receiving server
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiver.Close()

	// Get the receiver port
	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

	// Create forwarder pointing to receiver
	f := NewForwarder(ForwarderConfig{
		Host:          "127.0.0.1",
		Port:          receiverAddr.Port,
		HeaderEnabled: false,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer f.Close()

	// Forward a datagram
	payload := []byte("Hello, World!")
	if err := f.ForwardRaw(100, 200, 18, payload); err != nil {
		t.Fatalf("ForwardRaw failed: %v", err)
	}

	// Read from receiver
	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read from receiver: %v", err)
	}

	// Should receive just the payload (no header)
	received := string(buf[:n])
	if received != string(payload) {
		t.Errorf("Expected %q, got %q", string(payload), received)
	}
}

// TestForwardRawWithHeader tests forwarding with HEADER=true.
func TestForwardRawWithHeader(t *testing.T) {
	// Create a receiving server
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

	// Create forwarder with header enabled
	f := NewForwarder(ForwarderConfig{
		Host:          "127.0.0.1",
		Port:          receiverAddr.Port,
		HeaderEnabled: true,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer f.Close()

	// Forward a datagram
	payload := []byte("Test Payload")
	if err := f.ForwardRaw(1234, 5678, 18, payload); err != nil {
		t.Fatalf("ForwardRaw failed: %v", err)
	}

	// Read from receiver
	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read from receiver: %v", err)
	}

	received := string(buf[:n])

	// Should have header followed by payload
	expectedHeader := "FROM_PORT=1234 TO_PORT=5678 PROTOCOL=18\n"
	if !strings.HasPrefix(received, expectedHeader) {
		t.Errorf("Expected header %q, got prefix %q", expectedHeader, received[:min(len(expectedHeader), len(received))])
	}

	if !strings.HasSuffix(received, string(payload)) {
		t.Errorf("Expected payload suffix %q, got %q", string(payload), received)
	}
}

// TestForwardDatagram tests datagram forwarding with destination.
func TestForwardDatagram(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: receiverAddr.Port,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer f.Close()

	destination := "AAAA~~~~Base64Dest~~~~AAAA"
	payload := []byte("Datagram content")

	if err := f.ForwardDatagram(destination, payload); err != nil {
		t.Fatalf("ForwardDatagram failed: %v", err)
	}

	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read from receiver: %v", err)
	}

	received := string(buf[:n])

	// Should have destination\npayload format
	expected := destination + "\n" + string(payload)
	if received != expected {
		t.Errorf("Expected %q, got %q", expected, received)
	}
}

// TestForwardDatagramWithPorts tests datagram forwarding with port info.
func TestForwardDatagramWithPorts(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: receiverAddr.Port,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer f.Close()

	destination := "TestDest~"
	payload := []byte("Port-tagged datagram")

	if err := f.ForwardDatagramWithPorts(destination, 100, 200, payload); err != nil {
		t.Fatalf("ForwardDatagramWithPorts failed: %v", err)
	}

	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read from receiver: %v", err)
	}

	received := string(buf[:n])

	// Should have "destination FROM_PORT=nnn TO_PORT=nnn\npayload"
	expectedHeader := "TestDest~ FROM_PORT=100 TO_PORT=200\n"
	if !strings.HasPrefix(received, expectedHeader) {
		t.Errorf("Expected header %q, got %q", expectedHeader, received)
	}

	if !strings.HasSuffix(received, string(payload)) {
		t.Errorf("Expected payload suffix %q, got %q", string(payload), received)
	}
}

// TestFormatRawHeader tests the raw header formatting function.
func TestFormatRawHeader(t *testing.T) {
	tests := []struct {
		fromPort int
		toPort   int
		protocol int
		expected string
	}{
		{100, 200, 18, "FROM_PORT=100 TO_PORT=200 PROTOCOL=18\n"},
		{0, 0, 0, "FROM_PORT=0 TO_PORT=0 PROTOCOL=0\n"},
		{65535, 65535, 255, "FROM_PORT=65535 TO_PORT=65535 PROTOCOL=255\n"},
		{1234, 5678, 42, "FROM_PORT=1234 TO_PORT=5678 PROTOCOL=42\n"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := FormatRawHeader(tt.fromPort, tt.toPort, tt.protocol)
			if got != tt.expected {
				t.Errorf("FormatRawHeader(%d, %d, %d) = %q, want %q",
					tt.fromPort, tt.toPort, tt.protocol, got, tt.expected)
			}
		})
	}
}

// TestFormatDatagramHeaderWithPorts tests the datagram header formatting.
func TestFormatDatagramHeaderWithPorts(t *testing.T) {
	tests := []struct {
		dest     string
		fromPort int
		toPort   int
		expected string
	}{
		{"AAAA~", 100, 200, "AAAA~ FROM_PORT=100 TO_PORT=200\n"},
		{"LongDest", 0, 0, "LongDest FROM_PORT=0 TO_PORT=0\n"},
		{"Test", 65535, 65535, "Test FROM_PORT=65535 TO_PORT=65535\n"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := FormatDatagramHeaderWithPorts(tt.dest, tt.fromPort, tt.toPort)
			if got != tt.expected {
				t.Errorf("FormatDatagramHeaderWithPorts(%q, %d, %d) = %q, want %q",
					tt.dest, tt.fromPort, tt.toPort, got, tt.expected)
			}
		})
	}
}

// TestForwarderConcurrency tests concurrent forwarding.
func TestForwarderConcurrency(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

	f := NewForwarder(ForwarderConfig{
		Host:          "127.0.0.1",
		Port:          receiverAddr.Port,
		HeaderEnabled: true,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer f.Close()

	// Send multiple datagrams concurrently
	var wg sync.WaitGroup
	numGoroutines := 10
	numMessages := 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numMessages; j++ {
				payload := []byte("Message from goroutine")
				_ = f.ForwardRaw(id, j, 18, payload)
			}
		}(i)
	}

	wg.Wait()

	// Give time for all datagrams to arrive
	time.Sleep(50 * time.Millisecond)

	// Read some datagrams to verify they were sent
	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	received := 0
	for {
		_, _, err := receiver.ReadFrom(buf)
		if err != nil {
			break
		}
		received++
	}

	// Should have received at least some datagrams
	if received == 0 {
		t.Error("Expected to receive some datagrams, got none")
	}
}

// TestSetConnection tests setting a custom connection.
func TestSetConnection(t *testing.T) {
	// Create a receiving server
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr()

	// Create sender socket
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer sender.Close()

	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: 12345, // Doesn't matter since we're setting connection
	})

	// Set custom connection
	f.SetConnection(sender, receiverAddr)

	// Should be able to forward without calling Start()
	payload := []byte("Custom connection test")
	if err := f.ForwardRaw(0, 0, 18, payload); err != nil {
		t.Fatalf("ForwardRaw failed: %v", err)
	}

	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("Expected %q, got %q", string(payload), string(buf[:n]))
	}
}

// TestForwardAfterClose tests that forwarding after close returns error.
func TestForwardAfterClose(t *testing.T) {
	f := NewForwarder(ForwarderConfig{
		Host: "127.0.0.1",
		Port: 12345,
	})

	if err := f.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// All forward methods should return ErrForwarderClosed
	if err := f.ForwardRaw(0, 0, 18, []byte("test")); err != ErrForwarderClosed {
		t.Errorf("ForwardRaw after close: expected ErrForwarderClosed, got %v", err)
	}

	if err := f.ForwardDatagram("dest", []byte("test")); err != ErrForwarderClosed {
		t.Errorf("ForwardDatagram after close: expected ErrForwarderClosed, got %v", err)
	}

	if err := f.ForwardDatagramWithPorts("dest", 0, 0, []byte("test")); err != ErrForwarderClosed {
		t.Errorf("ForwardDatagramWithPorts after close: expected ErrForwarderClosed, got %v", err)
	}
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
