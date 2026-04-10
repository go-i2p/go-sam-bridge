package i2cp

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/handler"
)

// TestNewLeasesetAdapter verifies basic adapter creation.
func TestNewLeasesetAdapter(t *testing.T) {
	t.Run("nil session", func(t *testing.T) {
		_, err := NewLeasesetAdapter(nil)
		if err == nil {
			t.Error("expected error for nil session")
		}
	})
}

// TestLeasesetAdapter_SetTimeout verifies timeout setting.
func TestLeasesetAdapter_SetTimeout(t *testing.T) {
	// Create a mock session (we can't use nil but we can check the method exists)
	// This test just verifies the API shape

	// Can't create without a real session, so skip to integration tests
	t.Skip("requires I2P router for full test")
}

// TestLeasesetAdapterFromClient verifies client-based adapter creation.
func TestLeasesetAdapterFromClient(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		_, err := LeasesetAdapterFromClient(nil, "test")
		if err == nil {
			t.Error("expected error for nil client")
		}
	})

	t.Run("session not found", func(t *testing.T) {
		client := NewClient(nil)
		_, err := LeasesetAdapterFromClient(client, "nonexistent")
		if err == nil {
			t.Error("expected error for nonexistent session")
		}
	})
}

// TestNewDestinationResolverAdapter verifies resolver adapter creation.
func TestNewDestinationResolverAdapter(t *testing.T) {
	t.Run("nil session", func(t *testing.T) {
		_, err := NewDestinationResolverAdapter(nil, 30*time.Second)
		if err == nil {
			t.Error("expected error for nil session")
		}
	})
}

// TestLeasesetAdapterInterface verifies interface compliance.
func TestLeasesetAdapterInterface(t *testing.T) {
	// Compile-time check is in the source file, but let's verify at runtime too
	var _ handler.LeasesetLookupProvider = (*LeasesetAdapter)(nil)
	var _ handler.DestinationResolver = (*DestinationResolverAdapter)(nil)
}

// Integration tests that require an I2P router

// TestIntegration_LeasesetAdapter_LookupWithOptions tests actual lookup.
// Requires I2P router running on localhost:7654.
func TestIntegration_LeasesetAdapter_LookupWithOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create I2CP client
	config := DefaultClientConfig()
	client := NewClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Connect to router
	if err := client.Connect(ctx); err != nil {
		t.Skipf("I2P router not available: %v", err)
	}
	defer client.Close()

	// Create a session for lookups
	session, err := client.CreateSession(ctx, "leaseset-test", DefaultSessionConfig())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	// Wait for session to be ready
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	if err := session.WaitForTunnels(waitCtx); err != nil {
		t.Fatalf("failed waiting for tunnels: %v", err)
	}

	// Create leaseset adapter
	adapter, err := NewLeasesetAdapter(session)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Lookup a well-known I2P service (stats.i2p should exist)
	result, err := adapter.LookupWithOptions("stats.i2p")
	if err != nil {
		t.Logf("lookup error (may be expected if stats.i2p is down): %v", err)
		return
	}

	if result == nil {
		t.Error("expected non-nil result")
		return
	}

	if result.Found {
		if result.Destination == "" {
			t.Error("found but destination is empty")
		}
		t.Logf("found stats.i2p: %s... (options: %d)",
			result.Destination[:min(50, len(result.Destination))],
			len(result.Options))
	} else {
		t.Log("stats.i2p not found (may be expected)")
	}
}

// TestIntegration_DestinationResolverAdapter_Resolve tests actual resolution.
func TestIntegration_DestinationResolverAdapter_Resolve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create I2CP client
	config := DefaultClientConfig()
	client := NewClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Connect to router
	if err := client.Connect(ctx); err != nil {
		t.Skipf("I2P router not available: %v", err)
	}
	defer client.Close()

	// Create a session for lookups
	session, err := client.CreateSession(ctx, "resolver-test", DefaultSessionConfig())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	// Wait for session to be ready
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	if err := session.WaitForTunnels(waitCtx); err != nil {
		t.Fatalf("failed waiting for tunnels: %v", err)
	}

	// Create destination resolver adapter
	resolver, err := NewDestinationResolverAdapter(session, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	// Lookup a well-known I2P service
	resolveCtx, resolveCancel := context.WithTimeout(ctx, 30*time.Second)
	defer resolveCancel()

	dest, err := resolver.Resolve(resolveCtx, "stats.i2p")
	if err != nil {
		t.Logf("resolve error (may be expected if stats.i2p is down): %v", err)
		return
	}

	if dest == "" {
		t.Error("expected non-empty destination")
	} else {
		t.Logf("resolved stats.i2p: %s...", dest[:min(50, len(dest))])
	}
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
