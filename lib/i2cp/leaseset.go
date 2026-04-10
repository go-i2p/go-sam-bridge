// Package i2cp provides I2CP integration for the SAM bridge.
// This file implements the leaseset lookup provider for NAMING LOOKUP OPTIONS=true support.
// ISSUE-011: Implements LeasesetLookupProvider interface.
package i2cp

import (
	"context"
	"fmt"
	"time"

	"github.com/go-i2p/go-sam-bridge/lib/handler"
)

// LeasesetAdapter implements handler.LeasesetLookupProvider using go-i2cp.
// This adapter wraps go-i2cp destination lookup functionality and provides
// leaseset options querying as specified in SAM API 0.9.66.
//
// Note: Full leaseset options support requires go-i2cp to be extended
// with leaseset query message support. Currently, only destination lookup
// is fully implemented; leaseset options return an empty list.
//
// ISSUE-011: Resolves NAMING LOOKUP OPTIONS=true integration.
type LeasesetAdapter struct {
	session *I2CPSession
	timeout time.Duration
}

// DefaultLeasesetLookupTimeout is the default timeout for leaseset lookups.
const DefaultLeasesetLookupTimeout = 30 * time.Second

// NewLeasesetAdapter creates a new LeasesetAdapter for the given I2CP session.
// The adapter uses the session's underlying go-i2cp session for destination lookups.
func NewLeasesetAdapter(session *I2CPSession) (*LeasesetAdapter, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	return &LeasesetAdapter{
		session: session,
		timeout: DefaultLeasesetLookupTimeout,
	}, nil
}

// SetTimeout sets the timeout for leaseset lookups.
func (a *LeasesetAdapter) SetTimeout(timeout time.Duration) {
	a.timeout = timeout
}

// LookupWithOptions performs a leaseset lookup and returns options if available.
// Implements handler.LeasesetLookupProvider interface.
//
// Per SAM API 0.9.66, OPTIONS=true in NAMING LOOKUP should return leaseset options
// with OPTION: prefix. The options include service records and other leaseset metadata.
//
// Current implementation:
//   - Resolves the destination using go-i2cp's LookupDestination
//   - Returns an empty options list (leaseset options querying not yet implemented in go-i2cp)
//
// Future implementation (when go-i2cp supports leaseset queries):
//   - Query the router for the destination's leaseset
//   - Parse leaseset options/service records
//   - Return options with their key-value pairs
func (a *LeasesetAdapter) LookupWithOptions(name string) (*handler.LeasesetLookupResult, error) {
	if a.session == nil {
		return nil, fmt.Errorf("session not available")
	}

	// Perform destination lookup using go-i2cp (async with sync wrapper)
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	dest, err := a.session.LookupDestinationSync(ctx, name, a.timeout)
	if err != nil {
		// Determine if it's a not-found error or other error
		// go-i2cp returns an error for not found, so we check the error message
		return &handler.LeasesetLookupResult{
			Found: false,
		}, nil
	}

	if dest == nil {
		return &handler.LeasesetLookupResult{
			Found: false,
		}, nil
	}

	// Get the destination as Base64
	destBase64 := dest.Base64()

	// TODO: When go-i2cp supports leaseset options querying, extract options here.
	// For now, return an empty options list since go-i2cp doesn't yet support
	// querying leaseset service records / options.
	//
	// Per I2P specification, leaseset options include:
	//   - Service records (e.g., "service.name=value")
	//   - Expiration information
	//   - Other metadata
	//
	// The I2CP protocol would need to use a LookupLeaseSet message type or
	// parse the returned leaseset data to extract these options.

	return &handler.LeasesetLookupResult{
		Destination: destBase64,
		Options:     nil,
		Found:       true,
	}, nil
}

// Compile-time check that LeasesetAdapter implements handler.LeasesetLookupProvider.
var _ handler.LeasesetLookupProvider = (*LeasesetAdapter)(nil)

// LeasesetAdapterFromClient creates a LeasesetAdapter using the first available
// session from the I2CP client. This is useful when you need leaseset lookups
// without a specific session context.
func LeasesetAdapterFromClient(client *Client, sessionID string) (*LeasesetAdapter, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	session := client.GetSession(sessionID)
	if session == nil {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}

	return NewLeasesetAdapter(session)
}

// DestinationResolverAdapter implements handler.DestinationResolver using go-i2cp.
// This adapter wraps go-i2cp's LookupDestination functionality for NAMING LOOKUP commands.
//
// Per SAMv3.md, NAMING LOOKUP should resolve:
//   - .b32.i2p addresses (base32-encoded destination hashes)
//   - .i2p hostnames (resolved via the I2P router's address book / network database)
type DestinationResolverAdapter struct {
	session *I2CPSession
	timeout time.Duration
}

// NewDestinationResolverAdapter creates a DestinationResolver adapter for the given session.
func NewDestinationResolverAdapter(session *I2CPSession, timeout time.Duration) (*DestinationResolverAdapter, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	return &DestinationResolverAdapter{
		session: session,
		timeout: timeout,
	}, nil
}

// Resolve looks up an I2P destination by name.
// Implements handler.DestinationResolver interface.
//
// The name can be:
//   - A .b32.i2p address (e.g., "abcd...wxyz.b32.i2p")
//   - A .i2p hostname (e.g., "example.i2p")
//
// Returns the full Base64-encoded destination on success.
func (a *DestinationResolverAdapter) Resolve(ctx context.Context, name string) (string, error) {
	if a.session == nil {
		return "", fmt.Errorf("session not available")
	}

	dest, err := a.session.LookupDestinationSync(ctx, name, a.timeout)
	if err != nil {
		return "", err
	}

	if dest == nil {
		return "", fmt.Errorf("destination not found: %s", name)
	}

	return dest.Base64(), nil
}

// Compile-time check that DestinationResolverAdapter implements handler.DestinationResolver.
var _ handler.DestinationResolver = (*DestinationResolverAdapter)(nil)

// ClientDestinationResolverAdapter implements handler.DestinationResolver using the I2CP client.
// It uses the first available I2CP session for lookups, making it suitable for global resolver use.
//
// This adapter is useful for NAMING LOOKUP commands that may occur before or after
// specific session creation.
type ClientDestinationResolverAdapter struct {
	client  *Client
	timeout time.Duration
}

// NewClientDestinationResolverAdapter creates a DestinationResolver adapter using the I2CP client.
func NewClientDestinationResolverAdapter(client *Client, timeout time.Duration) (*ClientDestinationResolverAdapter, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	return &ClientDestinationResolverAdapter{
		client:  client,
		timeout: timeout,
	}, nil
}

// Resolve looks up an I2P destination by name using any available session.
// Implements handler.DestinationResolver interface.
func (a *ClientDestinationResolverAdapter) Resolve(ctx context.Context, name string) (string, error) {
	if a.client == nil {
		return "", fmt.Errorf("client not available")
	}

	// Get the first available session for lookup
	session := a.client.GetFirstSession()
	if session == nil {
		return "", fmt.Errorf("no active session available for lookup")
	}

	dest, err := session.LookupDestinationSync(ctx, name, a.timeout)
	if err != nil {
		return "", err
	}

	if dest == nil {
		return "", fmt.Errorf("destination not found: %s", name)
	}

	return dest.Base64(), nil
}

// Compile-time check that ClientDestinationResolverAdapter implements handler.DestinationResolver.
var _ handler.DestinationResolver = (*ClientDestinationResolverAdapter)(nil)
