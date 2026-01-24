// Package i2cp provides I2CP session management for the SAM bridge.
package i2cp

import (
	"context"
	"fmt"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// I2CPSession wraps a go-i2cp Session to provide SAM-specific functionality.
// Each SAM session maps to one I2CPSession which manages the underlying
// I2P tunnels and destination.
//
// Thread-safety: All methods are safe for concurrent use.
type I2CPSession struct {
	mu sync.RWMutex

	// client is the parent I2CP client.
	client *Client

	// session is the underlying go-i2cp session.
	session *go_i2cp.Session

	// config holds the session configuration.
	config *SessionConfig

	// destination is the I2P destination for this session.
	destination *go_i2cp.Destination

	// samSessionID is the SAM session identifier (nickname).
	samSessionID string

	// active indicates if the session is active.
	active bool

	// created is when the session was created.
	created time.Time

	// callbacks holds session-level callbacks.
	callbacks *SessionCallbacks

	// tunnelReady is closed when tunnels are built and ready.
	// Per SAMv3.md: "the router builds tunnels before responding with SESSION STATUS"
	// ISSUE-003: Used to block SESSION STATUS response until tunnels are ready.
	tunnelReady chan struct{}

	// tunnelReadyOnce ensures tunnelReady is only closed once.
	tunnelReadyOnce sync.Once
}

// SessionConfig holds configuration for an I2CP session.
// These options map to SAM SESSION CREATE options.
type SessionConfig struct {
	// SignatureType is the signature algorithm (default: 7 = Ed25519).
	SignatureType int

	// EncryptionTypes specifies encryption algorithms (default: [4, 0]).
	EncryptionTypes []int

	// InboundQuantity is the number of inbound tunnels (default: 3).
	InboundQuantity int

	// OutboundQuantity is the number of outbound tunnels (default: 3).
	OutboundQuantity int

	// InboundLength is the number of hops for inbound tunnels (default: 3).
	InboundLength int

	// OutboundLength is the number of hops for outbound tunnels (default: 3).
	OutboundLength int

	// InboundBackupQuantity is the number of backup inbound tunnels.
	InboundBackupQuantity int

	// OutboundBackupQuantity is the number of backup outbound tunnels.
	OutboundBackupQuantity int

	// FastReceive enables fast receive mode.
	FastReceive bool

	// ReduceIdleTime enables tunnel reduction when idle (seconds, 0 = disabled).
	ReduceIdleTime int

	// CloseIdleTime closes session after idle (seconds, 0 = disabled).
	CloseIdleTime int

	// ExistingDestination is an existing private key to use.
	// If nil, a new transient destination is generated.
	ExistingDestination []byte
}

// DefaultSessionConfig returns a SessionConfig with recommended defaults.
// Uses Ed25519 signatures and ECIES-X25519 encryption per SAM best practices.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		SignatureType:    7,        // Ed25519
		EncryptionTypes:  []int{4}, // ECIES-X25519
		InboundQuantity:  3,
		OutboundQuantity: 3,
		InboundLength:    3,
		OutboundLength:   3,
		FastReceive:      true,
	}
}

// SessionCallbacks holds callbacks for session-level events.
type SessionCallbacks struct {
	// OnCreated is called when the session is created and ready.
	OnCreated func(dest *go_i2cp.Destination)

	// OnDestroyed is called when the session is destroyed.
	OnDestroyed func()

	// OnMessage is called when a message is received.
	OnMessage func(srcDest *go_i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload []byte)

	// OnMessageStatus is called with message delivery status.
	OnMessageStatus func(nonce uint32, status int)
}

// CreateSession creates a new I2CP session with the given configuration.
// This allocates I2P tunnels and establishes the session with the router.
//
// The creation process:
//  1. Create go-i2cp Session with callbacks
//  2. Apply configuration options (tunnels, crypto)
//  3. Send CreateSession to router
//  4. Wait for session confirmation
//
// Returns the session or an error if creation fails.
func (c *Client) CreateSession(ctx context.Context, samSessionID string, config *SessionConfig) (*I2CPSession, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("not connected to I2P router")
	}
	i2cpClient := c.i2cpClient
	c.mu.RUnlock()

	if config == nil {
		config = DefaultSessionConfig()
	}

	// Create the I2CP session wrapper
	sess := &I2CPSession{
		client:       c,
		config:       config,
		samSessionID: samSessionID,
		created:      time.Now(),
		tunnelReady:  make(chan struct{}),
	}

	// Set up session callbacks - match go-i2cp SessionCallbacks signature
	callbacks := go_i2cp.SessionCallbacks{
		OnMessage:       sess.onMessage,
		OnStatus:        sess.onStatus,
		OnMessageStatus: sess.onMessageStatus,
	}

	// Create the go-i2cp session
	i2cpSession := go_i2cp.NewSession(i2cpClient, callbacks)
	sess.session = i2cpSession

	// Configure session properties via the session's config
	sess.applyConfig(config)

	// Apply timeout to context
	sessionCtx := ctx
	timeout := c.config.SessionTimeout
	if timeout > 0 {
		var cancel context.CancelFunc
		sessionCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Create the session with the router
	if err := i2cpClient.CreateSession(sessionCtx, i2cpSession); err != nil {
		return nil, fmt.Errorf("failed to create I2CP session: %w", err)
	}

	// Get the destination and mark active (protected by mutex since callbacks
	// can be triggered from go-i2cp's ProcessIO goroutine concurrently)
	sess.mu.Lock()
	sess.destination = i2cpSession.Destination()
	sess.active = true
	sess.mu.Unlock()

	// Register the session
	c.RegisterSession(samSessionID, sess)

	return sess, nil
}

// applyConfig applies the SessionConfig to the go-i2cp session's config.
func (sess *I2CPSession) applyConfig(config *SessionConfig) {
	sessionConfig := sess.session.Config()

	// Set tunnel configuration using go-i2cp SessionConfigProperty constants
	sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, fmt.Sprintf("%d", config.InboundQuantity))
	sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, fmt.Sprintf("%d", config.OutboundQuantity))
	sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_LENGTH, fmt.Sprintf("%d", config.InboundLength))
	sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_LENGTH, fmt.Sprintf("%d", config.OutboundLength))

	if config.InboundBackupQuantity > 0 {
		sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY, fmt.Sprintf("%d", config.InboundBackupQuantity))
	}
	if config.OutboundBackupQuantity > 0 {
		sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY, fmt.Sprintf("%d", config.OutboundBackupQuantity))
	}

	// Set encryption type
	if len(config.EncryptionTypes) > 0 {
		encTypes := ""
		for i, t := range config.EncryptionTypes {
			if i > 0 {
				encTypes += ","
			}
			encTypes += fmt.Sprintf("%d", t)
		}
		sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE, encTypes)
	}

	// Set fast receive
	if config.FastReceive {
		sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	}

	// Set message reliability to none for performance
	sessionConfig.SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")
}

// Close closes the I2CP session and releases resources.
// Safe to call multiple times.
func (sess *I2CPSession) Close() error {
	sess.mu.Lock()

	if !sess.active {
		sess.mu.Unlock()
		return nil
	}

	sess.active = false

	// Unregister from client
	if sess.client != nil {
		sess.client.UnregisterSession(sess.samSessionID)
	}

	// Capture session and callbacks before releasing lock
	// We must release the lock before calling session.Close() because
	// go-i2cp's Close() invokes status callbacks which try to acquire our lock.
	session := sess.session
	callbacks := sess.callbacks
	sess.mu.Unlock()

	// Close the I2CP session (outside of lock to prevent deadlock)
	if session != nil {
		if err := session.Close(); err != nil {
			return fmt.Errorf("failed to close I2CP session: %w", err)
		}
	}

	// Notify callback (outside of lock)
	if callbacks != nil && callbacks.OnDestroyed != nil {
		callbacks.OnDestroyed()
	}

	return nil
}

// IsActive returns true if the session is active.
func (sess *I2CPSession) IsActive() bool {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	return sess.active
}

// SAMSessionID returns the SAM session identifier.
func (sess *I2CPSession) SAMSessionID() string {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	return sess.samSessionID
}

// Destination returns the I2P destination for this session.
func (sess *I2CPSession) Destination() *go_i2cp.Destination {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	return sess.destination
}

// DestinationBase64 returns the base64-encoded destination.
// Implements session.I2CPSessionHandle interface.
func (sess *I2CPSession) DestinationBase64() string {
	sess.mu.RLock()
	dest := sess.destination
	sess.mu.RUnlock()

	if dest == nil {
		return ""
	}
	return dest.Base64()
}

// Session returns the underlying go-i2cp session.
// This allows direct access for advanced operations.
func (sess *I2CPSession) Session() *go_i2cp.Session {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	return sess.session
}

// Config returns the session configuration.
func (sess *I2CPSession) Config() *SessionConfig {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	return sess.config
}

// SetCallbacks sets the session callbacks.
func (sess *I2CPSession) SetCallbacks(callbacks *SessionCallbacks) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.callbacks = callbacks
}

// onMessage handles incoming messages from the I2CP session.
// Matches go-i2cp SessionCallbacks.OnMessage signature.
func (sess *I2CPSession) onMessage(session *go_i2cp.Session, srcDest *go_i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *go_i2cp.Stream) {
	sess.mu.RLock()
	callbacks := sess.callbacks
	sess.mu.RUnlock()

	if callbacks != nil && callbacks.OnMessage != nil {
		// Convert Stream to []byte for our callback interface
		var data []byte
		if payload != nil {
			data = payload.Bytes()
		}
		callbacks.OnMessage(srcDest, protocol, srcPort, destPort, data)
	}
}

// onStatus handles session status updates from the I2CP session.
// Matches go-i2cp SessionCallbacks.OnStatus signature.
//
// Per SAMv3.md: "the router builds tunnels before responding with SESSION STATUS"
// We use I2CP_SESSION_STATUS_UPDATED to detect when tunnels are ready.
// ISSUE-003: Signal tunnel readiness for blocking SESSION STATUS response.
func (sess *I2CPSession) onStatus(session *go_i2cp.Session, status go_i2cp.SessionStatus) {
	sess.mu.RLock()
	callbacks := sess.callbacks
	dest := sess.destination
	sess.mu.RUnlock()

	// I2CP_SESSION_STATUS_CREATED means session created successfully
	if status == go_i2cp.I2CP_SESSION_STATUS_CREATED && callbacks != nil && callbacks.OnCreated != nil {
		callbacks.OnCreated(dest)
	}

	// I2CP_SESSION_STATUS_UPDATED indicates session configuration updated,
	// which typically happens when tunnels are built.
	// Also signal on CREATED since some routers may not send UPDATED.
	// Per I2P implementation: tunnel build status is conveyed via SessionStatus.
	if status == go_i2cp.I2CP_SESSION_STATUS_CREATED || status == go_i2cp.I2CP_SESSION_STATUS_UPDATED {
		sess.signalTunnelReady()
	}
}

// signalTunnelReady signals that tunnels are ready.
// Safe to call multiple times - only signals once.
// Safe to call even if tunnelReady channel is nil (e.g., in tests).
func (sess *I2CPSession) signalTunnelReady() {
	if sess.tunnelReady == nil {
		return // Channel not initialized, nothing to signal
	}
	sess.tunnelReadyOnce.Do(func() {
		close(sess.tunnelReady)
	})
}

// WaitForTunnels blocks until tunnels are built or context is cancelled.
// Returns nil when tunnels are ready, or context error on timeout/cancellation.
//
// Per SAMv3.md: "the router builds tunnels before responding with SESSION STATUS.
// This could take several seconds."
// ISSUE-003: Use this to block SESSION STATUS response until tunnels are ready.
func (sess *I2CPSession) WaitForTunnels(ctx context.Context) error {
	select {
	case <-sess.tunnelReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsTunnelReady returns true if tunnels are built and ready.
func (sess *I2CPSession) IsTunnelReady() bool {
	select {
	case <-sess.tunnelReady:
		return true
	default:
		return false
	}
}

// onMessageStatus handles message delivery status updates.
// Matches go-i2cp SessionCallbacks.OnMessageStatus signature.
func (sess *I2CPSession) onMessageStatus(session *go_i2cp.Session, messageId uint32, status go_i2cp.SessionMessageStatus, size, nonce uint32) {
	sess.mu.RLock()
	callbacks := sess.callbacks
	sess.mu.RUnlock()

	if callbacks != nil && callbacks.OnMessageStatus != nil {
		callbacks.OnMessageStatus(nonce, int(status))
	}
}

// SendMessage sends a message to a destination.
func (sess *I2CPSession) SendMessage(dest *go_i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload []byte, nonce uint32) error {
	sess.mu.RLock()
	if !sess.active {
		sess.mu.RUnlock()
		return fmt.Errorf("session is not active")
	}
	session := sess.session
	sess.mu.RUnlock()

	// Create payload stream
	stream := go_i2cp.NewStream(payload)

	return session.SendMessage(dest, protocol, srcPort, destPort, stream, nonce)
}
