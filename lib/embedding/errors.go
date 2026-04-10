package embedding

import "errors"

// Errors returned by the embedding package.
var (
	// ErrMissingListenAddr is returned when no listen address or listener is provided.
	ErrMissingListenAddr = errors.New("embedding: listen address or listener required")

	// ErrMissingI2CPAddr is returned when no I2CP address or provider is provided.
	ErrMissingI2CPAddr = errors.New("embedding: I2CP address or provider required")

	// ErrBridgeAlreadyRunning is returned when Start is called on a running bridge.
	ErrBridgeAlreadyRunning = errors.New("embedding: bridge is already running")

	// ErrBridgeNotRunning is returned when Stop is called on a stopped bridge.
	ErrBridgeNotRunning = errors.New("embedding: bridge is not running")

	// ErrI2CPConnectFailed is returned when connection to I2P router fails.
	ErrI2CPConnectFailed = errors.New("embedding: failed to connect to I2P router")

	// ErrEmbeddedRouterTimeout is returned when the embedded router fails to become ready.
	ErrEmbeddedRouterTimeout = errors.New("embedding: embedded router did not become ready within timeout")
)
