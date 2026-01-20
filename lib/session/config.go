// Package session implements SAM v3.0-3.3 session management.
package session

import "time"

// SessionConfig holds configuration options for SAM sessions.
// These options are set during SESSION CREATE and affect tunnel behavior.
// See SAMv3.md section on SESSION CREATE for full option details.
type SessionConfig struct {
	// SignatureType specifies the signature algorithm for the destination.
	// Default is 7 (Ed25519) per SAM specification recommendation.
	// Valid values: 0=DSA_SHA1 (deprecated), 1-6=ECDSA/RSA, 7=Ed25519, 8=Ed25519ph.
	SignatureType int

	// EncryptionTypes specifies the encryption algorithms.
	// Default is [4, 0] (ECIES-X25519 with ElGamal fallback).
	EncryptionTypes []int

	// InboundQuantity is the number of inbound tunnels.
	// Default is 3 for balanced performance between Java I2P and i2pd.
	InboundQuantity int

	// OutboundQuantity is the number of outbound tunnels.
	// Default is 3 for balanced performance between Java I2P and i2pd.
	OutboundQuantity int

	// InboundLength is the number of hops for inbound tunnels.
	// Default is 3 for reasonable anonymity.
	InboundLength int

	// OutboundLength is the number of hops for outbound tunnels.
	// Default is 3 for reasonable anonymity.
	OutboundLength int

	// InboundBackupQuantity is the number of backup inbound tunnels.
	InboundBackupQuantity int

	// OutboundBackupQuantity is the number of backup outbound tunnels.
	OutboundBackupQuantity int

	// FromPort is the default source port for outbound traffic (SAM 3.2+).
	// Valid range: 0-65535, default 0.
	FromPort int

	// ToPort is the default destination port for outbound traffic (SAM 3.2+).
	// Valid range: 0-65535, default 0.
	ToPort int

	// Protocol is the I2CP protocol number for RAW sessions.
	// Valid range: 0-255 excluding 6, 17, 19, 20. Default is 18.
	Protocol int

	// HeaderEnabled enables header prepending for RAW forwarding (SAM 3.2+).
	// When true, forwarded datagrams include FROM_PORT/TO_PORT/PROTOCOL.
	HeaderEnabled bool

	// ListenPort is the port to listen on for inbound traffic (SAM 3.3+).
	// Default is the FromPort value.
	ListenPort int

	// ListenProtocol is the protocol to listen on for RAW sessions (SAM 3.3+).
	// Subsession feature to receive on different protocols.
	ListenProtocol int

	// ReduceIdleTime enables tunnel reduction when idle (seconds).
	// 0 means disabled.
	ReduceIdleTime int

	// ReduceIdleQuantity is the number of tunnels to keep when idle.
	ReduceIdleQuantity int

	// CloseIdleTime closes the session after idle for this duration (seconds).
	// 0 means disabled.
	CloseIdleTime int

	// OfflineSignature contains offline signature data if provided.
	// Allows transient keys while keeping long-term identity offline.
	OfflineSignature *OfflineSignature
}

// OfflineSignature represents offline signing capability per SAM 3.3.
// This allows a session to use a transient signing key while keeping
// the long-term identity key offline for security.
type OfflineSignature struct {
	// Expires is the Unix timestamp when the offline signature expires.
	Expires int64
	// TransientType is the signature type of the transient key.
	TransientType int
	// TransientPublicKey is the transient public signing key.
	TransientPublicKey []byte
	// Signature is the signature from the long-term key.
	Signature []byte
}

// DefaultSessionConfig returns a SessionConfig with recommended defaults.
// Uses Ed25519 signatures, ECIES encryption, and 3 tunnels for compatibility.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		SignatureType:          DefaultSignatureType,
		EncryptionTypes:        append([]int{}, DefaultEncryptionTypes...),
		InboundQuantity:        DefaultTunnelQuantity,
		OutboundQuantity:       DefaultTunnelQuantity,
		InboundLength:          DefaultTunnelLength,
		OutboundLength:         DefaultTunnelLength,
		InboundBackupQuantity:  0,
		OutboundBackupQuantity: 0,
		FromPort:               0,
		ToPort:                 0,
		Protocol:               DefaultRawProtocol,
		HeaderEnabled:          false,
		ListenPort:             0,
		ListenProtocol:         0,
		ReduceIdleTime:         0,
		ReduceIdleQuantity:     0,
		CloseIdleTime:          0,
		OfflineSignature:       nil,
	}
}

// Default values for session configuration.
const (
	// DefaultSignatureType is Ed25519 per SAM specification.
	DefaultSignatureType = 7

	// DefaultTunnelQuantity is balanced for Java I2P (2) and i2pd (5).
	DefaultTunnelQuantity = 3

	// DefaultTunnelLength provides reasonable anonymity.
	DefaultTunnelLength = 3

	// DefaultRawProtocol is 18 per SAMv3.md specification.
	DefaultRawProtocol = 18
)

// DefaultEncryptionTypes specifies ECIES-X25519 with ElGamal fallback.
var DefaultEncryptionTypes = []int{4, 0}

// ConnectOptions holds options for STREAM CONNECT operations.
// See SAMv3.md STREAM CONNECT command for details.
type ConnectOptions struct {
	// FromPort overrides session default source port (SAM 3.2+).
	FromPort int
	// ToPort overrides session default destination port (SAM 3.2+).
	ToPort int
	// Silent suppresses the response confirmation if true.
	Silent bool
	// Timeout specifies the connection timeout duration.
	Timeout time.Duration
}

// AcceptOptions holds options for STREAM ACCEPT operations.
// See SAMv3.md STREAM ACCEPT command for details.
type AcceptOptions struct {
	// Silent suppresses the response confirmation if true.
	Silent bool
	// Timeout specifies the accept timeout duration.
	Timeout time.Duration
}

// ForwardOptions holds options for STREAM FORWARD operations.
// See SAMv3.md STREAM FORWARD command for details.
type ForwardOptions struct {
	// Port is the local port to forward incoming connections to.
	Port int
	// Host is the local host to forward incoming connections to.
	// Defaults to "127.0.0.1".
	Host string
	// Silent suppresses the response confirmation if true.
	Silent bool
	// SSLEnabled enables TLS/SSL for the forwarded connection.
	SSLEnabled bool
}

// DatagramSendOptions holds options for DATAGRAM SEND operations.
// See SAMv3.md DATAGRAM SEND command for details.
type DatagramSendOptions struct {
	// FromPort overrides session default source port (SAM 3.2+).
	FromPort int
	// ToPort overrides session default destination port (SAM 3.2+).
	ToPort int
}

// RawSendOptions holds options for RAW SEND operations.
// See SAMv3.md RAW SEND command for details.
type RawSendOptions struct {
	// FromPort overrides session default source port (SAM 3.2+).
	FromPort int
	// ToPort overrides session default destination port (SAM 3.2+).
	ToPort int
	// Protocol overrides session default I2CP protocol (SAM 3.2+).
	Protocol int
}

// SubsessionOptions holds options for SESSION ADD operations on PRIMARY sessions.
// See SAMv3.md SESSION ADD command for details.
type SubsessionOptions struct {
	// FromPort is the default source port for outbound traffic.
	FromPort int
	// ToPort is the default destination port for outbound traffic.
	ToPort int
	// Protocol is the I2CP protocol for RAW subsessions.
	Protocol int
	// ListenPort is the port to listen on for inbound traffic.
	ListenPort int
	// ListenProtocol is the protocol to listen on for RAW subsessions.
	ListenProtocol int
	// HeaderEnabled enables header prepending for RAW forwarding.
	HeaderEnabled bool

	// Host is the forwarding host for DATAGRAM/RAW subsessions.
	Host string
	// Port is the forwarding port for DATAGRAM/RAW subsessions.
	Port int
}

// Validate checks that the session configuration is valid per SAM specification.
// Returns an error if any option is out of valid range.
func (c *SessionConfig) Validate() error {
	if c.FromPort < 0 || c.FromPort > 65535 {
		return ErrInvalidPort
	}
	if c.ToPort < 0 || c.ToPort > 65535 {
		return ErrInvalidPort
	}
	if c.Protocol < 0 || c.Protocol > 255 {
		return ErrInvalidProtocol
	}
	if isDisallowedProtocol(c.Protocol) {
		return ErrInvalidProtocol
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return ErrInvalidPort
	}
	if c.InboundQuantity < 0 || c.OutboundQuantity < 0 {
		return ErrInvalidTunnelConfig
	}
	if c.InboundLength < 0 || c.OutboundLength < 0 {
		return ErrInvalidTunnelConfig
	}
	return nil
}

// isDisallowedProtocol checks if the protocol number is disallowed for RAW.
func isDisallowedProtocol(protocol int) bool {
	// Protocols 6 (TCP), 17 (UDP), 19, 20 are disallowed per SAMv3.md
	switch protocol {
	case 6, 17, 19, 20:
		return true
	default:
		return false
	}
}

// WithFromPort sets the FromPort and returns the config for chaining.
func (c *SessionConfig) WithFromPort(port int) *SessionConfig {
	c.FromPort = port
	return c
}

// WithToPort sets the ToPort and returns the config for chaining.
func (c *SessionConfig) WithToPort(port int) *SessionConfig {
	c.ToPort = port
	return c
}

// WithTunnelQuantity sets both inbound and outbound tunnel quantities.
func (c *SessionConfig) WithTunnelQuantity(quantity int) *SessionConfig {
	c.InboundQuantity = quantity
	c.OutboundQuantity = quantity
	return c
}

// WithTunnelLength sets both inbound and outbound tunnel lengths.
func (c *SessionConfig) WithTunnelLength(length int) *SessionConfig {
	c.InboundLength = length
	c.OutboundLength = length
	return c
}

// WithSignatureType sets the signature type for destination generation.
func (c *SessionConfig) WithSignatureType(sigType int) *SessionConfig {
	c.SignatureType = sigType
	return c
}

// WithEncryptionTypes sets the encryption types for the session.
func (c *SessionConfig) WithEncryptionTypes(types []int) *SessionConfig {
	c.EncryptionTypes = append([]int{}, types...)
	return c
}

// Clone creates a deep copy of the configuration.
func (c *SessionConfig) Clone() *SessionConfig {
	if c == nil {
		return nil
	}
	clone := *c
	if c.EncryptionTypes != nil {
		clone.EncryptionTypes = append([]int{}, c.EncryptionTypes...)
	}
	if c.OfflineSignature != nil {
		offlineCopy := *c.OfflineSignature
		if c.OfflineSignature.TransientPublicKey != nil {
			offlineCopy.TransientPublicKey = append([]byte{}, c.OfflineSignature.TransientPublicKey...)
		}
		if c.OfflineSignature.Signature != nil {
			offlineCopy.Signature = append([]byte{}, c.OfflineSignature.Signature...)
		}
		clone.OfflineSignature = &offlineCopy
	}
	return &clone
}
