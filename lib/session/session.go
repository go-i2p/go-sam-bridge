// Package session implements SAM v3.0-3.3 session management.
// Sessions are long-lived entities that represent I2P destinations and provide
// communication capabilities (STREAM, DATAGRAM, RAW, PRIMARY).
// See SAMv3.md for the complete protocol specification.
package session

import (
	"net"
)

// Status represents the current state of a session per SAM lifecycle.
type Status int

const (
	// StatusCreating indicates the session is being created.
	StatusCreating Status = iota
	// StatusActive indicates the session is active and operational.
	StatusActive
	// StatusClosing indicates the session is being closed.
	StatusClosing
	// StatusClosed indicates the session has been closed.
	StatusClosed
)

// String returns a human-readable representation of the status.
func (s Status) String() string {
	switch s {
	case StatusCreating:
		return "CREATING"
	case StatusActive:
		return "ACTIVE"
	case StatusClosing:
		return "CLOSING"
	case StatusClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Style represents the SAM session style per SAM 3.0-3.3 specification.
type Style string

const (
	// StyleStream represents TCP-like virtual streams (SAM 3.0).
	StyleStream Style = "STREAM"
	// StyleDatagram represents repliable authenticated datagrams (SAM 3.0).
	StyleDatagram Style = "DATAGRAM"
	// StyleRaw represents anonymous datagrams (SAM 3.1).
	StyleRaw Style = "RAW"
	// StyleDatagram2 represents DATAGRAM with additional features.
	StyleDatagram2 Style = "DATAGRAM2"
	// StyleDatagram3 represents DATAGRAM with even more features.
	StyleDatagram3 Style = "DATAGRAM3"
	// StylePrimary represents multiplexed subsession support (SAM 3.3).
	StylePrimary Style = "PRIMARY"
	// StyleMaster is deprecated alias for PRIMARY (pre-0.9.47).
	StyleMaster Style = "MASTER"
)

// IsValid returns true if the style is a recognized SAM session style.
func (s Style) IsValid() bool {
	switch s {
	case StyleStream, StyleDatagram, StyleRaw, StyleDatagram2, StyleDatagram3, StylePrimary, StyleMaster:
		return true
	default:
		return false
	}
}

// IsPrimary returns true if this is a PRIMARY or MASTER session style.
func (s Style) IsPrimary() bool {
	return s == StylePrimary || s == StyleMaster
}

// Destination represents an I2P destination with public and private keys.
// This is a placeholder that will be fully implemented in lib/destination.
type Destination struct {
	// PublicKey is the I2P destination (public portion).
	PublicKey []byte
	// PrivateKey is the full private key for signing.
	PrivateKey []byte
	// SignatureType is the signature algorithm (e.g., 7 for Ed25519).
	SignatureType int
	// OfflineSignature contains parsed offline signature data, if present.
	// Offline signatures allow using a transient key while keeping the
	// long-term identity key offline for security. Per SAMv3.md, offline
	// signatures are only supported for STREAM and RAW sessions.
	OfflineSignature *ParsedOfflineSignature
}

// ParsedOfflineSignature mirrors destination.ParsedOfflineSignature for session package use.
// This avoids circular imports between session and destination packages.
type ParsedOfflineSignature struct {
	// Expires is the Unix timestamp when the offline signature expires.
	Expires int64
	// TransientSigType is the signature type of the transient key.
	TransientSigType int
	// TransientPublicKey is the transient signing public key.
	TransientPublicKey []byte
	// Signature is the signature from the long-term (offline) key.
	Signature []byte
	// TransientPrivateKey is the transient signing private key.
	TransientPrivateKey []byte
}

// HasOfflineSignature returns true if the destination has an offline signature.
func (d *Destination) HasOfflineSignature() bool {
	return d != nil && d.OfflineSignature != nil
}

// Hash returns a unique identifier for the destination (typically a hash of the public key).
func (d *Destination) Hash() string {
	if d == nil || len(d.PublicKey) == 0 {
		return ""
	}
	// For now, use a simple hex representation of first 32 bytes
	// This will be replaced with proper I2P hash calculation
	hashLen := len(d.PublicKey)
	if hashLen > 32 {
		hashLen = 32
	}
	return string(d.PublicKey[:hashLen])
}

// Session defines the base interface for all SAM session types.
// All session implementations must embed *BaseSession per SAM 3.0 specification.
type Session interface {
	// ID returns the unique session identifier (nickname).
	// Session IDs must be globally unique per SAMv3.md.
	ID() string

	// Style returns the session style (STREAM, DATAGRAM, RAW, PRIMARY, etc.).
	Style() Style

	// Destination returns the I2P destination associated with this session.
	// Returns the full private key for SESSION STATUS responses.
	Destination() *Destination

	// Status returns the current session status.
	Status() Status

	// Close terminates the session and releases all resources.
	// Must be safe to call multiple times.
	Close() error

	// ControlConn returns the control socket associated with this session.
	// Session dies when this socket closes per SAMv3.md.
	ControlConn() net.Conn
}

// ReceivedDatagram represents a received datagram with source information.
type ReceivedDatagram struct {
	// Source is the I2P destination that sent the datagram.
	Source string
	// FromPort is the source port (SAM 3.2+).
	FromPort int
	// ToPort is the destination port (SAM 3.2+).
	ToPort int
	// Data is the datagram payload.
	Data []byte
}

// ReceivedRawDatagram represents a received raw datagram with header info.
type ReceivedRawDatagram struct {
	// FromPort is the source port (SAM 3.2+).
	FromPort int
	// ToPort is the destination port (SAM 3.2+).
	ToPort int
	// Protocol is the I2CP protocol number.
	Protocol int
	// Data is the datagram payload.
	Data []byte
}

// StreamSession extends Session with STREAM-specific operations.
// Implements SAM 3.0 STREAM CONNECT, ACCEPT, FORWARD commands.
type StreamSession interface {
	Session

	// Connect establishes an outbound stream to the specified destination.
	// Implements SAM 3.0 STREAM CONNECT command.
	// The returned net.Conn is used for bidirectional data transfer.
	Connect(dest string, opts ConnectOptions) (net.Conn, error)

	// Accept waits for and accepts an incoming stream connection.
	// Implements SAM 3.0 STREAM ACCEPT command.
	// Concurrent ACCEPTs are supported as of SAM 3.2.
	Accept(opts AcceptOptions) (net.Conn, string, error)

	// Forward sets up forwarding of incoming connections to host:port.
	// Implements SAM 3.0 STREAM FORWARD command.
	// FORWARD and ACCEPT are mutually exclusive.
	Forward(host string, port int, opts ForwardOptions) error

	// IsForwarding returns true if FORWARD is active on this session.
	IsForwarding() bool
}

// DatagramSession extends Session with DATAGRAM-specific operations.
// Implements SAM 3.0 DATAGRAM sessions with repliable/authenticated datagrams.
type DatagramSession interface {
	Session

	// Send transmits a repliable datagram to the specified destination.
	// Implements SAM DATAGRAM SEND command.
	Send(dest string, data []byte, opts DatagramSendOptions) error

	// Receive returns a channel for incoming datagrams.
	// Each received datagram includes source destination and data.
	Receive() <-chan ReceivedDatagram

	// ForwardingAddr returns the UDP address for forwarding, if configured.
	ForwardingAddr() net.Addr
}

// RawSession extends Session with RAW-specific operations.
// Implements SAM 3.1 RAW sessions with anonymous datagrams.
type RawSession interface {
	Session

	// Send transmits an anonymous raw datagram to the specified destination.
	// Implements SAM RAW SEND command.
	Send(dest string, data []byte, opts RawSendOptions) error

	// Receive returns a channel for incoming raw datagrams.
	Receive() <-chan ReceivedRawDatagram

	// Protocol returns the I2CP protocol number for this RAW session.
	// Default is 18; range 0-255 excluding 6, 17, 19, 20.
	Protocol() int

	// HeaderEnabled returns true if HEADER=true was specified.
	// When true, forwarded datagrams include FROM_PORT/TO_PORT/PROTOCOL header.
	HeaderEnabled() bool
}

// PrimarySession extends Session with PRIMARY/MASTER session operations.
// Implements SAM 3.3 multiplexed subsession support.
type PrimarySession interface {
	Session

	// AddSubsession creates a new subsession with the given style and options.
	// Implements SAM 3.3 SESSION ADD command.
	// Subsession IDs must be globally unique.
	AddSubsession(id string, style Style, opts SubsessionOptions) (Session, error)

	// RemoveSubsession terminates and removes a subsession by ID.
	// Implements SAM 3.3 SESSION REMOVE command.
	RemoveSubsession(id string) error

	// Subsession returns a subsession by ID, or nil if not found.
	Subsession(id string) Session

	// Subsessions returns all active subsession IDs.
	Subsessions() []string
}
