// Package session implements SAM v3.0-3.3 session management.
// This file implements PrimarySessionImpl for PRIMARY/MASTER session handling
// per SAM 3.3 specification for multiplexed subsession support.
package session

import (
	"fmt"
	"net"
	"sync"
)

// PrimarySessionImpl implements the PrimarySession interface for PRIMARY/MASTER style.
// It embeds *BaseSession and provides multiplexed subsession support.
//
// Per SAMv3.md and PLAN.md Phase 5.2:
//   - Multiple subsessions share a single destination
//   - Routing of incoming traffic is based on port/protocol
//   - Subsession IDs must be globally unique
//   - All subsessions closed when primary is closed
//
// A PRIMARY session connects to the router and builds tunnels. Once ready,
// subsessions can be added that share the tunnels. This enables a single
// application to support multiple protocols (STREAM, DATAGRAM, RAW) on
// one destination.
//
// Key concepts:
//   - LISTEN_PORT: Port to listen on for inbound traffic
//   - LISTEN_PROTOCOL: Protocol for RAW inbound routing
//   - Default subsession: Handles unmatched inbound traffic
type PrimarySessionImpl struct {
	*BaseSession

	mu sync.RWMutex

	// subsessions maps subsession ID -> Session
	subsessions map[string]Session

	// routingTable maps (listenPort, listenProtocol) -> subsession ID
	// Key format: "port:protocol" where 0 means wildcard
	routingTable map[string]string

	// defaultSubsession is the subsession that receives unmatched traffic
	// (when LISTEN_PORT=0 and LISTEN_PROTOCOL=0)
	defaultSubsession string
}

// NewPrimarySession creates a new PRIMARY session for multiplexed subsession support.
//
// Parameters:
//   - id: Unique session identifier (nickname)
//   - dest: I2P destination for this session (shared by all subsessions)
//   - conn: Control connection (session dies when this closes)
//   - cfg: Session configuration (tunnel settings)
//
// Per SAM 3.3 specification, the primary session starts in Creating state.
// After tunnels are built and status becomes Active, subsessions can be added.
//
// Note: Use STYLE=MASTER for pre-0.9.47 compatibility, STYLE=PRIMARY for 0.9.47+
func NewPrimarySession(
	id string,
	dest *Destination,
	conn net.Conn,
	cfg *SessionConfig,
) *PrimarySessionImpl {
	// Ensure we have a config with valid defaults
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}

	return &PrimarySessionImpl{
		BaseSession:  NewBaseSession(id, StylePrimary, dest, conn, cfg),
		subsessions:  make(map[string]Session),
		routingTable: make(map[string]string),
	}
}

// AddSubsession creates a new subsession with the given style and options.
// Implements SAM 3.3 SESSION ADD command.
//
// Parameters:
//   - id: Unique subsession identifier (must be globally unique)
//   - style: Subsession style (STREAM, DATAGRAM, RAW, DATAGRAM2, DATAGRAM3)
//   - opts: Subsession options (ports, protocol, forwarding)
//
// Returns error if:
//   - Primary session is not active
//   - Subsession ID already exists
//   - Routing conflict with existing subsession
//   - Invalid style or options
//
// Per SAM spec, subsessions use the same destination as the primary session.
// Multiple subsessions must have unique LISTEN_PORT/LISTEN_PROTOCOL combinations.
func (p *PrimarySessionImpl) AddSubsession(id string, style Style, opts SubsessionOptions) (Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Validate preconditions
	if err := p.validateAddSubsession(id, style, opts); err != nil {
		return nil, err
	}

	// Apply default options per SAM spec
	p.applySubsessionDefaults(&opts, style)

	// Validate and reserve routing
	routingKey, err := p.validateSubsessionRouting(opts)
	if err != nil {
		return nil, err
	}

	// Create the subsession
	sess, err := p.createSubsession(id, style, opts)
	if err != nil {
		return nil, err
	}

	// Register the subsession
	p.registerSubsession(id, sess, routingKey, opts)

	return sess, nil
}

// validateAddSubsession checks preconditions for adding a subsession.
func (p *PrimarySessionImpl) validateAddSubsession(id string, style Style, opts SubsessionOptions) error {
	if p.Status() != StatusActive {
		return ErrSessionNotActive
	}

	if _, exists := p.subsessions[id]; exists {
		return ErrDuplicateSubsessionID
	}

	if style.IsPrimary() {
		return ErrInvalidSubsessionStyle
	}

	// Validate RAW-specific options
	if style == StyleRaw && opts.ListenProtocol == 6 {
		return ErrProtocol6Disallowed
	}
	return nil
}

// applySubsessionDefaults applies default values per SAM spec.
func (p *PrimarySessionImpl) applySubsessionDefaults(opts *SubsessionOptions, style Style) {
	// Per SAM spec: If LISTEN_PORT is not specified, default to FROM_PORT
	if opts.ListenPort == 0 && opts.FromPort != 0 {
		opts.ListenPort = opts.FromPort
	}

	// Per SAM spec: For RAW, if LISTEN_PROTOCOL is not specified, default to PROTOCOL
	if style == StyleRaw && opts.ListenProtocol == 0 && opts.Protocol != 0 {
		opts.ListenProtocol = opts.Protocol
	}
}

// validateSubsessionRouting checks for routing conflicts.
func (p *PrimarySessionImpl) validateSubsessionRouting(opts SubsessionOptions) (string, error) {
	routingKey := p.makeRoutingKey(opts.ListenPort, opts.ListenProtocol)
	if existing, exists := p.routingTable[routingKey]; exists {
		return "", fmt.Errorf("%w: conflicts with subsession %s", ErrRoutingConflict, existing)
	}
	return routingKey, nil
}

// createSubsession creates the appropriate session type for the subsession.
func (p *PrimarySessionImpl) createSubsession(id string, style Style, opts SubsessionOptions) (Session, error) {
	cfg := p.createSubsessionConfig(opts)

	var sess Session
	switch style {
	case StyleStream:
		sess = NewStreamSession(id, p.Destination(), p.ControlConn(), cfg, nil, nil)
	case StyleDatagram:
		sess = NewDatagramSession(id, p.Destination(), p.ControlConn(), cfg)
	case StyleDatagram2:
		sess = NewDatagram2Session(id, p.Destination(), p.ControlConn(), cfg)
	case StyleDatagram3:
		sess = NewDatagram3Session(id, p.Destination(), p.ControlConn(), cfg)
	case StyleRaw:
		sess = NewRawSession(id, p.Destination(), p.ControlConn(), cfg)
	default:
		return nil, ErrInvalidSubsessionStyle
	}

	// Configure forwarding for DATAGRAM/RAW if specified
	if opts.Port > 0 {
		if fwd, ok := sess.(forwardable); ok {
			host := opts.Host
			if host == "" {
				host = "127.0.0.1"
			}
			if err := fwd.SetForwarding(host, opts.Port); err != nil {
				return nil, fmt.Errorf("failed to set forwarding: %w", err)
			}
		}
	}
	return sess, nil
}

// registerSubsession stores the subsession and sets up routing.
func (p *PrimarySessionImpl) registerSubsession(id string, sess Session, routingKey string, opts SubsessionOptions) {
	p.subsessions[id] = sess
	p.routingTable[routingKey] = id

	// Track default subsession (LISTEN_PORT=0 and LISTEN_PROTOCOL=0)
	if opts.ListenPort == 0 && opts.ListenProtocol == 0 {
		p.defaultSubsession = id
	}

	// Activate subsession immediately (tunnels already built)
	if activatable, ok := sess.(interface{ SetStatus(Status) }); ok {
		activatable.SetStatus(StatusActive)
	}
}

// RemoveSubsession terminates and removes a subsession by ID.
// Implements SAM 3.3 SESSION REMOVE command.
//
// Returns error if:
//   - Subsession not found
//
// After removal, the subsession is closed and cannot be used.
func (p *PrimarySessionImpl) RemoveSubsession(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	sess, exists := p.subsessions[id]
	if !exists {
		return ErrSubsessionNotFound
	}

	// Close the subsession
	if err := sess.Close(); err != nil {
		// Log but don't fail - we still want to remove it
		_ = err
	}

	// Remove from subsessions map
	delete(p.subsessions, id)

	// Remove from routing table
	for key, subID := range p.routingTable {
		if subID == id {
			delete(p.routingTable, key)
			break
		}
	}

	// Clear default if this was it
	if p.defaultSubsession == id {
		p.defaultSubsession = ""
	}

	return nil
}

// Subsession returns a subsession by ID, or nil if not found.
func (p *PrimarySessionImpl) Subsession(id string) Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.subsessions[id]
}

// Subsessions returns all active subsession IDs.
func (p *PrimarySessionImpl) Subsessions() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ids := make([]string, 0, len(p.subsessions))
	for id := range p.subsessions {
		ids = append(ids, id)
	}
	return ids
}

// RouteIncoming returns the subsession ID for incoming data based on port/protocol.
// Used for routing incoming traffic to the correct subsession.
//
// Routing rules per SAMv3.md:
//  1. Exact match on (port, protocol) if exists
//  2. Wildcard match on (port, 0) if exists
//  3. Wildcard match on (0, protocol) if exists
//  4. Default subsession (0, 0) if exists
//  5. Empty string if no match (data dropped)
//
// Note: Streaming traffic (protocol 6) never routes to RAW subsessions.
func (p *PrimarySessionImpl) RouteIncoming(port, protocol int) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Try exact match first
	if id := p.tryExactMatch(port, protocol); id != "" {
		return id
	}

	// Try wildcard matches
	if id := p.tryWildcardMatches(port, protocol); id != "" {
		return id
	}

	// Use default subsession if available
	return p.tryDefaultSubsession(protocol)
}

// tryExactMatch attempts exact port/protocol routing match.
func (p *PrimarySessionImpl) tryExactMatch(port, protocol int) string {
	key := p.makeRoutingKey(port, protocol)
	if id, exists := p.routingTable[key]; exists {
		return id
	}
	return ""
}

// tryWildcardMatches attempts wildcard routing matches.
func (p *PrimarySessionImpl) tryWildcardMatches(port, protocol int) string {
	// Try port wildcard (any protocol)
	key := p.makeRoutingKey(port, 0)
	if id, exists := p.routingTable[key]; exists {
		if !p.isStreamingToRaw(protocol, id) {
			return id
		}
	}

	// Try protocol wildcard (any port)
	key = p.makeRoutingKey(0, protocol)
	if id, exists := p.routingTable[key]; exists {
		return id
	}
	return ""
}

// tryDefaultSubsession attempts to route to default subsession.
func (p *PrimarySessionImpl) tryDefaultSubsession(protocol int) string {
	if p.defaultSubsession == "" {
		return ""
	}
	if p.isStreamingToRaw(protocol, p.defaultSubsession) {
		return ""
	}
	return p.defaultSubsession
}

// isStreamingToRaw checks if streaming protocol would route to RAW session.
func (p *PrimarySessionImpl) isStreamingToRaw(protocol int, subsessionID string) bool {
	if protocol != 6 {
		return false
	}
	if sess := p.subsessions[subsessionID]; sess != nil {
		return sess.Style() == StyleRaw
	}
	return false
}

// Close terminates the primary session and all subsessions.
// Safe to call multiple times.
func (p *PrimarySessionImpl) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Status() == StatusClosed {
		return nil
	}

	// Close all subsessions first
	for id, sess := range p.subsessions {
		_ = sess.Close() // Ignore errors, we're closing everything
		delete(p.subsessions, id)
	}

	// Clear routing table
	p.routingTable = make(map[string]string)
	p.defaultSubsession = ""

	// Close base session
	return p.BaseSession.Close()
}

// SubsessionCount returns the number of active subsessions.
func (p *PrimarySessionImpl) SubsessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.subsessions)
}

// makeRoutingKey creates a routing table key from port and protocol.
func (p *PrimarySessionImpl) makeRoutingKey(port, protocol int) string {
	return fmt.Sprintf("%d:%d", port, protocol)
}

// createSubsessionConfig creates a SessionConfig from SubsessionOptions.
func (p *PrimarySessionImpl) createSubsessionConfig(opts SubsessionOptions) *SessionConfig {
	cfg := DefaultSessionConfig()
	cfg.FromPort = opts.FromPort
	cfg.ToPort = opts.ToPort
	cfg.Protocol = opts.Protocol
	cfg.ListenPort = opts.ListenPort
	cfg.HeaderEnabled = opts.HeaderEnabled
	return cfg
}

// forwardable is an internal interface for sessions that support forwarding.
type forwardable interface {
	SetForwarding(host string, port int) error
}

// Error definitions for PrimarySession.
var (
	// ErrDuplicateSubsessionID indicates the subsession ID already exists.
	ErrDuplicateSubsessionID = fmt.Errorf("duplicate subsession ID")

	// ErrInvalidSubsessionStyle indicates an invalid style for subsession.
	ErrInvalidSubsessionStyle = fmt.Errorf("invalid subsession style: PRIMARY/MASTER not allowed")

	// ErrProtocol6Disallowed indicates LISTEN_PROTOCOL=6 is invalid for RAW.
	ErrProtocol6Disallowed = fmt.Errorf("LISTEN_PROTOCOL=6 (streaming) is disallowed for RAW subsessions")

	// ErrRoutingConflict indicates a LISTEN_PORT/LISTEN_PROTOCOL conflict.
	ErrRoutingConflict = fmt.Errorf("routing conflict: duplicate LISTEN_PORT/LISTEN_PROTOCOL")
)

// Verify PrimarySessionImpl implements PrimarySession interface.
var _ PrimarySession = (*PrimarySessionImpl)(nil)
