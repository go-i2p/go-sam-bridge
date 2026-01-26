// Package session implements SAM v3.0-3.3 session management.
package session

import (
	"sync"

	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// Registry manages all active sessions with global uniqueness enforcement.
// Thread-safe for concurrent access per SAM 3.2 requirements.
type Registry interface {
	// Register adds a session to the registry.
	// Returns ErrDuplicateID if session ID already exists.
	// Returns ErrDuplicateDest if destination already in use.
	Register(s Session) error

	// Unregister removes a session from the registry by ID.
	// Returns ErrSessionNotFound if the session does not exist.
	Unregister(id string) error

	// Get returns a session by ID, or nil if not found.
	Get(id string) Session

	// GetByDestination returns a session by destination hash, or nil if not found.
	GetByDestination(destHash string) Session

	// MostRecentByStyle returns the most recently created session of the given style.
	// Per SAMv3.md: "DATAGRAM SEND/RAW SEND sends to the most recently created
	// DATAGRAM- or RAW-style session, as appropriate."
	// Returns nil if no session of that style exists.
	MostRecentByStyle(style Style) Session

	// All returns all registered session IDs.
	All() []string

	// Count returns the number of active sessions.
	Count() int

	// Close terminates all sessions and clears the registry.
	Close() error
}

// RegistryImpl is the concrete implementation of Registry.
// It enforces global uniqueness of session IDs and destinations.
type RegistryImpl struct {
	mu       sync.RWMutex
	sessions map[string]Session // id -> Session
	dests    map[string]string  // destHash -> id (for uniqueness check)

	// Track most recently created sessions by style for V1/V2 DATAGRAM/RAW commands.
	// Per SAMv3.md: "DATAGRAM SEND/RAW SEND sends to the most recently created
	// DATAGRAM- or RAW-style session, as appropriate."
	mostRecentByStyle map[Style]string // style -> session id
}

// NewRegistry creates a new session registry.
func NewRegistry() *RegistryImpl {
	return &RegistryImpl{
		sessions:          make(map[string]Session),
		dests:             make(map[string]string),
		mostRecentByStyle: make(map[Style]string),
	}
}

// Register adds a session to the registry.
// Returns util.ErrDuplicateID if session ID already exists.
// Returns util.ErrDuplicateDest if destination already in use.
func (r *RegistryImpl) Register(s Session) error {
	if s == nil {
		return util.ErrSessionNotFound
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	id := s.ID()
	if id == "" {
		return util.ErrSessionNotFound
	}

	// Check ID uniqueness
	if _, exists := r.sessions[id]; exists {
		return util.ErrDuplicateID
	}

	// Check destination uniqueness (if destination is set)
	dest := s.Destination()
	if dest != nil {
		destHash := dest.Hash()
		if destHash != "" {
			if _, exists := r.dests[destHash]; exists {
				return util.ErrDuplicateDest
			}
			r.dests[destHash] = id
		}
	}

	r.sessions[id] = s

	// Track most recently created session by style for V1/V2 DATAGRAM/RAW commands.
	// Per SAMv3.md: "DATAGRAM SEND/RAW SEND sends to the most recently created
	// DATAGRAM- or RAW-style session, as appropriate."
	style := s.Style()
	if style == StyleDatagram || style == StyleDatagram2 || style == StyleDatagram3 || style == StyleRaw {
		r.mostRecentByStyle[style] = id
	}

	return nil
}

// Unregister removes a session from the registry by ID.
// Returns util.ErrSessionNotFound if the session does not exist.
func (r *RegistryImpl) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, exists := r.sessions[id]
	if !exists {
		return util.ErrSessionNotFound
	}

	// Remove destination mapping
	if dest := s.Destination(); dest != nil {
		destHash := dest.Hash()
		if destHash != "" {
			delete(r.dests, destHash)
		}
	}

	// Clean up most recent tracking if this was the most recent for its style
	style := s.Style()
	if r.mostRecentByStyle[style] == id {
		delete(r.mostRecentByStyle, style)
	}

	delete(r.sessions, id)
	return nil
}

// Get returns a session by ID, or nil if not found.
func (r *RegistryImpl) Get(id string) Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[id]
}

// GetByDestination returns a session by destination hash, or nil if not found.
func (r *RegistryImpl) GetByDestination(destHash string) Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if id, exists := r.dests[destHash]; exists {
		return r.sessions[id]
	}
	return nil
}

// MostRecentByStyle returns the most recently created session of the given style.
// Per SAMv3.md: "DATAGRAM SEND/RAW SEND sends to the most recently created
// DATAGRAM- or RAW-style session, as appropriate."
// Returns nil if no session of that style exists.
func (r *RegistryImpl) MostRecentByStyle(style Style) Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if id, exists := r.mostRecentByStyle[style]; exists {
		return r.sessions[id]
	}
	return nil
}

// All returns all registered session IDs.
func (r *RegistryImpl) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active sessions.
func (r *RegistryImpl) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// Close terminates all sessions and clears the registry.
// Sessions are collected first and the lock is released before closing them
// to prevent deadlocks if session close callbacks attempt to unregister.
// Errors from individual session closes are ignored.
func (r *RegistryImpl) Close() error {
	// Collect sessions while holding the lock
	r.mu.Lock()
	sessions := make([]Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	// Clear registry state while still holding the lock
	r.sessions = make(map[string]Session)
	r.dests = make(map[string]string)
	r.mostRecentByStyle = make(map[Style]string)
	r.mu.Unlock()

	// Close sessions without holding the lock to prevent deadlocks
	// from session close callbacks that may call Unregister
	for _, s := range sessions {
		_ = s.Close()
	}
	return nil
}

// Has returns true if a session with the given ID exists.
func (r *RegistryImpl) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.sessions[id]
	return exists
}

// HasDestination returns true if a session with the given destination hash exists.
func (r *RegistryImpl) HasDestination(destHash string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.dests[destHash]
	return exists
}
