// Package session implements SAM v3.0-3.3 session management.
// Tests for PrimarySessionImpl.
package session

import (
	"testing"
)

func TestNewPrimarySession(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		config *SessionConfig
	}{
		{
			name:   "basic creation",
			id:     "test-primary",
			config: DefaultSessionConfig(),
		},
		{
			name:   "nil config uses defaults",
			id:     "test-primary-nil",
			config: nil,
		},
		{
			name:   "empty id",
			id:     "",
			config: DefaultSessionConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewPrimarySession(tt.id, nil, nil, tt.config)
			if sess == nil {
				t.Fatal("NewPrimarySession returned nil")
			}

			if sess.ID() != tt.id {
				t.Errorf("ID() = %q, want %q", sess.ID(), tt.id)
			}

			if sess.Style() != StylePrimary {
				t.Errorf("Style() = %v, want %v", sess.Style(), StylePrimary)
			}

			if sess.Status() != StatusCreating {
				t.Errorf("Status() = %v, want %v", sess.Status(), StatusCreating)
			}

			if sess.SubsessionCount() != 0 {
				t.Errorf("SubsessionCount() = %d, want 0", sess.SubsessionCount())
			}

			// Clean up
			if err := sess.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestPrimarySession_AddSubsession(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		style    Style
		opts     SubsessionOptions
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "add STREAM subsession",
			id:      "stream-sub",
			style:   StyleStream,
			opts:    SubsessionOptions{ListenPort: 1234},
			wantErr: false,
		},
		{
			name:    "add DATAGRAM subsession",
			id:      "dg-sub",
			style:   StyleDatagram,
			opts:    SubsessionOptions{ListenPort: 2345},
			wantErr: false,
		},
		{
			name:    "add DATAGRAM2 subsession",
			id:      "dg2-sub",
			style:   StyleDatagram2,
			opts:    SubsessionOptions{ListenPort: 3456},
			wantErr: false,
		},
		{
			name:    "add DATAGRAM3 subsession",
			id:      "dg3-sub",
			style:   StyleDatagram3,
			opts:    SubsessionOptions{ListenPort: 4567},
			wantErr: false,
		},
		{
			name:    "add RAW subsession",
			id:      "raw-sub",
			style:   StyleRaw,
			opts:    SubsessionOptions{ListenPort: 5678, ListenProtocol: 18},
			wantErr: false,
		},
		{
			name:    "add default subsession (0:0)",
			id:      "default-sub",
			style:   StyleStream,
			opts:    SubsessionOptions{ListenPort: 0, ListenProtocol: 0},
			wantErr: false,
		},
		{
			name:    "reject PRIMARY style",
			id:      "invalid-primary",
			style:   StylePrimary,
			opts:    SubsessionOptions{},
			wantErr: true,
			errCheck: func(err error) bool {
				return err == ErrInvalidSubsessionStyle
			},
		},
		{
			name:    "reject MASTER style",
			id:      "invalid-master",
			style:   StyleMaster,
			opts:    SubsessionOptions{},
			wantErr: true,
			errCheck: func(err error) bool {
				return err == ErrInvalidSubsessionStyle
			},
		},
		{
			name:    "reject RAW with LISTEN_PROTOCOL=6",
			id:      "invalid-raw-6",
			style:   StyleRaw,
			opts:    SubsessionOptions{ListenPort: 6666, ListenProtocol: 6},
			wantErr: true,
			errCheck: func(err error) bool {
				return err == ErrProtocol6Disallowed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := NewPrimarySession("test-primary", nil, nil, nil)
			primary.SetStatus(StatusActive) // Must be active to add subsessions
			defer primary.Close()

			sub, err := primary.AddSubsession(tt.id, tt.style, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("AddSubsession() expected error, got nil")
				} else if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("AddSubsession() error = %v, wrong error type", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("AddSubsession() error = %v", err)
			}

			if sub == nil {
				t.Fatal("AddSubsession() returned nil session")
			}

			if sub.ID() != tt.id {
				t.Errorf("Subsession ID() = %q, want %q", sub.ID(), tt.id)
			}

			if sub.Style() != tt.style {
				t.Errorf("Subsession Style() = %v, want %v", sub.Style(), tt.style)
			}

			// Verify subsession is registered
			if primary.Subsession(tt.id) == nil {
				t.Error("Subsession not registered in primary")
			}
		})
	}
}

func TestPrimarySession_AddSubsession_NotActive(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	defer primary.Close()

	// Primary is in StatusCreating, not StatusActive
	_, err := primary.AddSubsession("sub1", StyleStream, SubsessionOptions{})
	if err != ErrSessionNotActive {
		t.Errorf("AddSubsession() error = %v, want %v", err, ErrSessionNotActive)
	}
}

func TestPrimarySession_AddSubsession_DuplicateID(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add first subsession
	_, err := primary.AddSubsession("sub1", StyleStream, SubsessionOptions{ListenPort: 1000})
	if err != nil {
		t.Fatalf("First AddSubsession() error = %v", err)
	}

	// Try to add duplicate
	_, err = primary.AddSubsession("sub1", StyleDatagram, SubsessionOptions{ListenPort: 2000})
	if err != ErrDuplicateSubsessionID {
		t.Errorf("AddSubsession() error = %v, want %v", err, ErrDuplicateSubsessionID)
	}
}

func TestPrimarySession_AddSubsession_RoutingConflict(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add first subsession with port 1234
	_, err := primary.AddSubsession("sub1", StyleStream, SubsessionOptions{ListenPort: 1234})
	if err != nil {
		t.Fatalf("First AddSubsession() error = %v", err)
	}

	// Try to add another with same port - should conflict
	_, err = primary.AddSubsession("sub2", StyleStream, SubsessionOptions{ListenPort: 1234})
	if err == nil {
		t.Error("AddSubsession() expected routing conflict error, got nil")
	}
}

func TestPrimarySession_RemoveSubsession(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add a subsession
	_, err := primary.AddSubsession("sub1", StyleStream, SubsessionOptions{ListenPort: 1234})
	if err != nil {
		t.Fatalf("AddSubsession() error = %v", err)
	}

	// Verify it exists
	if primary.Subsession("sub1") == nil {
		t.Fatal("Subsession not found after add")
	}

	// Remove it
	if err := primary.RemoveSubsession("sub1"); err != nil {
		t.Errorf("RemoveSubsession() error = %v", err)
	}

	// Verify it's gone
	if primary.Subsession("sub1") != nil {
		t.Error("Subsession still exists after remove")
	}

	if primary.SubsessionCount() != 0 {
		t.Errorf("SubsessionCount() = %d, want 0", primary.SubsessionCount())
	}
}

func TestPrimarySession_RemoveSubsession_NotFound(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	err := primary.RemoveSubsession("nonexistent")
	if err != ErrSubsessionNotFound {
		t.Errorf("RemoveSubsession() error = %v, want %v", err, ErrSubsessionNotFound)
	}
}

func TestPrimarySession_Subsessions(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Initially empty
	if ids := primary.Subsessions(); len(ids) != 0 {
		t.Errorf("Subsessions() = %v, want empty", ids)
	}

	// Add several subsessions
	expectedIDs := []string{"sub1", "sub2", "sub3"}
	for i, id := range expectedIDs {
		_, err := primary.AddSubsession(id, StyleStream, SubsessionOptions{ListenPort: 1000 + i})
		if err != nil {
			t.Fatalf("AddSubsession(%s) error = %v", id, err)
		}
	}

	// Check count
	if primary.SubsessionCount() != 3 {
		t.Errorf("SubsessionCount() = %d, want 3", primary.SubsessionCount())
	}

	// Check all IDs are returned
	ids := primary.Subsessions()
	if len(ids) != 3 {
		t.Errorf("Subsessions() len = %d, want 3", len(ids))
	}

	// Verify each expected ID is present
	for _, expected := range expectedIDs {
		found := false
		for _, id := range ids {
			if id == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Subsessions() missing %q", expected)
		}
	}
}

func TestPrimarySession_RouteIncoming(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add subsessions with different port/protocol combinations
	_, _ = primary.AddSubsession("exact-1234", StyleStream, SubsessionOptions{ListenPort: 1234, ListenProtocol: 0})
	_, _ = primary.AddSubsession("port-5000", StyleDatagram, SubsessionOptions{ListenPort: 5000, ListenProtocol: 0})
	_, _ = primary.AddSubsession("raw-18", StyleRaw, SubsessionOptions{ListenPort: 0, ListenProtocol: 18})
	_, _ = primary.AddSubsession("default", StyleStream, SubsessionOptions{ListenPort: 0, ListenProtocol: 0})

	tests := []struct {
		name     string
		port     int
		protocol int
		wantID   string
	}{
		{
			name:     "exact match port 1234",
			port:     1234,
			protocol: 0,
			wantID:   "exact-1234",
		},
		{
			name:     "exact match port 5000",
			port:     5000,
			protocol: 0,
			wantID:   "port-5000",
		},
		{
			name:     "protocol 18 routes to raw",
			port:     0,
			protocol: 18,
			wantID:   "raw-18",
		},
		{
			name:     "unmatched routes to default",
			port:     9999,
			protocol: 99,
			wantID:   "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := primary.RouteIncoming(tt.port, tt.protocol)
			if id != tt.wantID {
				t.Errorf("RouteIncoming(%d, %d) = %q, want %q", tt.port, tt.protocol, id, tt.wantID)
			}
		})
	}
}

func TestPrimarySession_RouteIncoming_StreamingNotToRaw(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add only RAW default subsession
	_, _ = primary.AddSubsession("raw-default", StyleRaw, SubsessionOptions{ListenPort: 0, ListenProtocol: 0})

	// Streaming traffic (protocol 6) should not route to RAW
	id := primary.RouteIncoming(0, 6)
	if id != "" {
		t.Errorf("RouteIncoming(0, 6) = %q, want empty (streaming should not route to RAW)", id)
	}
}

func TestPrimarySession_RouteIncoming_NoMatch(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add only a specific port subsession
	_, _ = primary.AddSubsession("port-1234", StyleStream, SubsessionOptions{ListenPort: 1234})

	// Unmatched traffic with no default
	id := primary.RouteIncoming(9999, 0)
	if id != "" {
		t.Errorf("RouteIncoming(9999, 0) = %q, want empty (no match)", id)
	}
}

func TestPrimarySession_Close(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)

	// Add subsessions
	_, _ = primary.AddSubsession("sub1", StyleStream, SubsessionOptions{ListenPort: 1000})
	_, _ = primary.AddSubsession("sub2", StyleDatagram, SubsessionOptions{ListenPort: 2000})

	if primary.SubsessionCount() != 2 {
		t.Errorf("SubsessionCount() = %d, want 2", primary.SubsessionCount())
	}

	// Close primary
	if err := primary.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify status
	if primary.Status() != StatusClosed {
		t.Errorf("Status() = %v, want %v", primary.Status(), StatusClosed)
	}

	// Verify subsessions are cleared
	if primary.SubsessionCount() != 0 {
		t.Errorf("SubsessionCount() after close = %d, want 0", primary.SubsessionCount())
	}

	// Double close should be safe
	if err := primary.Close(); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestPrimarySession_ImplementsInterface(t *testing.T) {
	// Compile-time interface check
	var _ PrimarySession = (*PrimarySessionImpl)(nil)
}

func TestPrimarySession_DefaultSubsession(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add default subsession
	_, err := primary.AddSubsession("default", StyleStream, SubsessionOptions{
		ListenPort:     0,
		ListenProtocol: 0,
	})
	if err != nil {
		t.Fatalf("AddSubsession() error = %v", err)
	}

	// Verify default is set
	if primary.defaultSubsession != "default" {
		t.Errorf("defaultSubsession = %q, want %q", primary.defaultSubsession, "default")
	}

	// Remove it
	if err := primary.RemoveSubsession("default"); err != nil {
		t.Errorf("RemoveSubsession() error = %v", err)
	}

	// Verify default is cleared
	if primary.defaultSubsession != "" {
		t.Errorf("defaultSubsession after remove = %q, want empty", primary.defaultSubsession)
	}
}

func TestPrimarySession_WithForwarding(t *testing.T) {
	primary := NewPrimarySession("test-primary", nil, nil, nil)
	primary.SetStatus(StatusActive)
	defer primary.Close()

	// Add DATAGRAM subsession with forwarding
	opts := SubsessionOptions{
		ListenPort: 1234,
		Host:       "127.0.0.1",
		Port:       7655,
	}
	sub, err := primary.AddSubsession("dg-forward", StyleDatagram, opts)
	if err != nil {
		t.Fatalf("AddSubsession() error = %v", err)
	}

	// Verify forwarding is configured
	if dgSub, ok := sub.(*DatagramSessionImpl); ok {
		if !dgSub.IsForwarding() {
			t.Error("Expected forwarding to be enabled")
		}
	}
}

func TestSubsessionOptions_Defaults(t *testing.T) {
	opts := SubsessionOptions{}

	if opts.FromPort != 0 {
		t.Errorf("FromPort default = %d, want 0", opts.FromPort)
	}
	if opts.ToPort != 0 {
		t.Errorf("ToPort default = %d, want 0", opts.ToPort)
	}
	if opts.Protocol != 0 {
		t.Errorf("Protocol default = %d, want 0", opts.Protocol)
	}
	if opts.ListenPort != 0 {
		t.Errorf("ListenPort default = %d, want 0", opts.ListenPort)
	}
	if opts.ListenProtocol != 0 {
		t.Errorf("ListenProtocol default = %d, want 0", opts.ListenProtocol)
	}
	if opts.HeaderEnabled {
		t.Error("HeaderEnabled default should be false")
	}
}
