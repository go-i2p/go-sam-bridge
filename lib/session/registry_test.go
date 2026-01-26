package session

import (
	"sync"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// testSession implements Session interface for testing registry.
type testSession struct {
	*BaseSession
}

func newTestSession(id string, dest *Destination) *testSession {
	return &testSession{
		BaseSession: NewBaseSession(id, StyleStream, dest, nil, nil),
	}
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	if r == nil {
		t.Fatal("NewRegistry() returned nil")
	}
	if r.Count() != 0 {
		t.Errorf("Count() = %d, want 0", r.Count())
	}
	if len(r.All()) != 0 {
		t.Errorf("All() len = %d, want 0", len(r.All()))
	}
}

func TestRegistry_Register(t *testing.T) {
	t.Run("register valid session", func(t *testing.T) {
		r := NewRegistry()
		dest := &Destination{PublicKey: []byte("dest1")}
		s := newTestSession("session1", dest)

		err := r.Register(s)
		if err != nil {
			t.Errorf("Register() returned error: %v", err)
		}
		if r.Count() != 1 {
			t.Errorf("Count() = %d, want 1", r.Count())
		}
	})

	t.Run("register nil session", func(t *testing.T) {
		r := NewRegistry()

		err := r.Register(nil)
		if err != util.ErrSessionNotFound {
			t.Errorf("Register(nil) = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("register session with empty ID", func(t *testing.T) {
		r := NewRegistry()
		s := newTestSession("", nil)

		err := r.Register(s)
		if err != util.ErrSessionNotFound {
			t.Errorf("Register(empty ID) = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("register duplicate ID", func(t *testing.T) {
		r := NewRegistry()
		s1 := newTestSession("session1", nil)
		s2 := newTestSession("session1", nil)

		_ = r.Register(s1)
		err := r.Register(s2)
		if err != util.ErrDuplicateID {
			t.Errorf("Register(duplicate ID) = %v, want ErrDuplicateID", err)
		}
	})

	t.Run("register duplicate destination", func(t *testing.T) {
		r := NewRegistry()
		dest := &Destination{PublicKey: []byte("same-dest")}
		s1 := newTestSession("session1", dest)
		s2 := newTestSession("session2", dest)

		_ = r.Register(s1)
		err := r.Register(s2)
		if err != util.ErrDuplicateDest {
			t.Errorf("Register(duplicate dest) = %v, want ErrDuplicateDest", err)
		}
	})

	t.Run("register session without destination", func(t *testing.T) {
		r := NewRegistry()
		s := newTestSession("session1", nil)

		err := r.Register(s)
		if err != nil {
			t.Errorf("Register(nil dest) = %v, want nil", err)
		}
		if r.Count() != 1 {
			t.Errorf("Count() = %d, want 1", r.Count())
		}
	})

	t.Run("register sessions with different destinations", func(t *testing.T) {
		r := NewRegistry()
		dest1 := &Destination{PublicKey: []byte("dest1")}
		dest2 := &Destination{PublicKey: []byte("dest2")}
		s1 := newTestSession("session1", dest1)
		s2 := newTestSession("session2", dest2)

		if err := r.Register(s1); err != nil {
			t.Errorf("Register(s1) = %v, want nil", err)
		}
		if err := r.Register(s2); err != nil {
			t.Errorf("Register(s2) = %v, want nil", err)
		}
		if r.Count() != 2 {
			t.Errorf("Count() = %d, want 2", r.Count())
		}
	})
}

func TestRegistry_Unregister(t *testing.T) {
	t.Run("unregister existing session", func(t *testing.T) {
		r := NewRegistry()
		dest := &Destination{PublicKey: []byte("dest1")}
		s := newTestSession("session1", dest)
		_ = r.Register(s)

		err := r.Unregister("session1")
		if err != nil {
			t.Errorf("Unregister() = %v, want nil", err)
		}
		if r.Count() != 0 {
			t.Errorf("Count() = %d, want 0", r.Count())
		}
	})

	t.Run("unregister removes destination mapping", func(t *testing.T) {
		r := NewRegistry()
		dest := &Destination{PublicKey: []byte("dest1")}
		s := newTestSession("session1", dest)
		_ = r.Register(s)

		_ = r.Unregister("session1")

		// Should be able to register same destination again
		s2 := newTestSession("session2", dest)
		err := r.Register(s2)
		if err != nil {
			t.Errorf("Register after unregister = %v, want nil", err)
		}
	})

	t.Run("unregister non-existent session", func(t *testing.T) {
		r := NewRegistry()

		err := r.Unregister("nonexistent")
		if err != util.ErrSessionNotFound {
			t.Errorf("Unregister(nonexistent) = %v, want ErrSessionNotFound", err)
		}
	})
}

func TestRegistry_Get(t *testing.T) {
	t.Run("get existing session", func(t *testing.T) {
		r := NewRegistry()
		s := newTestSession("session1", nil)
		_ = r.Register(s)

		got := r.Get("session1")
		if got != s {
			t.Error("Get() should return registered session")
		}
	})

	t.Run("get non-existent session", func(t *testing.T) {
		r := NewRegistry()

		got := r.Get("nonexistent")
		if got != nil {
			t.Error("Get(nonexistent) should return nil")
		}
	})
}

func TestRegistry_GetByDestination(t *testing.T) {
	t.Run("get by existing destination", func(t *testing.T) {
		r := NewRegistry()
		dest := &Destination{PublicKey: []byte("dest1")}
		s := newTestSession("session1", dest)
		_ = r.Register(s)

		got := r.GetByDestination(dest.Hash())
		if got != s {
			t.Error("GetByDestination() should return registered session")
		}
	})

	t.Run("get by non-existent destination", func(t *testing.T) {
		r := NewRegistry()

		got := r.GetByDestination("nonexistent")
		if got != nil {
			t.Error("GetByDestination(nonexistent) should return nil")
		}
	})
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()
	s1 := newTestSession("session1", nil)
	s2 := newTestSession("session2", nil)
	s3 := newTestSession("session3", nil)

	_ = r.Register(s1)
	_ = r.Register(s2)
	_ = r.Register(s3)

	all := r.All()
	if len(all) != 3 {
		t.Errorf("All() len = %d, want 3", len(all))
	}

	// Check all IDs are present
	idMap := make(map[string]bool)
	for _, id := range all {
		idMap[id] = true
	}
	if !idMap["session1"] || !idMap["session2"] || !idMap["session3"] {
		t.Error("All() should contain all registered session IDs")
	}
}

func TestRegistry_Count(t *testing.T) {
	r := NewRegistry()

	if r.Count() != 0 {
		t.Errorf("initial Count() = %d, want 0", r.Count())
	}

	_ = r.Register(newTestSession("s1", nil))
	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1", r.Count())
	}

	_ = r.Register(newTestSession("s2", nil))
	if r.Count() != 2 {
		t.Errorf("Count() = %d, want 2", r.Count())
	}

	_ = r.Unregister("s1")
	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1", r.Count())
	}
}

func TestRegistry_Close(t *testing.T) {
	t.Run("basic close", func(t *testing.T) {
		r := NewRegistry()
		conn := &mockConn{}
		s := &testSession{
			BaseSession: NewBaseSession("session1", StyleStream, nil, conn, nil),
		}
		_ = r.Register(s)

		err := r.Close()
		if err != nil {
			t.Errorf("Close() = %v, want nil", err)
		}
		if r.Count() != 0 {
			t.Errorf("Count() after Close() = %d, want 0", r.Count())
		}
		if !conn.isClosed() {
			t.Error("Session connection should be closed")
		}
	})

	t.Run("close multiple sessions", func(t *testing.T) {
		r := NewRegistry()
		conns := make([]*mockConn, 5)
		for i := 0; i < 5; i++ {
			conns[i] = &mockConn{}
			s := &testSession{
				BaseSession: NewBaseSession("session"+string(rune('0'+i)), StyleStream, nil, conns[i], nil),
			}
			_ = r.Register(s)
		}

		err := r.Close()
		if err != nil {
			t.Errorf("Close() = %v, want nil", err)
		}
		if r.Count() != 0 {
			t.Errorf("Count() after Close() = %d, want 0", r.Count())
		}
		for i, conn := range conns {
			if !conn.isClosed() {
				t.Errorf("Session %d connection should be closed", i)
			}
		}
	})

	t.Run("close is safe after registry cleared", func(t *testing.T) {
		// This test verifies that sessions can safely call Unregister
		// during Close() without deadlock, since we release the lock first.
		r := NewRegistry()
		s := newTestSession("session1", nil)
		_ = r.Register(s)

		// Close clears the registry first, so subsequent Unregister calls
		// should find nothing and return harmlessly
		err := r.Close()
		if err != nil {
			t.Errorf("Close() = %v, want nil", err)
		}

		// This should not panic or deadlock
		err = r.Unregister("session1")
		if err != nil {
			// Session was already removed during Close, so this is expected
			// to return ErrSessionNotFound
			if err != util.ErrSessionNotFound {
				t.Errorf("Unregister after Close() = %v, want nil or ErrSessionNotFound", err)
			}
		}
	})

	t.Run("close empty registry", func(t *testing.T) {
		r := NewRegistry()
		err := r.Close()
		if err != nil {
			t.Errorf("Close() empty registry = %v, want nil", err)
		}
	})
}

func TestRegistry_Has(t *testing.T) {
	r := NewRegistry()
	s := newTestSession("session1", nil)
	_ = r.Register(s)

	if !r.Has("session1") {
		t.Error("Has(session1) = false, want true")
	}
	if r.Has("nonexistent") {
		t.Error("Has(nonexistent) = true, want false")
	}
}

func TestRegistry_HasDestination(t *testing.T) {
	r := NewRegistry()
	dest := &Destination{PublicKey: []byte("dest1")}
	s := newTestSession("session1", dest)
	_ = r.Register(s)

	if !r.HasDestination(dest.Hash()) {
		t.Error("HasDestination(dest1) = false, want true")
	}
	if r.HasDestination("nonexistent") {
		t.Error("HasDestination(nonexistent) = true, want false")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	iterations := 100

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sessionID := "session" + string(rune(id*1000+j))
				s := newTestSession(sessionID, nil)
				_ = r.Register(s)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = r.Count()
				_ = r.All()
				_ = r.Get("session0")
			}
		}()
	}

	// Concurrent unregistrations
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sessionID := "session" + string(rune(id*1000+j))
				_ = r.Unregister(sessionID)
			}
		}(i)
	}

	wg.Wait()
}

// Verify Registry implements the Registry interface
var _ Registry = (*RegistryImpl)(nil)
