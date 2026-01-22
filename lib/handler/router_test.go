package handler

import (
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

func TestNewRouter(t *testing.T) {
	r := NewRouter()

	if r == nil {
		t.Fatal("NewRouter returned nil")
	}
	if !r.CaseInsensitive {
		t.Error("CaseInsensitive should be true by default")
	}
	if r.handlers == nil {
		t.Error("handlers map should be initialized")
	}
	if r.Count() != 0 {
		t.Error("Count should be 0 initially")
	}
}

func TestRouter_Register(t *testing.T) {
	r := NewRouter()

	handler := HandlerFunc(func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return nil, nil
	})

	r.Register("HELLO VERSION", handler)

	if !r.HasHandler("HELLO VERSION") {
		t.Error("Handler not registered")
	}
	if r.Count() != 1 {
		t.Errorf("Count = %d, want 1", r.Count())
	}
}

func TestRouter_RegisterFunc(t *testing.T) {
	r := NewRouter()

	called := false
	r.RegisterFunc("TEST", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		called = true
		return nil, nil
	})

	if !r.HasHandler("TEST") {
		t.Error("Handler not registered via RegisterFunc")
	}

	// Verify it works
	handler := r.Route(&protocol.Command{Verb: "TEST"})
	if handler == nil {
		t.Fatal("Route returned nil")
	}
	_, _ = handler.Handle(nil, nil)
	if !called {
		t.Error("Handler was not called")
	}
}

func TestRouter_CaseInsensitive(t *testing.T) {
	r := NewRouter()
	r.CaseInsensitive = true

	r.RegisterFunc("HELLO VERSION", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("HELLO").WithAction("REPLY").WithResult("OK"), nil
	})

	tests := []struct {
		name   string
		verb   string
		action string
		found  bool
	}{
		{"uppercase", "HELLO", "VERSION", true},
		{"lowercase", "hello", "version", true},
		{"mixed case", "Hello", "Version", true},
		{"verb lowercase", "hello", "VERSION", true},
		{"wrong verb", "HI", "VERSION", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &protocol.Command{Verb: tt.verb, Action: tt.action}
			handler := r.Route(cmd)
			if tt.found && handler == nil {
				t.Error("Expected handler to be found")
			}
			if !tt.found && handler != nil {
				t.Error("Expected handler to NOT be found")
			}
		})
	}
}

func TestRouter_CaseSensitive(t *testing.T) {
	r := NewRouter()
	r.CaseInsensitive = false

	r.RegisterFunc("HELLO VERSION", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return nil, nil
	})

	tests := []struct {
		name   string
		verb   string
		action string
		found  bool
	}{
		{"uppercase", "HELLO", "VERSION", true},
		{"lowercase", "hello", "version", false},
		{"mixed case", "Hello", "Version", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &protocol.Command{Verb: tt.verb, Action: tt.action}
			handler := r.Route(cmd)
			if tt.found && handler == nil {
				t.Error("Expected handler to be found")
			}
			if !tt.found && handler != nil {
				t.Error("Expected handler to NOT be found")
			}
		})
	}
}

func TestRouter_Route_Priority(t *testing.T) {
	r := NewRouter()

	// Register both verb-only and verb+action handlers
	verbOnlyCalled := false
	verbActionCalled := false

	r.RegisterFunc("SESSION", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		verbOnlyCalled = true
		return nil, nil
	})

	r.RegisterFunc("SESSION CREATE", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		verbActionCalled = true
		return nil, nil
	})

	// "SESSION CREATE" should match the specific handler
	cmd := &protocol.Command{Verb: "SESSION", Action: "CREATE"}
	handler := r.Route(cmd)
	if handler == nil {
		t.Fatal("Route returned nil")
	}
	_, _ = handler.Handle(nil, nil)

	if !verbActionCalled {
		t.Error("VERB ACTION handler should have been called")
	}
	if verbOnlyCalled {
		t.Error("VERB only handler should NOT have been called")
	}

	// Reset
	verbOnlyCalled = false
	verbActionCalled = false

	// "SESSION ADD" should fall back to verb-only handler
	cmd = &protocol.Command{Verb: "SESSION", Action: "ADD"}
	handler = r.Route(cmd)
	if handler == nil {
		t.Fatal("Route returned nil")
	}
	_, _ = handler.Handle(nil, nil)

	if !verbOnlyCalled {
		t.Error("VERB only handler should have been called")
	}
	if verbActionCalled {
		t.Error("VERB ACTION handler should NOT have been called")
	}
}

func TestRouter_Route_VerbOnly(t *testing.T) {
	r := NewRouter()

	r.RegisterFunc("PING", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return protocol.NewResponse("PONG"), nil
	})

	// PING without action
	cmd := &protocol.Command{Verb: "PING", Action: ""}
	handler := r.Route(cmd)
	if handler == nil {
		t.Error("Expected to find PING handler")
	}

	// PING with arbitrary action (per SAM 3.2, PING echoes text)
	cmd = &protocol.Command{Verb: "PING", Action: "hello world"}
	handler = r.Route(cmd)
	if handler == nil {
		t.Error("Expected to find PING handler even with action")
	}
}

func TestRouter_Route_UnknownHandler(t *testing.T) {
	r := NewRouter()

	unknownCalled := false
	r.UnknownHandler = HandlerFunc(func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		unknownCalled = true
		return protocol.NewResponse("ERROR").WithResult("UNKNOWN"), nil
	})

	cmd := &protocol.Command{Verb: "UNKNOWN", Action: "COMMAND"}
	handler := r.Route(cmd)

	if handler == nil {
		t.Fatal("Expected UnknownHandler to be returned")
	}

	_, _ = handler.Handle(nil, cmd)
	if !unknownCalled {
		t.Error("UnknownHandler was not called")
	}
}

func TestRouter_Route_NoHandler(t *testing.T) {
	r := NewRouter()

	cmd := &protocol.Command{Verb: "UNKNOWN", Action: "COMMAND"}
	handler := r.Route(cmd)

	if handler != nil {
		t.Error("Expected nil when no handler registered and no UnknownHandler")
	}
}

func TestRouter_Handle_Unknown(t *testing.T) {
	r := NewRouter()

	cmd := &protocol.Command{Verb: "UNKNOWN", Action: "COMMAND"}
	resp, err := r.Handle(nil, cmd)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response for unknown command")
	}

	respStr := resp.String()
	if respStr == "" {
		t.Error("Response string is empty")
	}
	// Should contain I2P_ERROR
	if !contains(respStr, "I2P_ERROR") {
		t.Errorf("Expected I2P_ERROR in response: %s", respStr)
	}
}

func TestRouter_Handle_EmptyVerb(t *testing.T) {
	r := NewRouter()

	cmd := &protocol.Command{Verb: "", Action: ""}
	resp, err := r.Handle(nil, cmd)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response for empty command")
	}

	respStr := resp.String()
	// With empty verb, should use "ERROR" as the verb
	if !contains(respStr, "ERROR") {
		t.Errorf("Expected ERROR in response for empty verb: %s", respStr)
	}
}

func TestRouter_Keys(t *testing.T) {
	r := NewRouter()

	r.RegisterFunc("HELLO VERSION", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return nil, nil
	})
	r.RegisterFunc("SESSION CREATE", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return nil, nil
	})
	r.RegisterFunc("PING", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return nil, nil
	})

	keys := r.Keys()
	if len(keys) != 3 {
		t.Errorf("Keys() returned %d keys, want 3", len(keys))
	}

	// Verify all keys are present (order may vary)
	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}

	expected := []string{"HELLO VERSION", "SESSION CREATE", "PING"}
	for _, k := range expected {
		if !keyMap[k] {
			t.Errorf("Key %q not found in Keys()", k)
		}
	}
}

func TestRouter_HasHandler(t *testing.T) {
	r := NewRouter()

	r.RegisterFunc("TEST", func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
		return nil, nil
	})

	tests := []struct {
		key      string
		expected bool
	}{
		{"TEST", true},
		{"test", true}, // Case insensitive
		{"Test", true},
		{"UNKNOWN", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := r.HasHandler(tt.key); got != tt.expected {
				t.Errorf("HasHandler(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}

// contains checks if substr is in s
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
