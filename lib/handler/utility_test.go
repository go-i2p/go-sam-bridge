package handler

import (
	"net"
	"strings"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// mockUtilitySession implements session.Session for utility tests.
type mockUtilitySession struct {
	id     string
	closed bool
}

func (m *mockUtilitySession) ID() string                        { return m.id }
func (m *mockUtilitySession) Style() session.Style              { return session.StyleStream }
func (m *mockUtilitySession) Destination() *session.Destination { return nil }
func (m *mockUtilitySession) Status() session.Status            { return session.StatusActive }
func (m *mockUtilitySession) Close() error                      { m.closed = true; return nil }
func (m *mockUtilitySession) ControlConn() net.Conn             { return nil }

func TestUtilityHandler_Handle_QUIT(t *testing.T) {
	handler := NewUtilityHandler()

	tests := []struct {
		name         string
		verb         string
		sendResponse bool
		hasSession   bool
	}{
		{"QUIT with response", "QUIT", true, false},
		{"STOP with response", "STOP", true, false},
		{"EXIT with response", "EXIT", true, false},
		{"QUIT without response", "QUIT", false, false},
		{"QUIT with session", "QUIT", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler.SendResponse = tt.sendResponse

			var ctx *Context
			var mockSess *mockUtilitySession

			if tt.hasSession {
				mockSess = &mockUtilitySession{id: "test-session"}
				ctx = &Context{Session: mockSess}
			} else {
				ctx = &Context{}
			}

			cmd := &protocol.Command{
				Verb: tt.verb,
				Raw:  tt.verb,
			}

			resp, err := handler.Handle(ctx, cmd)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if tt.sendResponse {
				if resp == nil {
					t.Fatal("Handle() returned nil response, want response")
				}
				if resp.Verb != "SESSION" {
					t.Errorf("response Verb = %q, want %q", resp.Verb, "SESSION")
				}
				if resp.Action != "STATUS" {
					t.Errorf("response Action = %q, want %q", resp.Action, "STATUS")
				}
				respStr := resp.String()
				if !strings.Contains(respStr, "RESULT=OK") {
					t.Errorf("response = %q, want RESULT=OK", respStr)
				}
			} else {
				if resp != nil {
					t.Errorf("Handle() returned response = %v, want nil", resp)
				}
			}

			if tt.hasSession && !mockSess.closed {
				t.Error("session was not closed")
			}
		})
	}
}

func TestUtilityHandler_NilContext(t *testing.T) {
	handler := NewUtilityHandler()
	cmd := &protocol.Command{
		Verb: "QUIT",
		Raw:  "QUIT",
	}

	// Should not panic with nil context
	resp, err := handler.Handle(nil, cmd)
	if err != nil {
		t.Fatalf("Handle() with nil context error = %v", err)
	}
	if resp == nil {
		t.Fatal("Handle() returned nil response")
	}
}

func TestRegisterUtilityHandlers(t *testing.T) {
	router := NewRouter()
	RegisterUtilityHandlers(router)

	// Verify all handlers are registered
	verbs := []string{"QUIT", "STOP", "EXIT"}
	for _, verb := range verbs {
		cmd := &protocol.Command{Verb: verb}
		h := router.Route(cmd)
		if h == nil {
			t.Errorf("%s handler not registered", verb)
		}
	}
}

func TestHelpHandler_Handle(t *testing.T) {
	handler := NewHelpHandler()
	cmd := &protocol.Command{
		Verb: "HELP",
		Raw:  "HELP",
	}

	resp, err := handler.Handle(nil, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if resp == nil {
		t.Fatal("Handle() returned nil response")
	}
	if resp.Verb != "HELP" {
		t.Errorf("response Verb = %q, want %q", resp.Verb, "HELP")
	}
	if resp.Action != "REPLY" {
		t.Errorf("response Action = %q, want %q", resp.Action, "REPLY")
	}

	respStr := resp.String()
	if !strings.Contains(respStr, "RESULT=OK") {
		t.Errorf("response = %q, want RESULT=OK", respStr)
	}
	if !strings.Contains(respStr, "SAM") {
		t.Errorf("response = %q, want to contain SAM", respStr)
	}

	// Verify all implemented commands are listed in the help response
	expectedCommands := []string{
		"HELLO VERSION",
		"DEST GENERATE",
		"SESSION CREATE",
		"SESSION ADD",
		"SESSION REMOVE",
		"STREAM CONNECT",
		"STREAM ACCEPT",
		"STREAM FORWARD",
		"DATAGRAM SEND",
		"RAW SEND",
		"NAMING LOOKUP",
		"PING",
		"PONG",
		"AUTH ADD",
		"AUTH REMOVE",
		"AUTH ENABLE",
		"AUTH DISABLE",
		"QUIT",
		"STOP",
		"EXIT",
		"HELP",
	}

	for _, cmd := range expectedCommands {
		if !strings.Contains(respStr, cmd) {
			t.Errorf("response missing command %q in %q", cmd, respStr)
		}
	}
}

// TestSamCommandsCompleteness verifies that the samCommands slice contains all expected commands.
func TestSamCommandsCompleteness(t *testing.T) {
	expectedCommands := []string{
		"HELLO VERSION",
		"DEST GENERATE",
		"SESSION CREATE",
		"SESSION ADD",
		"SESSION REMOVE",
		"STREAM CONNECT",
		"STREAM ACCEPT",
		"STREAM FORWARD",
		"DATAGRAM SEND",
		"RAW SEND",
		"NAMING LOOKUP",
		"PING",
		"PONG",
		"AUTH ADD",
		"AUTH REMOVE",
		"AUTH ENABLE",
		"AUTH DISABLE",
		"QUIT",
		"STOP",
		"EXIT",
		"HELP",
	}

	// Check samCommands contains all expected commands
	for _, expected := range expectedCommands {
		found := false
		for _, actual := range samCommands {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("samCommands missing command %q", expected)
		}
	}

	// Check samCommands has the expected length
	if len(samCommands) != len(expectedCommands) {
		t.Errorf("samCommands has %d commands, want %d", len(samCommands), len(expectedCommands))
	}
}

func TestRegisterHelpHandler(t *testing.T) {
	router := NewRouter()
	RegisterHelpHandler(router)

	cmd := &protocol.Command{Verb: "HELP"}
	h := router.Route(cmd)
	if h == nil {
		t.Error("HELP handler not registered")
	}
}
