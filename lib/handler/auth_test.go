package handler

import (
	"errors"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// mockAuthManager is a test implementation of AuthManager.
type mockAuthManager struct {
	enabled bool
	users   map[string]string
}

func newMockAuthManager() *mockAuthManager {
	return &mockAuthManager{
		enabled: false,
		users:   make(map[string]string),
	}
}

func (m *mockAuthManager) IsAuthEnabled() bool {
	return m.enabled
}

func (m *mockAuthManager) SetAuthEnabled(enabled bool) {
	m.enabled = enabled
}

func (m *mockAuthManager) AddUser(username, password string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}
	m.users[username] = password
	return nil
}

func (m *mockAuthManager) RemoveUser(username string) error {
	if _, exists := m.users[username]; !exists {
		return errors.New("user not found")
	}
	delete(m.users, username)
	return nil
}

func (m *mockAuthManager) HasUser(username string) bool {
	_, exists := m.users[username]
	return exists
}

func TestAuthHandler_Enable(t *testing.T) {
	manager := newMockAuthManager()
	handler := NewAuthHandler(manager)
	ctx := NewContext(nil, nil)

	// Initially disabled
	if manager.IsAuthEnabled() {
		t.Fatal("auth should be disabled initially")
	}

	// Send AUTH ENABLE
	cmd := &protocol.Command{
		Verb:    protocol.VerbAuth,
		Action:  protocol.ActionEnable,
		Options: make(map[string]string),
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Check response
	respStr := resp.String()
	if !containsAll(respStr, "AUTH", "REPLY", "RESULT=OK") {
		t.Errorf("unexpected response: %s", respStr)
	}

	// Verify auth is now enabled
	if !manager.IsAuthEnabled() {
		t.Error("auth should be enabled after AUTH ENABLE")
	}
}

func TestAuthHandler_Disable(t *testing.T) {
	manager := newMockAuthManager()
	manager.SetAuthEnabled(true) // Start with auth enabled
	handler := NewAuthHandler(manager)
	ctx := NewContext(nil, nil)

	// Send AUTH DISABLE
	cmd := &protocol.Command{
		Verb:    protocol.VerbAuth,
		Action:  protocol.ActionDisable,
		Options: make(map[string]string),
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check response
	respStr := resp.String()
	if !containsAll(respStr, "AUTH", "REPLY", "RESULT=OK") {
		t.Errorf("unexpected response: %s", respStr)
	}

	// Verify auth is now disabled
	if manager.IsAuthEnabled() {
		t.Error("auth should be disabled after AUTH DISABLE")
	}
}

func TestAuthHandler_AddUser(t *testing.T) {
	tests := []struct {
		name        string
		user        string
		password    string
		expectOK    bool
		expectError string
	}{
		{
			name:     "add new user",
			user:     "testuser",
			password: "testpass",
			expectOK: true,
		},
		{
			name:     "add user with empty password",
			user:     "testuser2",
			password: "",
			expectOK: true, // Empty password is allowed per SAM spec
		},
		{
			name:        "add user with empty username",
			user:        "",
			password:    "testpass",
			expectOK:    false,
			expectError: "USER is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newMockAuthManager()
			handler := NewAuthHandler(manager)
			ctx := NewContext(nil, nil)

			cmd := &protocol.Command{
				Verb:   protocol.VerbAuth,
				Action: protocol.ActionAdd,
				Options: map[string]string{
					"USER":     tt.user,
					"PASSWORD": tt.password,
				},
			}

			resp, err := handler.Handle(ctx, cmd)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			respStr := resp.String()

			if tt.expectOK {
				if !containsAll(respStr, "RESULT=OK") {
					t.Errorf("expected OK response, got: %s", respStr)
				}
				if !manager.HasUser(tt.user) {
					t.Errorf("user %q should exist after add", tt.user)
				}
			} else {
				if !containsAll(respStr, "RESULT=I2P_ERROR") {
					t.Errorf("expected I2P_ERROR response, got: %s", respStr)
				}
				if tt.expectError != "" && !containsAll(respStr, tt.expectError) {
					t.Errorf("expected error message %q, got: %s", tt.expectError, respStr)
				}
			}
		})
	}
}

func TestAuthHandler_AddUser_Update(t *testing.T) {
	manager := newMockAuthManager()
	handler := NewAuthHandler(manager)
	ctx := NewContext(nil, nil)

	// Add user first
	manager.AddUser("testuser", "oldpass")

	// Update password
	cmd := &protocol.Command{
		Verb:   protocol.VerbAuth,
		Action: protocol.ActionAdd,
		Options: map[string]string{
			"USER":     "testuser",
			"PASSWORD": "newpass",
		},
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respStr := resp.String()
	if !containsAll(respStr, "RESULT=OK") {
		t.Errorf("expected OK response, got: %s", respStr)
	}

	// Verify password was updated (user still exists)
	if !manager.HasUser("testuser") {
		t.Error("user should still exist after update")
	}
}

func TestAuthHandler_RemoveUser(t *testing.T) {
	tests := []struct {
		name        string
		setupUsers  map[string]string
		removeUser  string
		expectOK    bool
		expectError string
	}{
		{
			name:       "remove existing user",
			setupUsers: map[string]string{"testuser": "testpass"},
			removeUser: "testuser",
			expectOK:   true,
		},
		{
			name:        "remove nonexistent user",
			setupUsers:  map[string]string{},
			removeUser:  "nouser",
			expectOK:    false,
			expectError: "user not found",
		},
		{
			name:        "remove with empty username",
			setupUsers:  map[string]string{},
			removeUser:  "",
			expectOK:    false,
			expectError: "USER is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newMockAuthManager()
			for user, pass := range tt.setupUsers {
				manager.AddUser(user, pass)
			}
			handler := NewAuthHandler(manager)
			ctx := NewContext(nil, nil)

			cmd := &protocol.Command{
				Verb:   protocol.VerbAuth,
				Action: protocol.ActionRemove,
				Options: map[string]string{
					"USER": tt.removeUser,
				},
			}

			resp, err := handler.Handle(ctx, cmd)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			respStr := resp.String()

			if tt.expectOK {
				if !containsAll(respStr, "RESULT=OK") {
					t.Errorf("expected OK response, got: %s", respStr)
				}
				if manager.HasUser(tt.removeUser) {
					t.Errorf("user %q should not exist after remove", tt.removeUser)
				}
			} else {
				if !containsAll(respStr, "RESULT=I2P_ERROR") {
					t.Errorf("expected I2P_ERROR response, got: %s", respStr)
				}
				if tt.expectError != "" && !containsAll(respStr, tt.expectError) {
					t.Errorf("expected error message %q, got: %s", tt.expectError, respStr)
				}
			}
		})
	}
}

func TestAuthHandler_UnknownAction(t *testing.T) {
	manager := newMockAuthManager()
	handler := NewAuthHandler(manager)
	ctx := NewContext(nil, nil)

	cmd := &protocol.Command{
		Verb:    protocol.VerbAuth,
		Action:  "UNKNOWN",
		Options: make(map[string]string),
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respStr := resp.String()
	if !containsAll(respStr, "RESULT=I2P_ERROR", "unknown AUTH action") {
		t.Errorf("expected I2P_ERROR with unknown action message, got: %s", respStr)
	}
}

func TestAuthHandler_EmptyAction(t *testing.T) {
	manager := newMockAuthManager()
	handler := NewAuthHandler(manager)
	ctx := NewContext(nil, nil)

	cmd := &protocol.Command{
		Verb:    protocol.VerbAuth,
		Action:  "",
		Options: make(map[string]string),
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respStr := resp.String()
	if !containsAll(respStr, "RESULT=I2P_ERROR") {
		t.Errorf("expected I2P_ERROR for empty action, got: %s", respStr)
	}
}

func TestRegisterAuthHandlers(t *testing.T) {
	router := NewRouter()
	manager := newMockAuthManager()

	RegisterAuthHandlers(router, manager)

	// Verify handlers are registered for all AUTH actions
	tests := []struct {
		verb   string
		action string
	}{
		{"AUTH", "ENABLE"},
		{"AUTH", "DISABLE"},
		{"AUTH", "ADD"},
		{"AUTH", "REMOVE"},
		{"AUTH", ""}, // Catch-all
	}

	for _, tt := range tests {
		cmd := &protocol.Command{
			Verb:   tt.verb,
			Action: tt.action,
		}

		h := router.Route(cmd)
		if h == nil {
			t.Errorf("expected handler for AUTH %s, got nil", tt.action)
		}
	}
}

// Helper function to check if a string contains all substrings.
func containsAll(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if !containsString(s, sub) {
			return false
		}
	}
	return true
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsStringSearch(s, substr)))
}

func containsStringSearch(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
