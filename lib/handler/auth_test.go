package handler

import (
	"errors"
	"sort"
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

// ListUsers returns a sorted slice of all registered usernames.
func (m *mockAuthManager) ListUsers() []string {
	users := make([]string, 0, len(m.users))
	for username := range m.users {
		users = append(users, username)
	}
	sort.Strings(users)
	return users
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
		{"AUTH", "LIST"},
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

func TestAuthHandler_List(t *testing.T) {
	tests := []struct {
		name        string
		setupUsers  map[string]string
		expectUsers string // Space-separated, sorted
	}{
		{
			name:        "empty user list",
			setupUsers:  map[string]string{},
			expectUsers: "",
		},
		{
			name:        "single user",
			setupUsers:  map[string]string{"alice": "pass1"},
			expectUsers: "alice",
		},
		{
			name:        "multiple users sorted",
			setupUsers:  map[string]string{"charlie": "pass3", "alice": "pass1", "bob": "pass2"},
			expectUsers: "alice bob charlie",
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
				Verb:    protocol.VerbAuth,
				Action:  protocol.ActionList,
				Options: make(map[string]string),
			}

			resp, err := handler.Handle(ctx, cmd)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			respStr := resp.String()

			// Check for OK result
			if !containsAll(respStr, "AUTH", "REPLY", "RESULT=OK") {
				t.Errorf("expected OK response, got: %s", respStr)
			}

			// Check for USERS field with expected value
			// Note: Values with spaces are quoted, single values are not
			if tt.expectUsers == "" {
				// Empty string should be USERS=
				if !containsAll(respStr, "USERS=") {
					t.Errorf("expected USERS= in response, got: %s", respStr)
				}
			} else if len(tt.setupUsers) == 1 {
				// Single user without spaces - no quotes
				expectedUsersField := "USERS=" + tt.expectUsers
				if !containsAll(respStr, expectedUsersField) {
					t.Errorf("expected %s in response, got: %s", expectedUsersField, respStr)
				}
			} else {
				// Multiple users with spaces - quoted
				expectedUsersField := "USERS=\"" + tt.expectUsers + "\""
				if !containsAll(respStr, expectedUsersField) {
					t.Errorf("expected %s in response, got: %s", expectedUsersField, respStr)
				}
			}
		})
	}
}

func TestAuthHandler_List_NoPasswordsExposed(t *testing.T) {
	manager := newMockAuthManager()
	manager.AddUser("testuser", "secretpassword")
	handler := NewAuthHandler(manager)
	ctx := NewContext(nil, nil)

	cmd := &protocol.Command{
		Verb:    protocol.VerbAuth,
		Action:  protocol.ActionList,
		Options: make(map[string]string),
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respStr := resp.String()

	// Verify password is not in response
	if containsAll(respStr, "secretpassword") {
		t.Errorf("password should not be exposed in AUTH LIST response: %s", respStr)
	}

	// Verify username IS in response
	if !containsAll(respStr, "testuser") {
		t.Errorf("username should be in AUTH LIST response: %s", respStr)
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
