package bridge

import (
	"sync"
	"testing"
)

func TestNewAuthStore(t *testing.T) {
	store := NewAuthStore()

	if store.IsAuthEnabled() {
		t.Error("new AuthStore should have auth disabled by default")
	}

	if store.UserCount() != 0 {
		t.Errorf("new AuthStore should have 0 users, got %d", store.UserCount())
	}
}

func TestNewAuthStoreFromConfig(t *testing.T) {
	cfg := AuthConfig{
		Required: true,
		Users: map[string]string{
			"user1": "pass1",
			"user2": "pass2",
		},
	}

	store := NewAuthStoreFromConfig(cfg)

	if !store.IsAuthEnabled() {
		t.Error("AuthStore should have auth enabled from config")
	}

	if store.UserCount() != 2 {
		t.Errorf("AuthStore should have 2 users, got %d", store.UserCount())
	}

	if !store.HasUser("user1") {
		t.Error("AuthStore should have user1")
	}

	if !store.HasUser("user2") {
		t.Error("AuthStore should have user2")
	}
}

func TestAuthStore_SetAuthEnabled(t *testing.T) {
	store := NewAuthStore()

	// Enable
	store.SetAuthEnabled(true)
	if !store.IsAuthEnabled() {
		t.Error("auth should be enabled")
	}

	// Disable
	store.SetAuthEnabled(false)
	if store.IsAuthEnabled() {
		t.Error("auth should be disabled")
	}
}

func TestAuthStore_AddUser(t *testing.T) {
	store := NewAuthStore()

	// Add new user
	err := store.AddUser("testuser", "testpass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !store.HasUser("testuser") {
		t.Error("user should exist after add")
	}

	if store.UserCount() != 1 {
		t.Errorf("expected 1 user, got %d", store.UserCount())
	}

	// Add another user
	err = store.AddUser("testuser2", "testpass2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.UserCount() != 2 {
		t.Errorf("expected 2 users, got %d", store.UserCount())
	}
}

func TestAuthStore_AddUser_EmptyUsername(t *testing.T) {
	store := NewAuthStore()

	err := store.AddUser("", "password")
	if err == nil {
		t.Error("expected error for empty username")
	}

	if err != ErrEmptyUsername {
		t.Errorf("expected ErrEmptyUsername, got: %v", err)
	}
}

func TestAuthStore_AddUser_EmptyPassword(t *testing.T) {
	store := NewAuthStore()

	// Empty password is allowed per SAM spec
	err := store.AddUser("testuser", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !store.HasUser("testuser") {
		t.Error("user should exist with empty password")
	}
}

func TestAuthStore_AddUser_Update(t *testing.T) {
	store := NewAuthStore()

	// Add user
	store.AddUser("testuser", "oldpass")
	if !store.CheckPassword("testuser", "oldpass") {
		t.Error("initial password should match")
	}

	// Update password
	store.AddUser("testuser", "newpass")
	if !store.CheckPassword("testuser", "newpass") {
		t.Error("updated password should match")
	}

	if store.CheckPassword("testuser", "oldpass") {
		t.Error("old password should no longer match")
	}

	// User count should remain 1
	if store.UserCount() != 1 {
		t.Errorf("expected 1 user, got %d", store.UserCount())
	}
}

func TestAuthStore_RemoveUser(t *testing.T) {
	store := NewAuthStore()
	store.AddUser("testuser", "testpass")

	err := store.RemoveUser("testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.HasUser("testuser") {
		t.Error("user should not exist after remove")
	}

	if store.UserCount() != 0 {
		t.Errorf("expected 0 users, got %d", store.UserCount())
	}
}

func TestAuthStore_RemoveUser_NotFound(t *testing.T) {
	store := NewAuthStore()

	err := store.RemoveUser("nouser")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}

	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got: %v", err)
	}
}

func TestAuthStore_HasUser(t *testing.T) {
	store := NewAuthStore()

	// Initially no users
	if store.HasUser("testuser") {
		t.Error("should not have user before add")
	}

	store.AddUser("testuser", "pass")

	if !store.HasUser("testuser") {
		t.Error("should have user after add")
	}

	store.RemoveUser("testuser")

	if store.HasUser("testuser") {
		t.Error("should not have user after remove")
	}
}

func TestAuthStore_CheckPassword(t *testing.T) {
	store := NewAuthStore()
	store.AddUser("testuser", "correctpass")

	tests := []struct {
		name     string
		username string
		password string
		expected bool
	}{
		{
			name:     "correct password",
			username: "testuser",
			password: "correctpass",
			expected: true,
		},
		{
			name:     "wrong password",
			username: "testuser",
			password: "wrongpass",
			expected: false,
		},
		{
			name:     "nonexistent user",
			username: "nouser",
			password: "anypass",
			expected: false,
		},
		{
			name:     "empty password when not empty",
			username: "testuser",
			password: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.CheckPassword(tt.username, tt.password)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAuthStore_CheckPassword_EmptyPassword(t *testing.T) {
	store := NewAuthStore()
	store.AddUser("testuser", "") // Empty password

	if !store.CheckPassword("testuser", "") {
		t.Error("empty password should match when set to empty")
	}

	if store.CheckPassword("testuser", "notEmpty") {
		t.Error("non-empty password should not match empty")
	}
}

func TestAuthStore_ToConfig(t *testing.T) {
	store := NewAuthStore()
	store.SetAuthEnabled(true)
	store.AddUser("user1", "pass1")
	store.AddUser("user2", "pass2")

	cfg := store.ToConfig()

	if !cfg.Required {
		t.Error("config Required should be true")
	}

	if len(cfg.Users) != 2 {
		t.Errorf("config should have 2 users, got %d", len(cfg.Users))
	}

	if cfg.Users["user1"] != "pass1" {
		t.Errorf("user1 password mismatch")
	}

	if cfg.Users["user2"] != "pass2" {
		t.Errorf("user2 password mismatch")
	}
}

func TestAuthStore_ToConfig_IndependentCopy(t *testing.T) {
	store := NewAuthStore()
	store.AddUser("user1", "pass1")

	cfg := store.ToConfig()

	// Modify the config
	cfg.Users["user1"] = "modified"
	cfg.Users["user2"] = "new"

	// Original store should be unchanged
	if !store.CheckPassword("user1", "pass1") {
		t.Error("original store should be unchanged")
	}

	if store.HasUser("user2") {
		t.Error("original store should not have user2")
	}
}

func TestAuthStore_Concurrent(t *testing.T) {
	store := NewAuthStore()
	var wg sync.WaitGroup

	// Concurrent enable/disable
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				store.SetAuthEnabled(true)
			} else {
				store.SetAuthEnabled(false)
			}
			_ = store.IsAuthEnabled()
		}(i)
	}

	// Concurrent user operations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			username := "user"
			if n%3 == 0 {
				store.AddUser(username, "pass")
			} else if n%3 == 1 {
				store.RemoveUser(username)
			} else {
				store.HasUser(username)
			}
		}(i)
	}

	wg.Wait()
	// If no race conditions, test passes
}

func TestAuthStore_ConcurrentReadWrite(t *testing.T) {
	store := NewAuthStore()
	store.AddUser("testuser", "testpass")

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Start readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					store.IsAuthEnabled()
					store.HasUser("testuser")
					store.CheckPassword("testuser", "testpass")
					store.UserCount()
				}
			}
		}()
	}

	// Start writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				select {
				case <-done:
					return
				default:
					store.SetAuthEnabled(j%2 == 0)
					store.AddUser("testuser", "pass")
				}
			}
		}(i)
	}

	// Let it run briefly
	close(done)
	wg.Wait()
}
