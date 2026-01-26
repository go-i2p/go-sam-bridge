package bridge

import (
	"errors"
	"sort"
	"sync"
)

// ErrUserNotFound is returned when attempting to remove a non-existent user.
var ErrUserNotFound = errors.New("user not found")

// ErrEmptyUsername is returned when attempting to add a user with an empty username.
var ErrEmptyUsername = errors.New("username cannot be empty")

// AuthStore provides thread-safe authentication management.
// It implements the handler.AuthManager interface to allow AUTH commands
// to modify authentication configuration at runtime.
//
// Per SAM 3.2, AUTH commands allow runtime configuration of authentication
// on subsequent connections. This store manages the credential database
// and auth requirement flag.
type AuthStore struct {
	mu      sync.RWMutex
	enabled bool
	users   map[string]string
}

// NewAuthStore creates a new authentication store.
// By default, authentication is disabled and no users are configured.
func NewAuthStore() *AuthStore {
	return &AuthStore{
		enabled: false,
		users:   make(map[string]string),
	}
}

// NewAuthStoreFromConfig creates an AuthStore initialized from an AuthConfig.
// This allows the bridge server to use existing configuration.
func NewAuthStoreFromConfig(cfg AuthConfig) *AuthStore {
	users := make(map[string]string)
	for k, v := range cfg.Users {
		users[k] = v
	}
	return &AuthStore{
		enabled: cfg.Required,
		users:   users,
	}
}

// IsAuthEnabled returns true if authentication is currently required.
// Implements handler.AuthManager interface.
func (s *AuthStore) IsAuthEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// SetAuthEnabled enables or disables authentication requirement.
// When enabled, subsequent connections must provide USER/PASSWORD in HELLO.
// Implements handler.AuthManager interface.
func (s *AuthStore) SetAuthEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

// AddUser adds or updates a user with the given password.
// Returns ErrEmptyUsername if the username is empty.
// Implements handler.AuthManager interface.
func (s *AuthStore) AddUser(username, password string) error {
	if username == "" {
		return ErrEmptyUsername
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = password
	return nil
}

// RemoveUser removes a user from the authentication store.
// Returns ErrUserNotFound if the user does not exist.
// Implements handler.AuthManager interface.
func (s *AuthStore) RemoveUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; !exists {
		return ErrUserNotFound
	}

	delete(s.users, username)
	return nil
}

// HasUser returns true if the username exists.
// Implements handler.AuthManager interface.
func (s *AuthStore) HasUser(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.users[username]
	return exists
}

// ListUsers returns a sorted slice of all registered usernames.
// Implements handler.AuthManager interface.
// Per Java I2P reference implementation, this supports AUTH LIST command.
// Passwords are never exposed through this method.
func (s *AuthStore) ListUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]string, 0, len(s.users))
	for username := range s.users {
		users = append(users, username)
	}

	// Sort for consistent output and easier testing
	sort.Strings(users)
	return users
}

// CheckPassword verifies the password for a user.
// Returns true if the user exists and the password matches.
// This method is used by the HELLO handler for authentication.
func (s *AuthStore) CheckPassword(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	storedPassword, ok := s.users[username]
	return ok && storedPassword == password
}

// UserCount returns the number of registered users.
func (s *AuthStore) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// ToConfig exports the current authentication state as an AuthConfig.
// This can be used for persistence or configuration snapshot.
func (s *AuthStore) ToConfig() AuthConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make(map[string]string)
	for k, v := range s.users {
		users[k] = v
	}

	return AuthConfig{
		Required: s.enabled,
		Users:    users,
	}
}
