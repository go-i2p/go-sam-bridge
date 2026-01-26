// Package handler implements SAM command handlers per SAMv3.md specification.
package handler

import (
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// AuthManager provides an interface for managing authentication configuration.
// This abstraction allows the AUTH handler to modify server auth settings
// without depending on the concrete bridge.Config type.
//
// Per SAM 3.2, AUTH commands allow runtime configuration of authentication.
type AuthManager interface {
	// IsAuthEnabled returns true if authentication is currently required.
	IsAuthEnabled() bool

	// SetAuthEnabled enables or disables authentication requirement.
	// When enabled, subsequent connections must provide USER/PASSWORD in HELLO.
	SetAuthEnabled(enabled bool)

	// AddUser adds or updates a user with the given password.
	// Returns an error if the username is empty or invalid.
	AddUser(username, password string) error

	// RemoveUser removes a user from the authentication store.
	// Returns an error if the user does not exist.
	RemoveUser(username string) error

	// HasUser returns true if the username exists.
	HasUser(username string) bool

	// ListUsers returns a sorted slice of all registered usernames.
	// Per Java I2P reference implementation, this supports AUTH LIST command.
	ListUsers() []string
}

// AuthHandler handles AUTH commands per SAM 3.2.
// These commands configure authentication without requiring a session.
//
// Supported commands:
//   - AUTH ENABLE — Enable authentication on subsequent connections
//   - AUTH DISABLE — Disable authentication on subsequent connections
//   - AUTH ADD USER="xxx" PASSWORD="yyy" — Add or update a user
//   - AUTH REMOVE USER="xxx" — Remove a user
//
// Per SAMv3.md: "AUTH does not require that a session has been created first."
type AuthHandler struct {
	manager AuthManager
}

// NewAuthHandler creates a new AUTH handler with the given auth manager.
func NewAuthHandler(manager AuthManager) *AuthHandler {
	return &AuthHandler{manager: manager}
}

// Handle processes an AUTH command.
// Routes to the appropriate handler based on the action.
func (h *AuthHandler) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	switch cmd.Action {
	case protocol.ActionEnable:
		return h.handleEnable(ctx, cmd)
	case protocol.ActionDisable:
		return h.handleDisable(ctx, cmd)
	case protocol.ActionAdd:
		return h.handleAdd(ctx, cmd)
	case protocol.ActionRemove:
		return h.handleRemove(ctx, cmd)
	case protocol.ActionList:
		return h.handleList(ctx, cmd)
	default:
		return authError("unknown AUTH action: " + cmd.Action), nil
	}
}

// handleEnable processes AUTH ENABLE command.
// Enables authentication on subsequent connections.
func (h *AuthHandler) handleEnable(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	h.manager.SetAuthEnabled(true)
	return authOK(), nil
}

// handleDisable processes AUTH DISABLE command.
// Disables authentication on subsequent connections.
func (h *AuthHandler) handleDisable(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	h.manager.SetAuthEnabled(false)
	return authOK(), nil
}

// handleAdd processes AUTH ADD command.
// Adds or updates a user with the given credentials.
//
// Format: AUTH ADD USER="xxx" PASSWORD="yyy"
// Per SAM spec: Double quotes are recommended but not required.
func (h *AuthHandler) handleAdd(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	user := cmd.Get("USER")
	password := cmd.Get("PASSWORD")

	if user == "" {
		return authError("USER is required"), nil
	}

	if err := h.manager.AddUser(user, password); err != nil {
		return authError(err.Error()), nil
	}

	return authOK(), nil
}

// handleRemove processes AUTH REMOVE command.
// Removes a user from the authentication store.
//
// Format: AUTH REMOVE USER="xxx"
func (h *AuthHandler) handleRemove(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	user := cmd.Get("USER")

	if user == "" {
		return authError("USER is required"), nil
	}

	if err := h.manager.RemoveUser(user); err != nil {
		return authError(err.Error()), nil
	}

	return authOK(), nil
}

// handleList processes AUTH LIST command.
// Returns a list of configured usernames.
//
// Format: AUTH LIST
// Response: AUTH REPLY RESULT=OK USERS="user1 user2 user3"
//
// Per Java I2P reference implementation, this allows administrators
// to view configured users. Passwords are never returned.
func (h *AuthHandler) handleList(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	users := h.manager.ListUsers()

	// Build space-separated user list
	userList := ""
	for i, user := range users {
		if i > 0 {
			userList += " "
		}
		userList += user
	}

	return protocol.NewResponse(protocol.VerbAuth).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultOK).
		WithOption("USERS", userList), nil
}

// authOK builds a successful AUTH response.
func authOK() *protocol.Response {
	return protocol.NewResponse(protocol.VerbAuth).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultOK)
}

// authError builds an error AUTH response.
// Per SAM spec: "On failure the server will reply with an I2P_ERROR and a message."
func authError(message string) *protocol.Response {
	return protocol.NewResponse(protocol.VerbAuth).
		WithAction(protocol.ActionReply).
		WithResult(protocol.ResultI2PError).
		WithMessage(message)
}

// RegisterAuthHandlers registers the AUTH handler with a router.
// All AUTH actions (ENABLE, DISABLE, ADD, REMOVE, LIST) use the same handler.
func RegisterAuthHandlers(router *Router, manager AuthManager) {
	handler := NewAuthHandler(manager)
	router.Register("AUTH ENABLE", handler)
	router.Register("AUTH DISABLE", handler)
	router.Register("AUTH ADD", handler)
	router.Register("AUTH REMOVE", handler)
	router.Register("AUTH LIST", handler)
	// Also register a catch-all for unknown AUTH actions
	router.Register("AUTH", handler)
}
