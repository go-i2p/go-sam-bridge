package handler

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/go-i2p/go-sam-bridge/lib/util"
)

// mockStreamConnector implements StreamConnector for testing.
type mockStreamConnector struct {
	conn    net.Conn
	err     error
	lastReq *connectRequest
}

type connectRequest struct {
	sess     session.Session
	dest     string
	fromPort int
	toPort   int
}

func (m *mockStreamConnector) Connect(sess session.Session, dest string, fromPort, toPort int) (net.Conn, error) {
	m.lastReq = &connectRequest{sess: sess, dest: dest, fromPort: fromPort, toPort: toPort}
	return m.conn, m.err
}

// mockStreamAcceptor implements StreamAcceptor for testing.
type mockStreamAcceptor struct {
	conn net.Conn
	info *AcceptInfo
	err  error
}

func (m *mockStreamAcceptor) Accept(sess session.Session) (net.Conn, *AcceptInfo, error) {
	return m.conn, m.info, m.err
}

// mockStreamForwarder implements StreamForwarder for testing.
type mockStreamForwarder struct {
	listener net.Listener
	err      error
	lastReq  *forwardRequest
}

type forwardRequest struct {
	sess session.Session
	host string
	port int
	ssl  bool
}

func (m *mockStreamForwarder) Forward(sess session.Session, host string, port int, ssl bool) (net.Listener, error) {
	m.lastReq = &forwardRequest{sess: sess, host: host, port: port, ssl: ssl}
	return m.listener, m.err
}

// mockListener implements net.Listener for testing.
type mockListener struct {
	addr net.Addr
}

func (m *mockListener) Accept() (net.Conn, error) { return nil, nil }
func (m *mockListener) Close() error              { return nil }
func (m *mockListener) Addr() net.Addr            { return m.addr }

// mockStreamSession implements a minimal session for stream testing.
type mockStreamSession struct {
	id    string
	style session.Style
	conn  net.Conn
}

func (m *mockStreamSession) ID() string                        { return m.id }
func (m *mockStreamSession) Style() session.Style              { return m.style }
func (m *mockStreamSession) Destination() *session.Destination { return nil }
func (m *mockStreamSession) Status() session.Status            { return session.StatusActive }
func (m *mockStreamSession) Close() error                      { return nil }
func (m *mockStreamSession) ControlConn() net.Conn             { return m.conn }

// mockStreamRegistry implements session.Registry for testing.
type mockStreamRegistry struct {
	sessions map[string]session.Session
	dests    map[string]string
}

func newMockStreamRegistry() *mockStreamRegistry {
	return &mockStreamRegistry{
		sessions: make(map[string]session.Session),
		dests:    make(map[string]string),
	}
}

func (r *mockStreamRegistry) Register(sess session.Session) error {
	r.sessions[sess.ID()] = sess
	return nil
}

func (r *mockStreamRegistry) Unregister(id string) error {
	delete(r.sessions, id)
	return nil
}

func (r *mockStreamRegistry) Get(id string) session.Session {
	return r.sessions[id]
}

func (r *mockStreamRegistry) GetByDestination(destHash string) session.Session {
	id, ok := r.dests[destHash]
	if !ok {
		return nil
	}
	return r.sessions[id]
}

func (r *mockStreamRegistry) All() []string {
	var ids []string
	for id := range r.sessions {
		ids = append(ids, id)
	}
	return ids
}

func (r *mockStreamRegistry) Count() int {
	return len(r.sessions)
}

func (r *mockStreamRegistry) Close() error {
	r.sessions = make(map[string]session.Session)
	r.dests = make(map[string]string)
	return nil
}

func (r *mockStreamRegistry) MostRecentByStyle(style session.Style) session.Session {
	// Simple implementation - return nil (no tracking in mock)
	return nil
}

func TestStreamHandler_HandleConnect(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *protocol.Command
		handshakeDone  bool
		session        session.Session
		registeredSess session.Session
		connector      *mockStreamConnector
		wantResult     string
		wantNilResp    bool
		wantSilentErr  bool // Expect SilentCloseError to be returned
	}{
		{
			name:          "missing handshake",
			cmd:           &protocol.Command{Verb: "STREAM", Action: "CONNECT"},
			handshakeDone: false,
			wantResult:    protocol.ResultI2PError,
		},
		{
			name:          "missing ID",
			cmd:           &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{}},
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidID,
		},
		{
			name: "missing DESTINATION",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultInvalidKey,
		},
		{
			name: "session not found",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "nonexistent",
				"DESTINATION": "AAAA...",
			}},
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidID,
		},
		{
			name: "wrong session style",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleDatagram},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "connector not available",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      nil,
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "connection error",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{err: errors.New("connection failed")},
			wantResult:     protocol.ResultCantReachPeer,
		},
		{
			name: "successful connect",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{conn: &mockConn{}},
			wantResult:     protocol.ResultOK,
		},
		{
			name: "successful connect with silent",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"SILENT":      "true",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{conn: &mockConn{}},
			wantNilResp:    true,
		},
		{
			name: "connection error with silent - returns SilentCloseError",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"SILENT":      "true",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{err: errors.New("connection failed")},
			wantNilResp:    true,
			wantSilentErr:  true,
		},
		{
			name: "connect with ports",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"FROM_PORT":   "1234",
				"TO_PORT":     "5678",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{conn: &mockConn{}},
			wantResult:     protocol.ResultOK,
		},
		{
			name: "invalid FROM_PORT",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"FROM_PORT":   "99999",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "invalid FROM_PORT - negative",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"FROM_PORT":   "-1",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "invalid FROM_PORT - non-numeric",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"FROM_PORT":   "notaport",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "invalid TO_PORT - too large",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"TO_PORT":     "70000",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "valid edge port 0",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"FROM_PORT":   "0",
				"TO_PORT":     "0",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{conn: &mockConn{}},
			wantResult:     protocol.ResultOK,
		},
		{
			name: "valid edge port 65535",
			cmd: &protocol.Command{Verb: "STREAM", Action: "CONNECT", Options: map[string]string{
				"ID":          "test-session",
				"DESTINATION": "AAAA...",
				"FROM_PORT":   "65535",
				"TO_PORT":     "65535",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			connector:      &mockStreamConnector{conn: &mockConn{}},
			wantResult:     protocol.ResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := newMockStreamRegistry()
			if tt.registeredSess != nil {
				registry.Register(tt.registeredSess)
			}

			// Build handler with optional connector (avoid typed nil interface issue)
			var connector StreamConnector
			if tt.connector != nil {
				connector = tt.connector
			}
			handler := NewStreamHandler(connector, nil, nil)
			ctx := &Context{
				Conn:              &mockConn{},
				Registry:          registry,
				HandshakeComplete: tt.handshakeDone,
				Session:           tt.session,
			}

			resp, err := handler.Handle(ctx, tt.cmd)

			// Check for expected SilentCloseError (SILENT=true failure case)
			if tt.wantSilentErr {
				if err == nil {
					t.Fatal("Handle() expected SilentCloseError, got nil error")
				}
				if !util.IsSilentClose(err) {
					t.Errorf("Handle() error = %v, want SilentCloseError", err)
				}
				if resp != nil {
					t.Errorf("Handle() expected nil response with SilentCloseError, got %v", resp)
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if tt.wantNilResp {
				if resp != nil {
					t.Errorf("Handle() expected nil response, got %v", resp)
				}
				return
			}

			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("response = %q, want RESULT=%s", respStr, tt.wantResult)
			}
		})
	}
}

func TestStreamHandler_HandleAccept(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *protocol.Command
		handshakeDone  bool
		registeredSess session.Session
		acceptor       *mockStreamAcceptor
		wantResult     string
		wantNilResp    bool
		wantSilentErr  bool   // Expect SilentCloseError to be returned
		wantDestLine   string // Expected destination line in AdditionalLines
	}{
		{
			name:          "missing ID",
			cmd:           &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{}},
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidID,
		},
		{
			name: "session not found",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID": "nonexistent",
			}},
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidID,
		},
		{
			name: "wrong session style",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleRaw},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "acceptor not available",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			acceptor:       nil,
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "accept error",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			acceptor:       &mockStreamAcceptor{err: errors.New("accept failed")},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "successful accept",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			acceptor: &mockStreamAcceptor{
				conn: &mockConn{},
				info: &AcceptInfo{Destination: "AAAA...", FromPort: 0, ToPort: 0},
			},
			wantResult:   protocol.ResultOK,
			wantDestLine: "AAAA... FROM_PORT=0 TO_PORT=0",
		},
		{
			name: "successful accept with ports",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			acceptor: &mockStreamAcceptor{
				conn: &mockConn{},
				info: &AcceptInfo{Destination: "BASE64DEST", FromPort: 8080, ToPort: 443},
			},
			wantResult:   protocol.ResultOK,
			wantDestLine: "BASE64DEST FROM_PORT=8080 TO_PORT=443",
		},
		{
			name: "accept with silent",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID":     "test-session",
				"SILENT": "true",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			acceptor: &mockStreamAcceptor{
				conn: &mockConn{},
				info: &AcceptInfo{Destination: "AAAA...", FromPort: 0, ToPort: 0},
			},
			wantNilResp: true,
		},
		{
			name: "accept error with silent - returns SilentCloseError",
			cmd: &protocol.Command{Verb: "STREAM", Action: "ACCEPT", Options: map[string]string{
				"ID":     "test-session",
				"SILENT": "true",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			acceptor:       &mockStreamAcceptor{err: errors.New("accept failed")},
			wantNilResp:    true,
			wantSilentErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := newMockStreamRegistry()
			if tt.registeredSess != nil {
				registry.Register(tt.registeredSess)
			}

			// Build handler with optional acceptor (avoid typed nil interface issue)
			var acceptor StreamAcceptor
			if tt.acceptor != nil {
				acceptor = tt.acceptor
			}
			handler := NewStreamHandler(nil, acceptor, nil)
			ctx := &Context{
				Conn:              &mockConn{},
				Registry:          registry,
				HandshakeComplete: tt.handshakeDone,
			}

			resp, err := handler.Handle(ctx, tt.cmd)

			// Check for expected SilentCloseError (SILENT=true failure case)
			if tt.wantSilentErr {
				if err == nil {
					t.Fatal("Handle() expected SilentCloseError, got nil error")
				}
				if !util.IsSilentClose(err) {
					t.Errorf("Handle() error = %v, want SilentCloseError", err)
				}
				if resp != nil {
					t.Errorf("Handle() expected nil response with SilentCloseError, got %v", resp)
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if tt.wantNilResp {
				if resp != nil {
					t.Errorf("Handle() expected nil response, got %v", resp)
				}
				return
			}

			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("response = %q, want RESULT=%s", respStr, tt.wantResult)
			}

			// Check for expected destination line in AdditionalLines
			if tt.wantDestLine != "" {
				if !resp.HasAdditionalLines() {
					t.Errorf("Handle() expected AdditionalLines with destination, got none")
				} else if len(resp.AdditionalLines) < 1 || resp.AdditionalLines[0] != tt.wantDestLine {
					t.Errorf("Handle() AdditionalLines[0] = %q, want %q", resp.AdditionalLines[0], tt.wantDestLine)
				}
			}
		})
	}
}

func TestStreamHandler_HandleForward(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *protocol.Command
		handshakeDone  bool
		remoteAddr     string
		registeredSess session.Session
		forwarder      *mockStreamForwarder
		wantResult     string
		wantHost       string
	}{
		{
			name:          "missing ID",
			cmd:           &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{}},
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidID,
		},
		{
			name: "missing PORT",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID": "test-session",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "invalid PORT",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "-1",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "invalid PORT - too large",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "99999",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "invalid PORT - non-numeric",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "notaport",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "valid PORT edge 0",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "0",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      &mockStreamForwarder{listener: &mockListener{}},
			wantResult:     protocol.ResultOK,
		},
		{
			name: "valid PORT edge 65535",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "65535",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      &mockStreamForwarder{listener: &mockListener{}},
			wantResult:     protocol.ResultOK,
		},
		{
			name: "session not found",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "nonexistent",
				"PORT": "8080",
			}},
			handshakeDone: true,
			wantResult:    protocol.ResultInvalidID,
		},
		{
			name: "forwarder not available",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "8080",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      nil,
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "forward error",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "8080",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      &mockStreamForwarder{err: errors.New("forward failed")},
			wantResult:     protocol.ResultI2PError,
		},
		{
			name: "successful forward with explicit host",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "8080",
				"HOST": "192.168.1.100",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      &mockStreamForwarder{listener: &mockListener{}},
			wantResult:     protocol.ResultOK,
			wantHost:       "192.168.1.100",
		},
		{
			name: "successful forward with default host",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "8080",
			}},
			handshakeDone:  true,
			remoteAddr:     "10.0.0.5:54321",
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      &mockStreamForwarder{listener: &mockListener{}},
			wantResult:     protocol.ResultOK,
			wantHost:       "10.0.0.5",
		},
		{
			name: "forward with SSL",
			cmd: &protocol.Command{Verb: "STREAM", Action: "FORWARD", Options: map[string]string{
				"ID":   "test-session",
				"PORT": "8080",
				"HOST": "localhost",
				"SSL":  "true",
			}},
			handshakeDone:  true,
			registeredSess: &mockStreamSession{id: "test-session", style: session.StyleStream},
			forwarder:      &mockStreamForwarder{listener: &mockListener{}},
			wantResult:     protocol.ResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := newMockStreamRegistry()
			if tt.registeredSess != nil {
				registry.Register(tt.registeredSess)
			}

			// Build handler with optional forwarder (avoid typed nil interface issue)
			var forwarder StreamForwarder
			if tt.forwarder != nil {
				forwarder = tt.forwarder
			}
			handler := NewStreamHandler(nil, nil, forwarder)

			var remoteAddr net.Addr
			if tt.remoteAddr != "" {
				remoteAddr = &mockAddr{network: "tcp", addr: tt.remoteAddr}
			}

			ctx := &Context{
				Conn:              &mockConn{remoteAddr: remoteAddr},
				Registry:          registry,
				HandshakeComplete: tt.handshakeDone,
			}

			resp, err := handler.Handle(ctx, tt.cmd)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("response = %q, want RESULT=%s", respStr, tt.wantResult)
			}

			// Verify forwarded host if applicable
			if tt.wantHost != "" && tt.forwarder != nil && tt.forwarder.lastReq != nil {
				if tt.forwarder.lastReq.host != tt.wantHost {
					t.Errorf("forwarded host = %q, want %q", tt.forwarder.lastReq.host, tt.wantHost)
				}
			}
		})
	}
}

func TestStreamHandler_UnknownAction(t *testing.T) {
	handler := NewStreamHandler(nil, nil, nil)
	ctx := &Context{
		Conn:              &mockConn{},
		HandshakeComplete: true,
	}

	cmd := &protocol.Command{Verb: "STREAM", Action: "UNKNOWN", Options: map[string]string{}}
	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp == nil {
		t.Fatal("expected response")
	}

	respStr := resp.String()
	if !strings.Contains(respStr, "RESULT="+protocol.ResultI2PError) {
		t.Errorf("response = %q, want RESULT=%s", respStr, protocol.ResultI2PError)
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input      string
		defaultVal bool
		want       bool
	}{
		{"", true, true},
		{"", false, false},
		{"true", false, true},
		{"TRUE", false, true},
		{"True", false, true},
		{"1", false, true},
		{"false", true, false},
		{"FALSE", true, false},
		{"False", true, false},
		{"0", true, false},
		{"invalid", true, true},
		{"invalid", false, false},
	}

	for _, tt := range tests {
		got := parseBool(tt.input, tt.defaultVal)
		if got != tt.want {
			t.Errorf("parseBool(%q, %v) = %v, want %v", tt.input, tt.defaultVal, got, tt.want)
		}
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input      string
		defaultVal int
		want       int
	}{
		{"", 0, 0},
		{"", 42, 42},
		{"123", 0, 123},
		{"-1", 0, -1},
		{"invalid", 99, 99},
	}

	for _, tt := range tests {
		got := parseInt(tt.input, tt.defaultVal)
		if got != tt.want {
			t.Errorf("parseInt(%q, %d) = %d, want %d", tt.input, tt.defaultVal, got, tt.want)
		}
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{0, true},
		{1, true},
		{80, true},
		{443, true},
		{65535, true},
		{-1, false},
		{65536, false},
		{99999, false},
	}

	for _, tt := range tests {
		got := isValidPort(tt.port)
		if got != tt.want {
			t.Errorf("isValidPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"", "127.0.0.1"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"127.0.0.1:12345", "127.0.0.1"},
		{"[::1]:8080", "::1"},
		{"localhost", "localhost"}, // no port, returns as-is
	}

	for _, tt := range tests {
		got := extractHost(tt.addr)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestStreamResponses(t *testing.T) {
	tests := []struct {
		name       string
		resp       *protocol.Response
		wantResult string
	}{
		{"streamOK", streamOK(), protocol.ResultOK},
		{"streamInvalidID", streamInvalidID("test"), protocol.ResultInvalidID},
		{"streamInvalidKey", streamInvalidKey("test"), protocol.ResultInvalidKey},
		{"streamCantReachPeer", streamCantReachPeer("test"), protocol.ResultCantReachPeer},
		{"streamTimeout", streamTimeout("test"), protocol.ResultTimeout},
		{"streamError", streamError("test"), protocol.ResultI2PError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.resp.Verb != protocol.VerbStream {
				t.Errorf("Verb = %q, want %q", tt.resp.Verb, protocol.VerbStream)
			}
			if tt.resp.Action != protocol.ActionStatus {
				t.Errorf("Action = %q, want %q", tt.resp.Action, protocol.ActionStatus)
			}
			respStr := tt.resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("response = %q, want RESULT=%s", respStr, tt.wantResult)
			}
		})
	}
}

func TestStreamHandler_LookupSession(t *testing.T) {
	handler := NewStreamHandler(nil, nil, nil)
	registry := newMockStreamRegistry()

	boundSession := &mockStreamSession{id: "bound", style: session.StyleStream}
	registeredSession := &mockStreamSession{id: "registered", style: session.StyleStream}
	registry.Register(registeredSession)

	// Test with bound session
	ctx := &Context{
		Session:  boundSession,
		Registry: registry,
	}

	// Should find bound session first
	found := handler.lookupSession(ctx, "bound")
	if found != boundSession {
		t.Error("should find bound session")
	}

	// Should find registered session
	found = handler.lookupSession(ctx, "registered")
	if found != registeredSession {
		t.Error("should find registered session")
	}

	// Should not find nonexistent session
	found = handler.lookupSession(ctx, "nonexistent")
	if found != nil {
		t.Error("should not find nonexistent session")
	}

	// Test with nil registry
	ctxNoReg := &Context{Session: nil, Registry: nil}
	found = handler.lookupSession(ctxNoReg, "any")
	if found != nil {
		t.Error("should return nil with no registry")
	}
}

// TestStreamHandler_LookupSubsession tests subsession lookup in PRIMARY sessions.
// Per SAMv3.md, STREAM commands use subsession IDs when operating on PRIMARY sessions.
func TestStreamHandler_LookupSubsession(t *testing.T) {
	handler := NewStreamHandler(nil, nil, nil)

	// Create a PRIMARY session with a STREAM subsession
	dest := &session.Destination{
		PublicKey:     []byte("test-pub-base64"),
		PrivateKey:    []byte("test-priv-key"),
		SignatureType: 7,
	}
	config := session.DefaultSessionConfig()
	primary := session.NewPrimarySession("primary-1", dest, nil, config)
	primary.SetStatus(session.StatusActive)

	// Add a STREAM subsession
	_, err := primary.AddSubsession("stream-sub", session.StyleStream, session.SubsessionOptions{
		FromPort:   1234,
		ListenPort: 1234,
	})
	if err != nil {
		t.Fatalf("AddSubsession() error = %v", err)
	}

	ctx := &Context{
		Session: primary,
	}

	// Should find PRIMARY session by its own ID
	found := handler.lookupSession(ctx, "primary-1")
	if found != primary {
		t.Error("should find PRIMARY session by its ID")
	}

	// Should find subsession by its ID
	found = handler.lookupSession(ctx, "stream-sub")
	if found == nil {
		t.Fatal("should find subsession by its ID")
	}
	if found.ID() != "stream-sub" {
		t.Errorf("found session ID = %q, want %q", found.ID(), "stream-sub")
	}
	if found.Style() != session.StyleStream {
		t.Errorf("found session Style = %v, want STREAM", found.Style())
	}

	// Should not find nonexistent subsession
	found = handler.lookupSession(ctx, "nonexistent-sub")
	if found != nil {
		t.Error("should not find nonexistent subsession")
	}
}

func TestStreamHandler_ConnectError(t *testing.T) {
	handler := NewStreamHandler(nil, nil, nil)

	tests := []struct {
		name       string
		err        error
		wantResult string
	}{
		{
			name:       "timeout error",
			err:        util.ErrTimeout,
			wantResult: protocol.ResultTimeout,
		},
		{
			name:       "peer not found error",
			err:        util.ErrPeerNotFound,
			wantResult: protocol.ResultPeerNotFound,
		},
		{
			name:       "leaseset not found error",
			err:        util.ErrLeasesetNotFound,
			wantResult: protocol.ResultPeerNotFound, // Maps to PEER_NOT_FOUND
		},
		{
			name:       "invalid key error",
			err:        util.ErrInvalidKey,
			wantResult: protocol.ResultInvalidKey,
		},
		{
			name:       "cant reach peer error",
			err:        util.ErrCantReachPeer,
			wantResult: protocol.ResultCantReachPeer,
		},
		{
			name:       "unknown error defaults to cant reach peer",
			err:        errors.New("some unknown error"),
			wantResult: protocol.ResultCantReachPeer,
		},
		{
			name:       "wrapped timeout error",
			err:        fmt.Errorf("connection failed: %w", util.ErrTimeout),
			wantResult: protocol.ResultTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := handler.connectError(tt.err)
			if resp == nil {
				t.Fatal("connectError() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("connectError() = %q, want RESULT=%s", respStr, tt.wantResult)
			}
		})
	}
}

// TestStreamHandler_AlreadyAccepting tests version-dependent concurrent ACCEPT behavior.
// Per SAMv3.md: Prior to SAM 3.2, concurrent ACCEPTs fail with ALREADY_ACCEPTING.
// As of SAM 3.2, multiple concurrent ACCEPTs are allowed.
func TestStreamHandler_AlreadyAccepting(t *testing.T) {
	t.Run("pre-3.2 rejects concurrent accept", func(t *testing.T) {
		// Create a StreamSessionImpl with pending accept
		streamSess := session.NewStreamSession("test-session", nil, nil, nil, nil, nil)
		streamSess.SetStatus(session.StatusActive)
		streamSess.IncrementPendingAccepts() // Simulate an active ACCEPT

		acceptor := &mockStreamAcceptor{
			conn: nil,
			info: &AcceptInfo{Destination: "test", FromPort: 0, ToPort: 0},
			err:  nil,
		}
		handler := NewStreamHandler(nil, acceptor, nil)

		// Create context with pre-3.2 version
		registry := newMockStreamRegistry()
		registry.sessions["test-session"] = streamSess

		ctx := &Context{
			Version:           "3.1",
			HandshakeComplete: true,
			Session:           streamSess,
			Registry:          registry,
		}

		cmd := &protocol.Command{
			Verb:    protocol.VerbStream,
			Action:  protocol.ActionAccept,
			Options: map[string]string{"ID": "test-session"},
		}

		resp, err := handler.Handle(ctx, cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respStr := resp.String()
		if !strings.Contains(respStr, protocol.ResultAlreadyAccepting) {
			t.Errorf("expected ALREADY_ACCEPTING, got: %s", respStr)
		}
	})

	t.Run("3.2+ allows concurrent accept", func(t *testing.T) {
		// Create a StreamSessionImpl with pending accept
		streamSess := session.NewStreamSession("test-session", nil, nil, nil, nil, nil)
		streamSess.SetStatus(session.StatusActive)
		streamSess.IncrementPendingAccepts() // Simulate an active ACCEPT

		// Create a simple mock connection
		acceptor := &mockStreamAcceptor{
			conn: nil, // nil conn is OK for this test
			info: &AcceptInfo{Destination: "testdest", FromPort: 0, ToPort: 0},
			err:  nil,
		}
		handler := NewStreamHandler(nil, acceptor, nil)

		// Create context with 3.2 version - concurrent accepts allowed
		registry := newMockStreamRegistry()
		registry.sessions["test-session"] = streamSess

		ctx := &Context{
			Version:           "3.2",
			HandshakeComplete: true,
			Session:           streamSess,
			Registry:          registry,
		}

		cmd := &protocol.Command{
			Verb:    protocol.VerbStream,
			Action:  protocol.ActionAccept,
			Options: map[string]string{"ID": "test-session"},
		}

		resp, err := handler.Handle(ctx, cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respStr := resp.String()
		if strings.Contains(respStr, protocol.ResultAlreadyAccepting) {
			t.Errorf("SAM 3.2 should allow concurrent accepts, got: %s", respStr)
		}
		if !strings.Contains(respStr, protocol.ResultOK) {
			t.Errorf("expected OK result, got: %s", respStr)
		}
	})

	t.Run("3.3 allows concurrent accept", func(t *testing.T) {
		// Create a StreamSessionImpl with pending accept
		streamSess := session.NewStreamSession("test-session", nil, nil, nil, nil, nil)
		streamSess.SetStatus(session.StatusActive)
		streamSess.IncrementPendingAccepts() // Simulate an active ACCEPT

		acceptor := &mockStreamAcceptor{
			conn: nil,
			info: &AcceptInfo{Destination: "testdest", FromPort: 0, ToPort: 0},
			err:  nil,
		}
		handler := NewStreamHandler(nil, acceptor, nil)

		// Create context with 3.3 version
		registry := newMockStreamRegistry()
		registry.sessions["test-session"] = streamSess

		ctx := &Context{
			Version:           "3.3",
			HandshakeComplete: true,
			Session:           streamSess,
			Registry:          registry,
		}

		cmd := &protocol.Command{
			Verb:    protocol.VerbStream,
			Action:  protocol.ActionAccept,
			Options: map[string]string{"ID": "test-session"},
		}

		resp, err := handler.Handle(ctx, cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respStr := resp.String()
		if strings.Contains(respStr, protocol.ResultAlreadyAccepting) {
			t.Errorf("SAM 3.3 should allow concurrent accepts, got: %s", respStr)
		}
		if !strings.Contains(respStr, protocol.ResultOK) {
			t.Errorf("expected OK result, got: %s", respStr)
		}
	})
}
