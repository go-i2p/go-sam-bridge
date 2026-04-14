// Package handler implements SAM command handlers per SAMv3.md specification.
// Each handler processes a specific SAM command (HELLO, SESSION, STREAM, etc.)
// and returns an appropriate response.
package handler

import (
	"context"
	"io"
	"net"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// Handler processes a SAM command and returns a response.
// Implementations must be safe for concurrent use.
type Handler interface {
	// Handle processes the command and returns a response.
	// Returns nil response if no response should be sent (e.g., after QUIT).
	// Returns error for internal errors (connection issues, not protocol errors).
	Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error)
}

// HandlerFunc is a function adapter for Handler interface.
// Allows using functions as handlers without creating a struct.
type HandlerFunc func(ctx *Context, cmd *protocol.Command) (*protocol.Response, error)

// Handle implements Handler by calling the function.
func (f HandlerFunc) Handle(ctx *Context, cmd *protocol.Command) (*protocol.Response, error) {
	return f(ctx, cmd)
}

// Context holds state for command execution.
// Created per-command and contains connection-specific information.
type Context struct {
	// Conn is the client connection.
	Conn net.Conn

	// StreamConn is the I2P stream connection after STREAM CONNECT/ACCEPT.
	// Per SAMv3.md: "all remaining data passing through the current socket
	// is forwarded from and to the connected I2P destination peer."
	// Nil until STREAM CONNECT or STREAM ACCEPT succeeds.
	StreamConn net.Conn

	// Session is the bound session, if any.
	// Nil until SESSION CREATE succeeds on this connection.
	Session session.Session

	// Registry provides access to the global session registry.
	Registry session.Registry

	// Version is the negotiated SAM version after HELLO.
	// Empty string before handshake completes.
	Version string

	// Authenticated indicates if the client has authenticated.
	// Always true if authentication is disabled on the bridge.
	Authenticated bool

	// HandshakeComplete indicates if HELLO has been received.
	HandshakeComplete bool

	// Ctx is the request context for cancellation and timeouts.
	Ctx context.Context

	// ForwardListeners holds listeners created by STREAM FORWARD.
	// Closed when the SAM connection is torn down to stop all forwarding loops.
	ForwardListeners []net.Listener
}

// NewContext creates a new handler context with the given connection.
func NewContext(conn net.Conn, registry session.Registry) *Context {
	return &Context{
		Conn:     conn,
		Registry: registry,
		Ctx:      context.Background(),
	}
}

// WithContext returns a copy of the Context with the given context.Context.
func (c *Context) WithContext(ctx context.Context) *Context {
	newCtx := *c
	newCtx.Ctx = ctx
	return &newCtx
}

// BindSession binds a session to this connection context.
func (c *Context) BindSession(s session.Session) {
	c.Session = s
}

// UnbindSession removes the session binding from this context.
func (c *Context) UnbindSession() {
	c.Session = nil
}

// RemoteAddr returns the remote address of the client connection.
// Returns empty string if connection is nil.
func (c *Context) RemoteAddr() string {
	if c.Conn == nil {
		return ""
	}
	addr := c.Conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

// SetStreamConn sets the I2P stream connection for data forwarding.
// Called after successful STREAM CONNECT or STREAM ACCEPT.
func (c *Context) SetStreamConn(conn net.Conn) {
	c.StreamConn = conn
}

// HasStreamConn returns true if a stream connection is set.
// When true, the bridge should start bidirectional data forwarding.
func (c *Context) HasStreamConn() bool {
	return c.StreamConn != nil
}

// AddForwardListener registers a listener created by STREAM FORWARD.
// All registered listeners are closed by CloseForwardListeners when the
// SAM connection ends, preventing goroutine and file-descriptor leaks.
func (c *Context) AddForwardListener(l net.Listener) {
	c.ForwardListeners = append(c.ForwardListeners, l)
}

// CloseForwardListeners closes all listeners registered via AddForwardListener.
// Must be called when the SAM client connection closes.
func (c *Context) CloseForwardListeners() {
	for _, l := range c.ForwardListeners {
		_ = l.Close()
	}
	c.ForwardListeners = nil
}

// StartForwarding starts bidirectional data forwarding between the control
// socket and the I2P stream connection. Per SAMv3.md: "all remaining data
// passing through the current socket is forwarded from and to the connected
// I2P destination peer."
//
// This method is called after STREAM CONNECT or STREAM ACCEPT succeeds.
// It spawns a background goroutine to perform the forwarding.
func (c *Context) StartForwarding() {
	if c.StreamConn == nil || c.Conn == nil {
		return
	}
	go c.ForwardData(c.StreamConn)
}

// ForwardData performs bidirectional data forwarding between the control
// socket (Conn) and the I2P stream connection (i2pConn).
// This function runs until either connection is closed or encounters an error.
func (c *Context) ForwardData(i2pConn net.Conn) error {
	if c.Conn == nil {
		return nil
	}

	// Use a WaitGroup to wait for both copy directions
	done := make(chan error, 2)

	// Forward: control socket -> I2P stream
	go func() {
		_, err := io.Copy(i2pConn, c.Conn)
		done <- err
	}()

	// Forward: I2P stream -> control socket
	go func() {
		_, err := io.Copy(c.Conn, i2pConn)
		done <- err
	}()

	// Wait for either direction to complete (connection closed)
	err := <-done

	// Close both connections to unblock the other goroutine
	c.Conn.Close()
	i2pConn.Close()

	// Wait for the second goroutine
	<-done

	return err
}

// StartDatagramReceiver starts a goroutine that reads from the session's
// Receive channel and writes DATAGRAM RECEIVED messages to the control socket.
//
// Per SAMv3.md: "When a datagram arrives, the bridge delivers it to the client via:
// <- DATAGRAM RECEIVED DESTINATION=$dest SIZE=$numBytes FROM_PORT=nnn TO_PORT=nnn \n
// [$numBytes of data]"
//
// This should be called after SESSION CREATE for DATAGRAM sessions when
// not using UDP forwarding (no PORT option).
func (c *Context) StartDatagramReceiver() {
	dgSess, ok := c.Session.(session.DatagramSession)
	if !ok {
		return
	}

	// Check if forwarding is enabled (in which case, don't write to control socket)
	if dgSess.ForwardingAddr() != nil {
		return
	}

	go c.receiveDatagrams(dgSess.Receive())
}

// receiveDatagrams reads datagrams from the channel and writes them to the control socket.
func (c *Context) receiveDatagrams(ch <-chan session.ReceivedDatagram) {
	for dg := range ch {
		// Format the DATAGRAM RECEIVED header
		header := FormatDatagramReceived(dg, c.Version)

		// Write header line followed by newline
		_, err := c.Conn.Write([]byte(header + "\n"))
		if err != nil {
			// Connection closed, stop receiving
			return
		}

		// Write the data payload
		_, err = c.Conn.Write(dg.Data)
		if err != nil {
			return
		}
	}
}

// StartRawReceiver starts a goroutine that reads from the session's
// Receive channel and writes RAW RECEIVED messages to the control socket.
//
// Per SAMv3.md: "When a raw datagram arrives, the bridge delivers it to the client via:
// <- RAW RECEIVED SIZE=$numBytes FROM_PORT=nnn TO_PORT=nnn PROTOCOL=nnn \n
// [$numBytes of data]"
//
// This should be called after SESSION CREATE for RAW sessions when
// not using UDP forwarding (no PORT option).
func (c *Context) StartRawReceiver() {
	rawSess, ok := c.Session.(session.RawSession)
	if !ok {
		return
	}

	// Check if forwarding is enabled (in which case, don't write to control socket)
	if rawSess.ForwardingAddr() != nil {
		return
	}

	go c.receiveRawDatagrams(rawSess.Receive())
}

// receiveRawDatagrams reads raw datagrams from the channel and writes them to the control socket.
func (c *Context) receiveRawDatagrams(ch <-chan session.ReceivedRawDatagram) {
	for dg := range ch {
		// Format the RAW RECEIVED header
		header := FormatRawReceived(dg, c.Version)

		// Write header line followed by newline
		_, err := c.Conn.Write([]byte(header + "\n"))
		if err != nil {
			// Connection closed, stop receiving
			return
		}

		// Write the data payload
		_, err = c.Conn.Write(dg.Data)
		if err != nil {
			return
		}
	}
}
