// Package session implements SAM v3.0-3.3 session management.
// This file provides shared helper functions for datagram session implementations
// (DATAGRAM, DATAGRAM2, DATAGRAM3) to reduce code duplication.
package session

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/go-i2p/go-datagrams"
)

// datagramConnHolder provides shared get/set access for a go-datagrams connection.
// Used by all datagram session types.
type datagramConnHolder struct {
	mu   sync.RWMutex
	conn *datagrams.DatagramConn
}

// setDatagramConn sets the go-datagrams connection.
func (h *datagramConnHolder) setDatagramConn(conn *datagrams.DatagramConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conn = conn
}

// getDatagramConn returns the go-datagrams connection, or nil if not configured.
func (h *datagramConnHolder) getDatagramConn() *datagrams.DatagramConn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.conn
}

// closeDatagramConn closes and nils the datagram connection if set.
func (h *datagramConnHolder) closeDatagramConn() {
	if h.conn != nil {
		h.conn.Close()
		h.conn = nil
	}
}

// resolveForwardingAddr validates and resolves a forwarding host:port for datagram sessions.
// Returns the resolved address or an error if the port is invalid or resolution fails.
func resolveForwardingAddr(host string, port int) (string, int, net.Addr, error) {
	if port < 1 || port > 65535 {
		return "", 0, nil, ErrInvalidForwardingPort
	}
	if host == "" {
		host = "127.0.0.1"
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return "", 0, nil, err
	}
	return host, port, addr, nil
}

// DatagramConnSetter is implemented by datagram and raw sessions to allow
// wiring the go-datagrams connection after session creation.
// This is used by the embedding layer to connect sessions to the I2CP datagram path.
type DatagramConnSetter interface {
	SetDatagramConn(conn *datagrams.DatagramConn)
}

// offlineSignatureHolder provides shared get/set access for offline signature data.
// Used by DATAGRAM2 and DATAGRAM3 which both support offline signatures.
type offlineSignatureHolder struct {
	mu  sync.RWMutex
	sig []byte
}

// SetOfflineSignature sets the offline signature data.
func (h *offlineSignatureHolder) SetOfflineSignature(sig []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sig = make([]byte, len(sig))
	copy(h.sig, sig)
}

// OfflineSignature returns a copy of the offline signature data.
func (h *offlineSignatureHolder) OfflineSignature() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.sig == nil {
		return nil
	}
	sig := make([]byte, len(h.sig))
	copy(sig, h.sig)
	return sig
}

// sam33Options holds the SAM 3.3 send options shared between datagram and raw sessions.
type sam33Options struct {
	SendTags        int
	TagThreshold    int
	Expires         int
	SendLeaseset    bool
	SendLeasesetSet bool
}

// hasSAM33Options returns true if any SAM 3.3 option is set.
func (o sam33Options) hasSAM33Options() bool {
	return o.SendTags != 0 || o.TagThreshold != 0 || o.Expires != 0 || o.SendLeasesetSet
}

// buildSAM33Options converts SAM 3.3 send options to go-datagrams Options.
// Returns nil if no SAM 3.3 options are set.
func (o sam33Options) buildSAM33Options() *datagrams.Options {
	if !o.hasSAM33Options() {
		return nil
	}
	dgOpts := datagrams.EmptyOptions()
	if o.SendTags > 0 {
		dgOpts.Set("SEND_TAGS", fmt.Sprintf("%d", o.SendTags))
	}
	if o.TagThreshold > 0 {
		dgOpts.Set("TAG_THRESHOLD", fmt.Sprintf("%d", o.TagThreshold))
	}
	if o.Expires > 0 {
		dgOpts.Set("EXPIRES", fmt.Sprintf("%d", o.Expires))
	}
	if o.SendLeasesetSet {
		if o.SendLeaseset {
			dgOpts.Set("SEND_LEASESET", "true")
		} else {
			dgOpts.Set("SEND_LEASESET", "false")
		}
	}
	return dgOpts
}

// closeDGResources performs the shared close sequence for DATAGRAM and RAW sessions.
// It checks status, cancels the context, waits for goroutines, calls cleanupFn under
// the write lock to release session-specific resources, then closes the base session.
func closeDGResources(
	mu *sync.RWMutex,
	statusFn func() Status,
	cancel context.CancelFunc,
	wg *sync.WaitGroup,
	cleanupFn func(),
	base *BaseSession,
) error {
	mu.Lock()
	status := statusFn()
	if status == StatusClosed || status == StatusClosing {
		mu.Unlock()
		return nil
	}
	mu.Unlock()

	cancel()
	wg.Wait()

	mu.Lock()
	cleanupFn()
	mu.Unlock()

	return base.Close()
}
