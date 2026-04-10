// Package session implements SAM v3.0-3.3 session management.
// This file provides shared helper functions for datagram session implementations
// (DATAGRAM, DATAGRAM2, DATAGRAM3) to reduce code duplication.
package session

import (
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

// offlineSignatureHolder provides shared get/set access for offline signature data.
// Used by DATAGRAM2 and DATAGRAM3 which both support offline signatures.
type offlineSignatureHolder struct {
	mu  sync.RWMutex
	sig []byte
}

// setOfflineSignature sets the offline signature data.
func (h *offlineSignatureHolder) setOfflineSignature(sig []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sig = make([]byte, len(sig))
	copy(h.sig, sig)
}

// getOfflineSignature returns a copy of the offline signature data.
func (h *offlineSignatureHolder) getOfflineSignature() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.sig == nil {
		return nil
	}
	sig := make([]byte, len(h.sig))
	copy(sig, h.sig)
	return sig
}
