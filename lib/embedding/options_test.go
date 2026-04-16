package embedding

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/logger"
)

func TestWithListenAddr(t *testing.T) {
	cfg := DefaultConfig()
	WithListenAddr(":9000")(cfg)

	if cfg.ListenAddr != ":9000" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9000")
	}
}

func TestWithI2CPAddr(t *testing.T) {
	cfg := DefaultConfig()
	WithI2CPAddr("10.0.0.1:7654")(cfg)

	if cfg.I2CPAddr != "10.0.0.1:7654" {
		t.Errorf("I2CPAddr = %q, want %q", cfg.I2CPAddr, "10.0.0.1:7654")
	}
}

func TestWithDatagramPort(t *testing.T) {
	cfg := DefaultConfig()
	WithDatagramPort(8000)(cfg)

	if cfg.DatagramPort != 8000 {
		t.Errorf("DatagramPort = %d, want %d", cfg.DatagramPort, 8000)
	}
}

func TestWithListener(t *testing.T) {
	cfg := DefaultConfig()
	mockLn := &mockListener{}
	WithListener(mockLn)(cfg)

	if cfg.Listener != mockLn {
		t.Error("Listener not set correctly")
	}
}

func TestWithRegistry(t *testing.T) {
	cfg := DefaultConfig()
	mockReg := &mockRegistry{}
	WithRegistry(mockReg)(cfg)

	if cfg.Registry != mockReg {
		t.Error("Registry not set correctly")
	}
}

func TestWithI2CPProvider(t *testing.T) {
	cfg := DefaultConfig()
	mockProv := &mockI2CPProvider{}
	WithI2CPProvider(mockProv)(cfg)

	if cfg.I2CPProvider != mockProv {
		t.Error("I2CPProvider not set correctly")
	}
}

func TestWithLogger(t *testing.T) {
	cfg := DefaultConfig()
	log := logger.GetGoI2PLogger()
	WithLogger(log)(cfg)

	if cfg.Logger != log {
		t.Error("Logger not set correctly")
	}
}

func TestWithTLS(t *testing.T) {
	cfg := DefaultConfig()
	tlsCfg := &tls.Config{ServerName: "test"}
	WithTLS(tlsCfg)(cfg)

	if cfg.TLSConfig != tlsCfg {
		t.Error("TLSConfig not set correctly")
	}
}

func TestWithAuth(t *testing.T) {
	cfg := DefaultConfig()
	users := map[string]string{
		"admin": "secret",
		"user":  "password",
	}
	WithAuth(users)(cfg)

	if len(cfg.AuthUsers) != 2 {
		t.Errorf("AuthUsers length = %d, want 2", len(cfg.AuthUsers))
	}

	if cfg.AuthUsers["admin"] != "secret" {
		t.Error("AuthUsers not copied correctly")
	}

	// Verify it's a copy, not a reference
	users["admin"] = "changed"
	if cfg.AuthUsers["admin"] == "changed" {
		t.Error("AuthUsers should be a copy, not a reference")
	}
}

func TestWithI2CPCredentials(t *testing.T) {
	cfg := DefaultConfig()
	WithI2CPCredentials("user", "pass")(cfg)

	if cfg.I2CPUsername != "user" {
		t.Errorf("I2CPUsername = %q, want %q", cfg.I2CPUsername, "user")
	}

	if cfg.I2CPPassword != "pass" {
		t.Errorf("I2CPPassword = %q, want %q", cfg.I2CPPassword, "pass")
	}
}

func TestWithDebug(t *testing.T) {
	cfg := DefaultConfig()
	WithDebug(true)(cfg)

	if !cfg.Debug {
		t.Error("Debug should be true")
	}
}

func TestWithHandlerRegistrar(t *testing.T) {
	cfg := DefaultConfig()
	called := false
	customRegistrar := HandlerRegistrarFunc(func(r *handler.Router, d *Dependencies) {
		called = true
	})

	WithHandlerRegistrar(customRegistrar)(cfg)

	if cfg.HandlerRegistrar == nil {
		t.Error("HandlerRegistrar should be set")
	}

	// Call it to verify it works
	cfg.HandlerRegistrar(nil, nil)
	if !called {
		t.Error("Custom registrar should have been called")
	}
}

// mockListener implements net.Listener for testing.
type mockListener struct{}

func (m *mockListener) Accept() (net.Conn, error) { return nil, nil }
func (m *mockListener) Close() error              { return nil }
func (m *mockListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7656} }
