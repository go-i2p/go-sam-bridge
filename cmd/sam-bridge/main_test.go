package main

import (
	"flag"
	"os"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/embedding"
	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/sirupsen/logrus"
)

// TestParseDatagramPort verifies boundary cases for parseDatagramPort.
func TestParseDatagramPort(t *testing.T) {
	defaultPort := embedding.DefaultDatagramPort

	tests := []struct {
		addr string
		want int
	}{
		{"", defaultPort},
		{":7655", 7655},
		{"0.0.0.0:7655", 7655},
		{"127.0.0.1:9999", 9999},
		{"7655", 7655},
		{"notaport", defaultPort},
		{":notaport", defaultPort},
		{":-1", -1}, // negative ports are returned as-is; caller is responsible for validation
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := parseDatagramPort(tt.addr)
			if got != tt.want {
				t.Errorf("parseDatagramPort(%q) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

// TestParseFlags_Defaults verifies that parseFlags returns expected defaults.
func TestParseFlags_Defaults(t *testing.T) {
	oldCmdLine := flag.CommandLine
	oldArgs := os.Args
	defer func() {
		flag.CommandLine = oldCmdLine
		os.Args = oldArgs
	}()

	flag.CommandLine = flag.NewFlagSet("sam-bridge", flag.ContinueOnError)
	os.Args = []string{"sam-bridge"}

	cfg := parseFlags()

	if cfg.ListenAddr != ":7656" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":7656")
	}
	if cfg.I2CPAddr != "127.0.0.1:7654" {
		t.Errorf("I2CPAddr = %q, want %q", cfg.I2CPAddr, "127.0.0.1:7654")
	}
	if cfg.UDPAddr != ":7655" {
		t.Errorf("UDPAddr = %q, want %q", cfg.UDPAddr, ":7655")
	}
	if cfg.Debug {
		t.Error("Debug should be false by default")
	}
}

// TestParseFlags_EnvVarOverrides verifies environment variable overrides in parseFlags.
func TestParseFlags_EnvVarOverrides(t *testing.T) {
	oldCmdLine := flag.CommandLine
	oldArgs := os.Args
	defer func() {
		flag.CommandLine = oldCmdLine
		os.Args = oldArgs
	}()

	// Set and restore environment variables
	envVars := map[string]string{
		"SAM_LISTEN": ":9876",
		"I2CP_ADDR":  "myrouter:7654",
		"SAM_DEBUG":  "1",
	}
	for k, v := range envVars {
		old := os.Getenv(k)
		os.Setenv(k, v)
		defer os.Setenv(k, old)
	}

	flag.CommandLine = flag.NewFlagSet("sam-bridge", flag.ContinueOnError)
	os.Args = []string{"sam-bridge"}

	cfg := parseFlags()

	if cfg.ListenAddr != ":9876" {
		t.Errorf("ListenAddr = %q, want %q (SAM_LISTEN override)", cfg.ListenAddr, ":9876")
	}
	if cfg.I2CPAddr != "myrouter:7654" {
		t.Errorf("I2CPAddr = %q, want %q (I2CP_ADDR override)", cfg.I2CPAddr, "myrouter:7654")
	}
	if !cfg.Debug {
		t.Error("Debug should be true when SAM_DEBUG is set")
	}
}

// TestCreateHandlerRegistrar_RouterKeys verifies that createHandlerRegistrar registers
// the minimum required router keys: SESSION CREATE, STREAM CONNECT, NAMING LOOKUP.
func TestCreateHandlerRegistrar_RouterKeys(t *testing.T) {
	// Build minimal dependencies — no live I2CP router needed.
	deps := &embedding.Dependencies{
		Registry:     session.NewRegistry(),
		DestManager:  destination.NewManager(),
		DatagramPort: embedding.DefaultDatagramPort,
		Logger:       logrus.New(),
	}

	router := handler.NewRouter()

	// Pass nil for i2cpClient; createHandlerRegistrar handles nil gracefully
	// (NewClientDestinationResolverAdapter returns error for nil, which is handled).
	registrar := createHandlerRegistrar(nil)
	registrar(router, deps)

	required := []string{
		"SESSION CREATE",
		"STREAM CONNECT",
		"NAMING LOOKUP",
	}
	for _, key := range required {
		if !router.HasHandler(key) {
			t.Errorf("router missing required handler for key %q", key)
		}
	}
}
