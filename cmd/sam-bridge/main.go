// Package main provides the entry point for the SAM bridge server.
// The SAM bridge implements the SAMv3.3 protocol, enabling applications
// to communicate over the I2P anonymity network using text-based commands.
//
// Usage:
//
//	sam-bridge [flags]
//
// Flags:
//
//	-listen string     SAM listen address (default ":7656")
//	-i2cp string       I2CP router address (default "127.0.0.1:7654")
//	-udp string        UDP datagram port (default ":7655")
//	-debug             Enable debug logging
//	-help              Show help message
//
// See SAMv3.md for the complete SAM protocol specification.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/go-i2p/go-sam-bridge/lib/bridge"
	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/handler"
	"github.com/go-i2p/go-sam-bridge/lib/i2cp"
	"github.com/go-i2p/go-sam-bridge/lib/session"
	"github.com/sirupsen/logrus"
)

var (
	// Version is set at build time via ldflags
	Version = "dev"

	// Build info
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Config holds the bridge server configuration.
type Config struct {
	// ListenAddr is the SAM TCP listen address (default ":7656").
	ListenAddr string

	// I2CPAddr is the I2CP router address (default "127.0.0.1:7654").
	I2CPAddr string

	// UDPAddr is the UDP datagram port (default ":7655").
	UDPAddr string

	// Debug enables debug logging.
	Debug bool

	// Username for I2CP authentication (optional).
	Username string

	// Password for I2CP authentication (optional).
	Password string
}

func main() {
	cfg := parseFlags()

	// Configure logging
	log := logrus.New()
	log.SetOutput(os.Stdout)
	if cfg.Debug {
		log.SetLevel(logrus.DebugLevel)
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	log.WithFields(logrus.Fields{
		"version":   Version,
		"buildTime": BuildTime,
		"commit":    GitCommit,
	}).Info("Starting SAM bridge server")

	// Create session registry
	registry := session.NewRegistry()

	// Create I2CP client configuration
	i2cpConfig := &i2cp.ClientConfig{
		RouterAddr: cfg.I2CPAddr,
		Username:   cfg.Username,
		Password:   cfg.Password,
	}

	// Create I2CP client
	i2cpClient := i2cp.NewClient(i2cpConfig)

	// Connect to I2P router
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.WithField("addr", cfg.I2CPAddr).Info("Connecting to I2P router")
	if err := i2cpClient.Connect(ctx); err != nil {
		log.WithError(err).Error("Failed to connect to I2P router")
		log.Info("Make sure I2P is running and SAM interface is enabled")
		os.Exit(1)
	}
	defer i2cpClient.Close()

	log.WithField("version", i2cpClient.RouterVersion()).Info("Connected to I2P router")

	// Parse UDP datagram port from address string
	datagramPort := bridge.DefaultDatagramPort
	if cfg.UDPAddr != "" {
		_, portStr, err := net.SplitHostPort(cfg.UDPAddr)
		if err != nil {
			// Try parsing as just a port number
			portStr = cfg.UDPAddr
		}
		if parsedPort, err := strconv.Atoi(portStr); err == nil {
			datagramPort = parsedPort
		}
	}

	// Create bridge server configuration
	bridgeConfig := &bridge.Config{
		ListenAddr:   cfg.ListenAddr,
		I2CPAddr:     cfg.I2CPAddr,
		DatagramPort: datagramPort,
	}

	// Create bridge server
	server, err := bridge.NewServer(bridgeConfig, registry)
	if err != nil {
		log.WithError(err).Error("Failed to create bridge server")
		os.Exit(1)
	}

	// Register all SAM command handlers
	registerHandlers(server, cfg, log)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		log.WithField("addr", cfg.ListenAddr).Info("SAM bridge listening")
		if err := server.ListenAndServe(); err != nil {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.WithField("signal", sig.String()).Info("Received shutdown signal")
	case err := <-errChan:
		log.WithError(err).Error("Server error")
	}

	// Graceful shutdown
	log.Info("Shutting down...")

	// Stop accepting new connections
	if err := server.Close(); err != nil {
		log.WithError(err).Warn("Error stopping server")
	}

	// Close all sessions
	if err := registry.Close(); err != nil {
		log.WithError(err).Warn("Error closing sessions")
	}

	log.Info("SAM bridge stopped")
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", ":7656", "SAM listen address")
	flag.StringVar(&cfg.I2CPAddr, "i2cp", "127.0.0.1:7654", "I2CP router address")
	flag.StringVar(&cfg.UDPAddr, "udp", ":7655", "UDP datagram port")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	flag.StringVar(&cfg.Username, "user", "", "I2CP username (optional)")
	flag.StringVar(&cfg.Password, "pass", "", "I2CP password (optional)")

	showVersion := flag.Bool("version", false, "Show version information")
	showHelp := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *showVersion {
		fmt.Printf("sam-bridge %s\n", Version)
		fmt.Printf("Build time: %s\n", BuildTime)
		fmt.Printf("Git commit: %s\n", GitCommit)
		os.Exit(0)
	}

	if *showHelp {
		fmt.Println("SAM Bridge - SAMv3.3 Protocol Bridge for I2P")
		fmt.Println()
		fmt.Println("Usage: sam-bridge [flags]")
		fmt.Println()
		fmt.Println("Flags:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Environment variables:")
		fmt.Println("  SAM_LISTEN    SAM listen address (overrides -listen)")
		fmt.Println("  I2CP_ADDR     I2CP router address (overrides -i2cp)")
		fmt.Println("  SAM_DEBUG     Enable debug logging (overrides -debug)")
		os.Exit(0)
	}

	// Override with environment variables if set
	if envListen := os.Getenv("SAM_LISTEN"); envListen != "" {
		cfg.ListenAddr = envListen
	}
	if envI2CP := os.Getenv("I2CP_ADDR"); envI2CP != "" {
		cfg.I2CPAddr = envI2CP
	}
	if os.Getenv("SAM_DEBUG") != "" {
		cfg.Debug = true
	}

	return cfg
}

// registerHandlers registers all SAM command handlers with the server.
// This sets up handlers for HELLO, SESSION, STREAM, DATAGRAM, RAW,
// NAMING, DEST, PING, QUIT, and AUTH commands per SAMv3.md.
func registerHandlers(server *bridge.Server, cfg *Config, log *logrus.Logger) {
	router := server.Router()
	authStore := server.AuthStore()

	// Create shared dependencies
	destManager := destination.NewManager()

	// Register HELLO handler (must be first command per SAMv3.md)
	helloConfig := handler.DefaultHelloConfig()
	if authStore != nil && authStore.IsAuthEnabled() {
		helloConfig.RequireAuth = true
		helloConfig.AuthFunc = authStore.CheckPassword
	}
	helloHandler := handler.NewHelloHandler(helloConfig)
	router.Register("HELLO VERSION", helloHandler)

	log.Debug("Registered HELLO VERSION handler")

	// Register SESSION handler
	sessionHandler := handler.NewSessionHandler(destManager)
	router.Register("SESSION CREATE", sessionHandler)
	router.Register("SESSION ADD", sessionHandler)
	router.Register("SESSION REMOVE", sessionHandler)

	log.Debug("Registered SESSION handlers")

	// Register STREAM handlers
	streamConnector := handler.NewStreamingConnector()
	streamAcceptor := handler.NewStreamingAcceptor()
	streamForwarder := handler.NewStreamingForwarder()
	streamHandler := handler.NewStreamHandler(streamConnector, streamAcceptor, streamForwarder)
	router.Register("STREAM CONNECT", streamHandler)
	router.Register("STREAM ACCEPT", streamHandler)
	router.Register("STREAM FORWARD", streamHandler)

	log.Debug("Registered STREAM handlers")

	// Register DATAGRAM handler
	handler.RegisterDatagramHandler(router)
	log.Debug("Registered DATAGRAM handler")

	// Register RAW handler
	rawHandler := handler.NewRawHandler()
	router.Register("RAW SEND", rawHandler)

	log.Debug("Registered RAW handler")

	// Register NAMING handler
	namingHandler := handler.NewNamingHandler(destManager)
	router.Register("NAMING LOOKUP", namingHandler)

	log.Debug("Registered NAMING handler")

	// Register DEST handler
	destHandler := handler.NewDestHandler(destManager)
	router.Register("DEST GENERATE", destHandler)

	log.Debug("Registered DEST handler")

	// Register PING handler
	handler.RegisterPingHandler(router)
	log.Debug("Registered PING handler")

	// Register utility handlers (QUIT, HELP, etc.)
	handler.RegisterUtilityHandlers(router)
	handler.RegisterHelpHandler(router)
	log.Debug("Registered utility handlers")

	// Register AUTH handlers if authentication is enabled
	if authStore != nil && authStore.IsAuthEnabled() {
		handler.RegisterAuthHandlers(router, authStore)
		log.Debug("Registered AUTH handlers")
	}

	log.WithField("count", router.Count()).Info("All SAM command handlers registered")
}
