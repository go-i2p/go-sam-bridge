// Package handler implements SAM command handlers per SAMv3.md specification.
// This file contains option parsing functions for SESSION CREATE and SESSION ADD commands,
// extracted from session.go to improve maintainability.
package handler

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// parseConfig extracts session configuration from command options.
// Per SAM 3.2+, validates ports (0-65535) and protocol (0-255, excluding 6,17,19,20).
// The style parameter determines which options are valid.
// Unparsed i2cp.* and streaming.* options are stored for passthrough to I2CP.
// Returns an error if validation fails.
func (h *SessionHandler) parseConfig(cmd *protocol.Command, style session.Style) (*session.SessionConfig, error) {
	config := session.DefaultSessionConfig()
	parsedOptions := make(map[string]bool)

	// Parse tunnel configuration
	h.parseTunnelOptions(cmd, config, parsedOptions)

	// Parse port options (SAM 3.2+)
	if err := h.parseConfigPortOptions(cmd, config, parsedOptions); err != nil {
		return nil, err
	}

	// Parse RAW-specific options
	if err := h.parseConfigRawOptions(cmd, config, style, parsedOptions); err != nil {
		return nil, err
	}

	// Parse UDP options (Java I2P specific)
	if err := h.parseConfigUDPOptions(cmd, config, parsedOptions); err != nil {
		return nil, err
	}

	// Collect unparsed I2CP options for passthrough
	h.collectI2CPOptions(cmd, config, parsedOptions)

	return config, nil
}

// parseTunnelOptions extracts tunnel quantity and length options.
func (h *SessionHandler) parseTunnelOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) {
	if v := cmd.Get("inbound.quantity"); v != "" {
		parsed["inbound.quantity"] = true
		if qty, err := strconv.Atoi(v); err == nil && qty >= 0 {
			config.InboundQuantity = qty
		}
	}
	if v := cmd.Get("outbound.quantity"); v != "" {
		parsed["outbound.quantity"] = true
		if qty, err := strconv.Atoi(v); err == nil && qty >= 0 {
			config.OutboundQuantity = qty
		}
	}
	if v := cmd.Get("inbound.length"); v != "" {
		parsed["inbound.length"] = true
		if len, err := strconv.Atoi(v); err == nil && len >= 0 {
			config.InboundLength = len
		}
	}
	if v := cmd.Get("outbound.length"); v != "" {
		parsed["outbound.length"] = true
		if len, err := strconv.Atoi(v); err == nil && len >= 0 {
			config.OutboundLength = len
		}
	}
}

// parseConfigPortOptions extracts and validates FROM_PORT and TO_PORT (SAM 3.2+).
func (h *SessionHandler) parseConfigPortOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) error {
	if v := cmd.Get("FROM_PORT"); v != "" {
		parsed["FROM_PORT"] = true
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return fmt.Errorf("invalid FROM_PORT: %w", err)
		}
		config.FromPort = port
	}
	if v := cmd.Get("TO_PORT"); v != "" {
		parsed["TO_PORT"] = true
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return fmt.Errorf("invalid TO_PORT: %w", err)
		}
		config.ToPort = port
	}
	return nil
}

// parseConfigRawOptions extracts RAW-specific options (PROTOCOL, HEADER).
func (h *SessionHandler) parseConfigRawOptions(cmd *protocol.Command, config *session.SessionConfig, style session.Style, parsed map[string]bool) error {
	if v := cmd.Get("PROTOCOL"); v != "" {
		parsed["PROTOCOL"] = true
		if style != session.StyleRaw {
			return fmt.Errorf("PROTOCOL option is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(v)
		if err != nil {
			return fmt.Errorf("invalid PROTOCOL: %w", err)
		}
		config.Protocol = proto
	}

	if v := cmd.Get("HEADER"); v != "" {
		parsed["HEADER"] = true
		if style != session.StyleRaw {
			return fmt.Errorf("HEADER option is only valid for STYLE=RAW")
		}
		config.HeaderEnabled = (v == "true")
	}
	return nil
}

// parseConfigUDPOptions extracts sam.udp.host and sam.udp.port options (Java I2P specific).
func (h *SessionHandler) parseConfigUDPOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) error {
	if v := cmd.Get("sam.udp.host"); v != "" {
		parsed["sam.udp.host"] = true
		config.SamUDPHost = v
	}
	if v := cmd.Get("sam.udp.port"); v != "" {
		parsed["sam.udp.port"] = true
		port, err := protocol.ValidatePortString(v)
		if err != nil {
			return fmt.Errorf("invalid sam.udp.port: %w", err)
		}
		config.SamUDPPort = port
	}
	return nil
}

// collectI2CPOptions gathers unparsed i2cp.* and streaming.* options for I2CP passthrough.
func (h *SessionHandler) collectI2CPOptions(cmd *protocol.Command, config *session.SessionConfig, parsed map[string]bool) {
	for key, value := range cmd.Options {
		if parsed[key] {
			continue
		}
		if isStandardSAMOption(key) {
			continue
		}
		if isI2CPOption(key) {
			config.I2CPOptions[key] = value
		}
	}
}

// containsWhitespace checks if a string contains any whitespace.
func containsWhitespace(s string) bool {
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			return true
		}
	}
	return false
}

// isStandardSAMOption returns true if the option is a standard SAM command option
// that should not be passed through to I2CP. These are options defined in the
// SAM specification that are handled by the SAM bridge itself.
func isStandardSAMOption(key string) bool {
	switch key {
	case "STYLE", "ID", "DESTINATION", "SIGNATURE_TYPE",
		"PORT", "HOST", "SILENT", "SSL",
		"LISTEN_PORT", "LISTEN_PROTOCOL",
		"SEND_TAGS", "TAG_THRESHOLD", "EXPIRES", "SEND_LEASESET":
		return true
	default:
		return false
	}
}

// isI2CPOption returns true if the option should be passed through to I2CP.
// This includes i2cp.*, streaming.*, inbound.*, outbound.*, and sam.* options
// per SAMv3.md specification.
func isI2CPOption(key string) bool {
	return strings.HasPrefix(key, "i2cp.") ||
		strings.HasPrefix(key, "streaming.") ||
		strings.HasPrefix(key, "inbound.") ||
		strings.HasPrefix(key, "outbound.") ||
		strings.HasPrefix(key, "sam.")
}

// hasOfflineSignatureOptions checks if the command contains offline signature options.
// Per SAMv3.md, offline signatures require specific options that cannot be used
// with DESTINATION=TRANSIENT.
func hasOfflineSignatureOptions(cmd *protocol.Command) bool {
	return cmd.Get("OFFLINE_SIGNATURE") != "" ||
		cmd.Get("OFFLINE_EXPIRES") != "" ||
		cmd.Get("TRANSIENT_KEY") != ""
}

// parseSubsessionOptions parses subsession options from SESSION ADD command.
// Per SAMv3.md, options include PORT, HOST, FROM_PORT, TO_PORT, PROTOCOL,
// LISTEN_PORT, LISTEN_PROTOCOL, HEADER.
func (h *SessionHandler) parseSubsessionOptions(cmd *protocol.Command, style session.Style) (*session.SubsessionOptions, error) {
	opts := &session.SubsessionOptions{}

	// Parse PORT and HOST (DATAGRAM*/RAW only)
	if err := h.parseSubsessionPortHost(cmd, opts, style); err != nil {
		return nil, err
	}

	// Parse traffic ports (FROM_PORT, TO_PORT)
	if err := h.parseSubsessionTrafficPorts(cmd, opts); err != nil {
		return nil, err
	}

	// Parse PROTOCOL (RAW only)
	if err := h.parseSubsessionProtocol(cmd, opts, style); err != nil {
		return nil, err
	}

	// Parse listen options (LISTEN_PORT, LISTEN_PROTOCOL)
	if err := h.parseSubsessionListenOptions(cmd, opts, style); err != nil {
		return nil, err
	}

	// Parse HEADER (RAW only)
	if err := h.parseSubsessionHeader(cmd, opts, style); err != nil {
		return nil, err
	}

	return opts, nil
}

// parseSubsessionPortHost extracts PORT and HOST options.
func (h *SessionHandler) parseSubsessionPortHost(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	if portStr := cmd.Get("PORT"); portStr != "" {
		if style == session.StyleStream {
			return fmt.Errorf("PORT is invalid for STYLE=STREAM")
		}
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid PORT: %w", err)
		}
		opts.Port = port
	}

	if host := cmd.Get("HOST"); host != "" {
		if style == session.StyleStream {
			return fmt.Errorf("HOST is invalid for STYLE=STREAM")
		}
		opts.Host = host
	} else if style != session.StyleStream {
		opts.Host = "127.0.0.1" // Default per SAM spec
	}
	return nil
}

// parseSubsessionTrafficPorts extracts FROM_PORT and TO_PORT options.
func (h *SessionHandler) parseSubsessionTrafficPorts(cmd *protocol.Command, opts *session.SubsessionOptions) error {
	if portStr := cmd.Get("FROM_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid FROM_PORT: %w", err)
		}
		opts.FromPort = port
	}

	if portStr := cmd.Get("TO_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid TO_PORT: %w", err)
		}
		opts.ToPort = port
	}
	return nil
}

// parseSubsessionProtocol extracts PROTOCOL option (RAW only).
func (h *SessionHandler) parseSubsessionProtocol(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	if protoStr := cmd.Get("PROTOCOL"); protoStr != "" {
		if style != session.StyleRaw {
			return fmt.Errorf("PROTOCOL is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(protoStr)
		if err != nil {
			return fmt.Errorf("invalid PROTOCOL: %w", err)
		}
		opts.Protocol = proto
	} else if style == session.StyleRaw {
		opts.Protocol = 18 // Default per SAM spec
	}
	return nil
}

// parseSubsessionListenOptions extracts LISTEN_PORT and LISTEN_PROTOCOL options.
func (h *SessionHandler) parseSubsessionListenOptions(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	// Parse LISTEN_PORT - default is FROM_PORT value
	if portStr := cmd.Get("LISTEN_PORT"); portStr != "" {
		port, err := protocol.ValidatePortString(portStr)
		if err != nil {
			return fmt.Errorf("invalid LISTEN_PORT: %w", err)
		}
		// For STREAM, only FROM_PORT value or 0 is allowed
		if style == session.StyleStream && port != 0 && port != opts.FromPort {
			return fmt.Errorf("LISTEN_PORT must be 0 or FROM_PORT value for STYLE=STREAM")
		}
		opts.ListenPort = port
	} else {
		opts.ListenPort = opts.FromPort // Default per spec
	}

	// Parse LISTEN_PROTOCOL (RAW only) - default is PROTOCOL value; 6 is disallowed
	if protoStr := cmd.Get("LISTEN_PROTOCOL"); protoStr != "" {
		if style != session.StyleRaw {
			return fmt.Errorf("LISTEN_PROTOCOL is only valid for STYLE=RAW")
		}
		proto, err := protocol.ValidateProtocolString(protoStr)
		if err != nil {
			return fmt.Errorf("invalid LISTEN_PROTOCOL: %w", err)
		}
		if proto == 6 {
			return fmt.Errorf("LISTEN_PROTOCOL=6 (streaming) is disallowed for RAW")
		}
		opts.ListenProtocol = proto
	} else if style == session.StyleRaw {
		opts.ListenProtocol = opts.Protocol // Default per spec
	}
	return nil
}

// parseSubsessionHeader extracts HEADER option (RAW only).
func (h *SessionHandler) parseSubsessionHeader(cmd *protocol.Command, opts *session.SubsessionOptions, style session.Style) error {
	if headerStr := cmd.Get("HEADER"); headerStr != "" {
		if style != session.StyleRaw {
			return fmt.Errorf("HEADER is only valid for STYLE=RAW")
		}
		opts.HeaderEnabled = (headerStr == "true")
	}

	return nil
}

// validateStyleOptions validates that style-specific option restrictions are followed.
// Per SAM spec:
//   - STREAM: PORT and HOST are invalid
//   - PRIMARY/MASTER: PORT, HOST, FROM_PORT, TO_PORT, PROTOCOL, LISTEN_PORT,
//     LISTEN_PROTOCOL, and HEADER are invalid (apply only to subsessions)
func validateStyleOptions(style session.Style, cmd *protocol.Command) error {
	switch style {
	case session.StyleStream:
		// Per SAM spec: PORT and HOST are invalid for STREAM
		if cmd.Get("PORT") != "" {
			return fmt.Errorf("PORT is invalid for STYLE=STREAM")
		}
		if cmd.Get("HOST") != "" {
			return fmt.Errorf("HOST is invalid for STYLE=STREAM")
		}

	case session.StylePrimary, session.StyleMaster:
		// Per SAM spec: These options only apply to subsessions, not PRIMARY
		disallowed := []string{
			"PORT", "HOST", "FROM_PORT", "TO_PORT",
			"PROTOCOL", "LISTEN_PORT", "LISTEN_PROTOCOL", "HEADER",
		}
		for _, opt := range disallowed {
			if cmd.Get(opt) != "" {
				return fmt.Errorf("%s is invalid for STYLE=PRIMARY", opt)
			}
		}
	}

	return nil
}
