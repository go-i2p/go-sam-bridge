// Package i2cp provides I2CP option mapping for the SAM bridge.
package i2cp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-i2p/go-sam-bridge/lib/session"
)

// MapSAMConfigToI2CP converts a SAM SessionConfig to an I2CP SessionConfig.
// This translates SAM protocol options to their I2CP equivalents.
//
// Per PLAN.md section 1.7: Maps SAM session configuration to I2CP options format.
func MapSAMConfigToI2CP(samConfig *session.SessionConfig) *SessionConfig {
	if samConfig == nil {
		return DefaultSessionConfig()
	}

	config := &SessionConfig{
		SignatureType:          samConfig.SignatureType,
		EncryptionTypes:        append([]int{}, samConfig.EncryptionTypes...),
		InboundQuantity:        samConfig.InboundQuantity,
		OutboundQuantity:       samConfig.OutboundQuantity,
		InboundLength:          samConfig.InboundLength,
		OutboundLength:         samConfig.OutboundLength,
		InboundBackupQuantity:  samConfig.InboundBackupQuantity,
		OutboundBackupQuantity: samConfig.OutboundBackupQuantity,
		FastReceive:            true, // Always enable for better performance
	}

	// Map idle handling
	if samConfig.ReduceIdleTime > 0 {
		config.ReduceIdleTime = samConfig.ReduceIdleTime
	}
	if samConfig.CloseIdleTime > 0 {
		config.CloseIdleTime = samConfig.CloseIdleTime
	}

	return config
}

// I2CPOptions represents a set of I2CP key-value options.
// These are sent to the I2P router during session creation.
type I2CPOptions map[string]string

// NewI2CPOptions creates an empty options map.
func NewI2CPOptions() I2CPOptions {
	return make(I2CPOptions)
}

// Set sets an option value.
func (o I2CPOptions) Set(key, value string) {
	o[key] = value
}

// SetInt sets an integer option value.
func (o I2CPOptions) SetInt(key string, value int) {
	o[key] = strconv.Itoa(value)
}

// SetBool sets a boolean option value.
func (o I2CPOptions) SetBool(key string, value bool) {
	if value {
		o[key] = "true"
	} else {
		o[key] = "false"
	}
}

// Get returns an option value, or empty string if not set.
func (o I2CPOptions) Get(key string) string {
	return o[key]
}

// GetInt returns an integer option value, or 0 if not set or invalid.
func (o I2CPOptions) GetInt(key string) int {
	v, _ := strconv.Atoi(o[key])
	return v
}

// GetBool returns a boolean option value, or false if not set or invalid.
func (o I2CPOptions) GetBool(key string) bool {
	return strings.ToLower(o[key]) == "true"
}

// BuildFromSAMConfig builds I2CP options from a SAM session configuration.
// This is used when creating I2CP sessions from SAM SESSION CREATE commands.
func BuildFromSAMConfig(samConfig *session.SessionConfig) I2CPOptions {
	opts := NewI2CPOptions()

	if samConfig == nil {
		return opts
	}

	// Tunnel configuration
	opts.SetInt("inbound.quantity", samConfig.InboundQuantity)
	opts.SetInt("outbound.quantity", samConfig.OutboundQuantity)
	opts.SetInt("inbound.length", samConfig.InboundLength)
	opts.SetInt("outbound.length", samConfig.OutboundLength)

	if samConfig.InboundBackupQuantity > 0 {
		opts.SetInt("inbound.backupQuantity", samConfig.InboundBackupQuantity)
	}
	if samConfig.OutboundBackupQuantity > 0 {
		opts.SetInt("outbound.backupQuantity", samConfig.OutboundBackupQuantity)
	}

	// Encryption type
	if len(samConfig.EncryptionTypes) > 0 {
		encTypes := make([]string, len(samConfig.EncryptionTypes))
		for i, t := range samConfig.EncryptionTypes {
			encTypes[i] = strconv.Itoa(t)
		}
		opts.Set("i2cp.leaseSetEncType", strings.Join(encTypes, ","))
	}

	// Performance options
	opts.SetBool("i2cp.fastReceive", true)
	opts.Set("i2cp.messageReliability", "none")

	// Idle handling
	if samConfig.ReduceIdleTime > 0 {
		opts.SetBool("i2cp.reduceOnIdle", true)
		opts.SetInt("i2cp.reduceIdleTime", samConfig.ReduceIdleTime*1000)
		if samConfig.ReduceIdleQuantity > 0 {
			opts.SetInt("i2cp.reduceQuantity", samConfig.ReduceIdleQuantity)
		}
	}
	if samConfig.CloseIdleTime > 0 {
		opts.SetBool("i2cp.closeOnIdle", true)
		opts.SetInt("i2cp.closeIdleTime", samConfig.CloseIdleTime*1000)
	}

	return opts
}

// ParseI2CPOptions parses I2CP options from a SAM command's key-value pairs.
// This extracts options that start with "i2cp." or are known tunnel options.
func ParseI2CPOptions(cmdOptions map[string]string) I2CPOptions {
	opts := NewI2CPOptions()

	// Known I2CP and tunnel options
	knownOptions := []string{
		"inbound.quantity",
		"outbound.quantity",
		"inbound.length",
		"outbound.length",
		"inbound.backupQuantity",
		"outbound.backupQuantity",
		"i2cp.leaseSetEncType",
		"i2cp.fastReceive",
		"i2cp.messageReliability",
		"i2cp.reduceOnIdle",
		"i2cp.reduceIdleTime",
		"i2cp.reduceQuantity",
		"i2cp.closeOnIdle",
		"i2cp.closeIdleTime",
		"i2cp.encryptLeaseSet",
		"i2cp.gzip",
	}

	for _, key := range knownOptions {
		if v, ok := cmdOptions[key]; ok {
			opts.Set(key, v)
		}
	}

	// Also include any other i2cp.* options
	for key, value := range cmdOptions {
		if strings.HasPrefix(key, "i2cp.") {
			opts.Set(key, value)
		}
	}

	return opts
}

// SignatureTypeName returns the human-readable name for a signature type.
func SignatureTypeName(sigType int) string {
	names := map[int]string{
		0: "DSA_SHA1",
		1: "ECDSA_SHA256_P256",
		2: "ECDSA_SHA384_P384",
		3: "ECDSA_SHA512_P521",
		4: "RSA_SHA256_2048",
		5: "RSA_SHA384_3072",
		6: "RSA_SHA512_4096",
		7: "Ed25519",
		8: "Ed25519ph",
	}

	if name, ok := names[sigType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", sigType)
}

// EncryptionTypeName returns the human-readable name for an encryption type.
func EncryptionTypeName(encType int) string {
	names := map[int]string{
		0: "ElGamal",
		4: "ECIES-X25519",
	}

	if name, ok := names[encType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", encType)
}

// ValidateSignatureType returns true if the signature type is valid.
func ValidateSignatureType(sigType int) bool {
	return sigType >= 0 && sigType <= 8
}

// ValidateEncryptionType returns true if the encryption type is valid.
func ValidateEncryptionType(encType int) bool {
	return encType == 0 || encType == 4
}
