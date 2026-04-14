package handler

import (
	"fmt"
	"strconv"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// sendSAM33Options holds parsed SAM 3.3 options shared by DATAGRAM and RAW handlers.
type sendSAM33Options struct {
	SendTags        int
	TagThreshold    int
	Expires         int
	SendLeaseset    bool
	SendLeasesetSet bool
}

// invalidKeyFn is a function that builds an INVALID_KEY error response for a specific verb.
type invalidKeyFn func(string) *protocol.Response

// parseSendRequiredParams validates and extracts DESTINATION and SIZE from the command.
// maxSize is the verb-specific maximum payload size.
func parseSendRequiredParams(cmd *protocol.Command, maxSize int, errFn invalidKeyFn) (string, int, *protocol.Response) {
	dest := cmd.Get("DESTINATION")
	if dest == "" {
		return "", 0, errFn("missing DESTINATION")
	}

	sizeStr := cmd.Get("SIZE")
	if sizeStr == "" {
		return "", 0, errFn("missing SIZE")
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size < 1 {
		return "", 0, errFn("invalid SIZE: must be positive integer")
	}
	if size > maxSize {
		return "", 0, errFn(fmt.Sprintf("SIZE exceeds maximum (%d)", maxSize))
	}
	return dest, size, nil
}

// parseSendPortOptions extracts FROM_PORT and TO_PORT from the command (SAM 3.2+).
func parseSendPortOptions(cmd *protocol.Command, errFn invalidKeyFn) (uint16, uint16, *protocol.Response) {
	var fromPort, toPort uint16
	var err error

	if fromPortStr := cmd.Get("FROM_PORT"); fromPortStr != "" {
		fromPort, err = parseSendPort(fromPortStr, "FROM_PORT")
		if err != nil {
			return 0, 0, errFn(err.Error())
		}
	}

	if toPortStr := cmd.Get("TO_PORT"); toPortStr != "" {
		toPort, err = parseSendPort(toPortStr, "TO_PORT")
		if err != nil {
			return 0, 0, errFn(err.Error())
		}
	}
	return fromPort, toPort, nil
}

// parseSendSAM33Options extracts SAM 3.3 specific options from the command.
func parseSendSAM33Options(cmd *protocol.Command, errFn invalidKeyFn) (*sendSAM33Options, *protocol.Response) {
	opts := &sendSAM33Options{
		SendLeaseset: true, // Default per SAMv3.md
	}
	var err error

	if sendTagsStr := cmd.Get("SEND_TAGS"); sendTagsStr != "" {
		opts.SendTags, err = parseSendSAM33Int(sendTagsStr, "SEND_TAGS", 0, 15)
		if err != nil {
			return nil, errFn(err.Error())
		}
	}

	if tagThresholdStr := cmd.Get("TAG_THRESHOLD"); tagThresholdStr != "" {
		opts.TagThreshold, err = parseSendSAM33Int(tagThresholdStr, "TAG_THRESHOLD", 0, 15)
		if err != nil {
			return nil, errFn(err.Error())
		}
	}

	if expiresStr := cmd.Get("EXPIRES"); expiresStr != "" {
		opts.Expires, err = parseSendSAM33Int(expiresStr, "EXPIRES", 0, 86400)
		if err != nil {
			return nil, errFn(err.Error())
		}
	}

	if sendLeasesetStr := cmd.Get("SEND_LEASESET"); sendLeasesetStr != "" {
		opts.SendLeaseset, err = parseSendBool(sendLeasesetStr, "SEND_LEASESET")
		if err != nil {
			return nil, errFn(err.Error())
		}
		opts.SendLeasesetSet = true
	}
	return opts, nil
}

// parseSendPort validates and parses a port string.
func parseSendPort(s, name string) (uint16, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid port value", name)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("%s: port must be 0-65535", name)
	}
	return uint16(port), nil
}

// parseSendSAM33Int parses a SAM 3.3 integer option with range validation.
func parseSendSAM33Int(s, name string, min, max int) (int, error) {
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value", name)
	}
	if val < min || val > max {
		return 0, fmt.Errorf("%s: value must be %d-%d", name, min, max)
	}
	return val, nil
}

// parseSendBool parses a boolean option value.
// Accepts "true"/"false" (case-insensitive) per SAM specification.
func parseSendBool(s, name string) (bool, error) {
	switch s {
	case "true", "TRUE", "True":
		return true, nil
	case "false", "FALSE", "False":
		return false, nil
	default:
		return false, fmt.Errorf("%s: must be true or false", name)
	}
}
