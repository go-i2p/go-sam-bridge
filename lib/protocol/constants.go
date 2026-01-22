// Package protocol implements SAM v3.0-3.3 command parsing and response building.
// See SAMv3.md for the complete protocol specification.
package protocol

// SAM Protocol Verbs per SAM 3.0-3.3 specification.
const (
	VerbHello    = "HELLO"
	VerbSession  = "SESSION"
	VerbStream   = "STREAM"
	VerbDatagram = "DATAGRAM"
	VerbRaw      = "RAW"
	VerbDest     = "DEST"
	VerbNaming   = "NAMING"
	VerbPing     = "PING"
	VerbPong     = "PONG"
	VerbAuth     = "AUTH"
	VerbQuit     = "QUIT"
	VerbStop     = "STOP"
	VerbExit     = "EXIT"
	VerbHelp     = "HELP"
)

// SAM Protocol Actions per SAM 3.0-3.3 specification.
const (
	ActionVersion  = "VERSION"
	ActionReply    = "REPLY"
	ActionStatus   = "STATUS"
	ActionCreate   = "CREATE"
	ActionAdd      = "ADD"
	ActionRemove   = "REMOVE"
	ActionConnect  = "CONNECT"
	ActionAccept   = "ACCEPT"
	ActionForward  = "FORWARD"
	ActionSend     = "SEND"
	ActionReceived = "RECEIVED"
	ActionGenerate = "GENERATE"
	ActionLookup   = "LOOKUP"
	ActionEnable   = "ENABLE"
	ActionDisable  = "DISABLE"
)

// SAM Result Codes per SAM 3.0-3.3 specification.
// These are returned in the RESULT= field of responses.
const (
	ResultOK               = "OK"
	ResultAlreadyAccepting = "ALREADY_ACCEPTING"
	ResultCantReachPeer    = "CANT_REACH_PEER"
	ResultDuplicatedDest   = "DUPLICATED_DEST"
	ResultDuplicatedID     = "DUPLICATED_ID"
	ResultI2PError         = "I2P_ERROR"
	ResultInvalidKey       = "INVALID_KEY"
	ResultInvalidID        = "INVALID_ID"
	ResultKeyNotFound      = "KEY_NOT_FOUND"
	ResultPeerNotFound     = "PEER_NOT_FOUND"
	ResultTimeout          = "TIMEOUT"
	ResultNoVersion        = "NOVERSION"
	ResultLeasesetNotFound = "LEASESET_NOT_FOUND"
)

// SAM Session Styles per SAM 3.0-3.3 specification.
const (
	StyleStream    = "STREAM"
	StyleDatagram  = "DATAGRAM"
	StyleRaw       = "RAW"
	StyleDatagram2 = "DATAGRAM2"
	StyleDatagram3 = "DATAGRAM3"
	StylePrimary   = "PRIMARY"
	StyleMaster    = "MASTER" // Deprecated, alias for PRIMARY (pre-0.9.47)
)

// SAM Default Ports per SAM specification.
const (
	DefaultSAMPort      = 7656
	DefaultDatagramPort = 7655
	DefaultI2CPPort     = 7654
)

// Port validation constants.
const (
	MinPort = 0
	MaxPort = 65535
)

// Protocol validation constants for RAW sessions.
const (
	MinProtocol        = 0
	MaxProtocol        = 255
	DefaultRawProtocol = 18
)

// DisallowedRawProtocols are I2CP protocols that cannot be used with RAW sessions
// per SAMv3.md specification. These are reserved for TCP(6), UDP(17), and
// internal I2P protocols (19, 20).
var DisallowedRawProtocols = []int{6, 17, 19, 20}

// Signature Types per I2P specification.
// All clients should use SigTypeEd25519 (7) for new destinations.
const (
	SigTypeDSA_SHA1          = 0 // Default (deprecated, do not use)
	SigTypeECDSA_SHA256_P256 = 1
	SigTypeECDSA_SHA384_P384 = 2
	SigTypeECDSA_SHA512_P521 = 3
	SigTypeRSA_SHA256_2048   = 4
	SigTypeRSA_SHA384_3072   = 5
	SigTypeRSA_SHA512_4096   = 6
	SigTypeEd25519           = 7 // Recommended
	SigTypeEd25519ph         = 8
)

// DefaultSignatureType is Ed25519 per SAM specification recommendation.
const DefaultSignatureType = SigTypeEd25519

// DefaultEncryptionTypes specifies ECIES-X25519 with ElGamal fallback.
// This ensures compatibility with older routers while preferring modern crypto.
var DefaultEncryptionTypes = []int{4, 0}

// DefaultTunnelQuantity is the recommended tunnel count for balanced performance
// between Java I2P (default 2) and i2pd (default 5).
const DefaultTunnelQuantity = 3

// SAM Version constants.
const (
	SAMVersionMin = "3.0"
	SAMVersionMax = "3.3"
)
