package protocol

import (
	"testing"
)

func TestConstants(t *testing.T) {
	// Verify all SAM verbs are defined
	verbs := []string{
		VerbHello, VerbSession, VerbStream, VerbDatagram, VerbRaw,
		VerbDest, VerbNaming, VerbPing, VerbPong, VerbAuth,
		VerbQuit, VerbStop, VerbExit, VerbHelp,
	}
	for _, v := range verbs {
		if v == "" {
			t.Error("empty verb constant")
		}
	}

	// Verify all SAM actions are defined
	actions := []string{
		ActionVersion, ActionReply, ActionStatus, ActionCreate,
		ActionAdd, ActionRemove, ActionConnect, ActionAccept,
		ActionForward, ActionSend, ActionReceived, ActionGenerate,
		ActionLookup, ActionEnable, ActionDisable,
	}
	for _, a := range actions {
		if a == "" {
			t.Error("empty action constant")
		}
	}

	// Verify result codes
	results := []string{
		ResultOK, ResultCantReachPeer, ResultDuplicatedDest, ResultDuplicatedID,
		ResultI2PError, ResultInvalidKey, ResultInvalidID, ResultKeyNotFound,
		ResultPeerNotFound, ResultTimeout, ResultNoVersion, ResultLeasesetNotFound,
	}
	for _, r := range results {
		if r == "" {
			t.Error("empty result constant")
		}
	}

	// Verify default ports
	if DefaultSAMPort != 7656 {
		t.Errorf("DefaultSAMPort = %d, want 7656", DefaultSAMPort)
	}
	if DefaultDatagramPort != 7655 {
		t.Errorf("DefaultDatagramPort = %d, want 7655", DefaultDatagramPort)
	}
	if DefaultI2CPPort != 7654 {
		t.Errorf("DefaultI2CPPort = %d, want 7654", DefaultI2CPPort)
	}

	// Verify disallowed protocols
	expected := []int{6, 17, 19, 20}
	if len(DisallowedRawProtocols) != len(expected) {
		t.Errorf("DisallowedRawProtocols length = %d, want %d",
			len(DisallowedRawProtocols), len(expected))
	}
	for i, p := range expected {
		if DisallowedRawProtocols[i] != p {
			t.Errorf("DisallowedRawProtocols[%d] = %d, want %d", i, DisallowedRawProtocols[i], p)
		}
	}

	// Verify default signature type
	if DefaultSignatureType != SigTypeEd25519 {
		t.Errorf("DefaultSignatureType = %d, want %d", DefaultSignatureType, SigTypeEd25519)
	}
}

func TestDefaultEncryptionTypes(t *testing.T) {
	// Should be ECIES-X25519 (4) with ElGamal fallback (0)
	if len(DefaultEncryptionTypes) != 2 {
		t.Fatalf("DefaultEncryptionTypes length = %d, want 2", len(DefaultEncryptionTypes))
	}
	if DefaultEncryptionTypes[0] != 4 {
		t.Errorf("DefaultEncryptionTypes[0] = %d, want 4", DefaultEncryptionTypes[0])
	}
	if DefaultEncryptionTypes[1] != 0 {
		t.Errorf("DefaultEncryptionTypes[1] = %d, want 0", DefaultEncryptionTypes[1])
	}
}

func TestVersionSupportsPortInfo(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		// SAM 3.0 and 3.1 do NOT support port info
		{"3.0", false},
		{"3.1", false},
		// SAM 3.2+ supports port info
		{"3.2", true},
		{"3.3", true},
		// Empty version defaults to supporting port info (latest behavior)
		{"", true},
		// Future versions should also support port info
		{"3.4", true},
		{"4.0", true},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			got := VersionSupportsPortInfo(tt.version)
			if got != tt.want {
				t.Errorf("VersionSupportsPortInfo(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
