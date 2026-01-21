package handler

import (
	"errors"
	"strings"
	"testing"

	commondest "github.com/go-i2p/common/destination"
	"github.com/go-i2p/go-sam-bridge/lib/destination"
	"github.com/go-i2p/go-sam-bridge/lib/protocol"
)

// mockManager is a test implementation of destination.Manager
type mockManager struct {
	generateErr     error
	encodeErr       error
	encodePubErr    error
	parseWithOffErr error
	dest            *commondest.Destination
	privateKey      []byte
	pubEncoded      string
	privEncoded     string
	parseResult     *destination.ParseResult
}

func (m *mockManager) Generate(signatureType int) (*commondest.Destination, []byte, error) {
	if m.generateErr != nil {
		return nil, nil, m.generateErr
	}
	return m.dest, m.privateKey, nil
}

func (m *mockManager) Parse(privkeyBase64 string) (*commondest.Destination, []byte, error) {
	return nil, nil, errors.New("not implemented")
}

func (m *mockManager) ParseWithOffline(privkeyBase64 string) (*destination.ParseResult, error) {
	if m.parseWithOffErr != nil {
		return nil, m.parseWithOffErr
	}
	if m.parseResult != nil {
		return m.parseResult, nil
	}
	return &destination.ParseResult{
		Destination:   m.dest,
		PrivateKey:    m.privateKey,
		SignatureType: 7,
	}, nil
}

func (m *mockManager) ParsePublic(destBase64 string) (*commondest.Destination, error) {
	return nil, errors.New("not implemented")
}

func (m *mockManager) Encode(dest *commondest.Destination, privateKey []byte) (string, error) {
	if m.encodeErr != nil {
		return "", m.encodeErr
	}
	return m.privEncoded, nil
}

func (m *mockManager) EncodePublic(d *commondest.Destination) (string, error) {
	if m.encodePubErr != nil {
		return "", m.encodePubErr
	}
	return m.pubEncoded, nil
}

func TestDestHandler_Handle(t *testing.T) {
	// Create a minimal destination for testing
	mockDest := &commondest.Destination{}
	mockPrivKey := []byte("test-private-key")

	tests := []struct {
		name       string
		command    *protocol.Command
		manager    *mockManager
		wantPub    bool
		wantPriv   bool
		wantResult string
	}{
		{
			name: "successful generation with default sig type",
			command: &protocol.Command{
				Verb:    "DEST",
				Action:  "GENERATE",
				Options: map[string]string{},
			},
			manager: &mockManager{
				dest:        mockDest,
				privateKey:  mockPrivKey,
				pubEncoded:  "test-pub-base64",
				privEncoded: "test-priv-base64",
			},
			wantPub:  true,
			wantPriv: true,
		},
		{
			name: "successful generation with Ed25519",
			command: &protocol.Command{
				Verb:   "DEST",
				Action: "GENERATE",
				Options: map[string]string{
					"SIGNATURE_TYPE": "7",
				},
			},
			manager: &mockManager{
				dest:        mockDest,
				privateKey:  mockPrivKey,
				pubEncoded:  "test-pub-base64",
				privEncoded: "test-priv-base64",
			},
			wantPub:  true,
			wantPriv: true,
		},
		{
			name: "successful generation with named sig type",
			command: &protocol.Command{
				Verb:   "DEST",
				Action: "GENERATE",
				Options: map[string]string{
					"SIGNATURE_TYPE": "ED25519",
				},
			},
			manager: &mockManager{
				dest:        mockDest,
				privateKey:  mockPrivKey,
				pubEncoded:  "test-pub-base64",
				privEncoded: "test-priv-base64",
			},
			wantPub:  true,
			wantPriv: true,
		},
		{
			name: "case-insensitive signature type name",
			command: &protocol.Command{
				Verb:   "DEST",
				Action: "GENERATE",
				Options: map[string]string{
					"SIGNATURE_TYPE": "ed25519",
				},
			},
			manager: &mockManager{
				dest:        mockDest,
				privateKey:  mockPrivKey,
				pubEncoded:  "test-pub-base64",
				privEncoded: "test-priv-base64",
			},
			wantPub:  true,
			wantPriv: true,
		},
		{
			name: "invalid signature type name",
			command: &protocol.Command{
				Verb:   "DEST",
				Action: "GENERATE",
				Options: map[string]string{
					"SIGNATURE_TYPE": "INVALID_TYPE",
				},
			},
			manager:    &mockManager{},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "unsupported signature type number",
			command: &protocol.Command{
				Verb:   "DEST",
				Action: "GENERATE",
				Options: map[string]string{
					"SIGNATURE_TYPE": "99",
				},
			},
			manager:    &mockManager{},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "generation failure",
			command: &protocol.Command{
				Verb:    "DEST",
				Action:  "GENERATE",
				Options: map[string]string{},
			},
			manager: &mockManager{
				generateErr: errors.New("generation failed"),
			},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "public encoding failure",
			command: &protocol.Command{
				Verb:    "DEST",
				Action:  "GENERATE",
				Options: map[string]string{},
			},
			manager: &mockManager{
				dest:         mockDest,
				privateKey:   mockPrivKey,
				encodePubErr: errors.New("encoding failed"),
			},
			wantResult: protocol.ResultI2PError,
		},
		{
			name: "private encoding failure",
			command: &protocol.Command{
				Verb:    "DEST",
				Action:  "GENERATE",
				Options: map[string]string{},
			},
			manager: &mockManager{
				dest:       mockDest,
				privateKey: mockPrivKey,
				pubEncoded: "test-pub-base64",
				encodeErr:  errors.New("encoding failed"),
			},
			wantResult: protocol.ResultI2PError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDestHandler(tt.manager)
			ctx := NewContext(&mockConn{}, nil)

			resp, err := handler.Handle(ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()

			if tt.wantResult != "" {
				if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
					t.Errorf("Handle() = %q, want RESULT=%s", respStr, tt.wantResult)
				}
			}

			if tt.wantPub && !strings.Contains(respStr, "PUB=") {
				t.Errorf("Handle() = %q, want PUB=", respStr)
			}

			if tt.wantPriv && !strings.Contains(respStr, "PRIV=") {
				t.Errorf("Handle() = %q, want PRIV=", respStr)
			}
		})
	}
}

func TestParseSignatureType(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]string
		want    int
		wantErr bool
	}{
		{
			name:    "empty defaults to 0",
			options: map[string]string{},
			want:    0,
		},
		{
			name:    "numeric 0",
			options: map[string]string{"SIGNATURE_TYPE": "0"},
			want:    0,
		},
		{
			name:    "numeric 7",
			options: map[string]string{"SIGNATURE_TYPE": "7"},
			want:    7,
		},
		{
			name:    "named DSA_SHA1",
			options: map[string]string{"SIGNATURE_TYPE": "DSA_SHA1"},
			want:    0,
		},
		{
			name:    "named ED25519",
			options: map[string]string{"SIGNATURE_TYPE": "ED25519"},
			want:    7,
		},
		{
			name:    "named ed25519 lowercase",
			options: map[string]string{"SIGNATURE_TYPE": "ed25519"},
			want:    7,
		},
		{
			name:    "named ECDSA_SHA256_P256",
			options: map[string]string{"SIGNATURE_TYPE": "ECDSA_SHA256_P256"},
			want:    1,
		},
		{
			name:    "invalid name",
			options: map[string]string{"SIGNATURE_TYPE": "UNKNOWN"},
			wantErr: true,
		},
		{
			name:    "invalid number format",
			options: map[string]string{"SIGNATURE_TYPE": "abc"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &protocol.Command{
				Verb:    "DEST",
				Action:  "GENERATE",
				Options: tt.options,
			}

			got, err := parseSignatureType(cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSignatureType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseSignatureType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSignatureTypeName(t *testing.T) {
	tests := []struct {
		name   string
		want   int
		wantOK bool
	}{
		{"DSA_SHA1", 0, true},
		{"ECDSA_SHA256_P256", 1, true},
		{"ECDSA_SHA384_P384", 2, true},
		{"ECDSA_SHA512_P521", 3, true},
		{"RSA_SHA256_2048", 4, true},
		{"RSA_SHA384_3072", 5, true},
		{"RSA_SHA512_4096", 6, true},
		{"ED25519", 7, true},
		{"EDDSA_SHA512_ED25519", 7, true},
		{"ED25519PH", 8, true},
		{"ed25519", 7, true}, // case-insensitive
		{"Ed25519", 7, true}, // case-insensitive
		{"UNKNOWN", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseSignatureTypeName(tt.name)
			if ok != tt.wantOK {
				t.Errorf("parseSignatureTypeName(%q) ok = %v, want %v", tt.name, ok, tt.wantOK)
			}
			if tt.wantOK && got != tt.want {
				t.Errorf("parseSignatureTypeName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestEqualFold(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"ABC", "ABC", true},
		{"abc", "ABC", true},
		{"ABC", "abc", true},
		{"AbC", "aBc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := equalFold(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("equalFold(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDestResponses(t *testing.T) {
	t.Run("destReply", func(t *testing.T) {
		resp := destReply("pub123", "priv456")
		got := resp.String()
		if !strings.Contains(got, "DEST REPLY") {
			t.Errorf("destReply() = %q, want 'DEST REPLY'", got)
		}
		if !strings.Contains(got, "PUB=pub123") {
			t.Errorf("destReply() = %q, want 'PUB=pub123'", got)
		}
		if !strings.Contains(got, "PRIV=priv456") {
			t.Errorf("destReply() = %q, want 'PRIV=priv456'", got)
		}
	})

	t.Run("destError", func(t *testing.T) {
		resp := destError("test error")
		got := resp.String()
		if !strings.Contains(got, "DEST REPLY") {
			t.Errorf("destError() = %q, want 'DEST REPLY'", got)
		}
		if !strings.Contains(got, "RESULT=I2P_ERROR") {
			t.Errorf("destError() = %q, want 'RESULT=I2P_ERROR'", got)
		}
		if !strings.Contains(got, "MESSAGE=") {
			t.Errorf("destError() = %q, want 'MESSAGE='", got)
		}
	})
}

func TestDestError(t *testing.T) {
	err := &destError_{msg: "test error message"}
	if err.Error() != "test error message" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error message")
	}
}
