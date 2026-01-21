package handler

import (
	"strings"
	"testing"

	"github.com/go-i2p/go-sam-bridge/lib/protocol"
	"github.com/go-i2p/go-sam-bridge/lib/session"
)

func TestNamingHandler_Handle(t *testing.T) {
	tests := []struct {
		name       string
		command    *protocol.Command
		session    session.Session
		wantResult string
		wantName   string
		wantValue  bool
	}{
		{
			name: "missing NAME parameter",
			command: &protocol.Command{
				Verb:    "NAMING",
				Action:  "LOOKUP",
				Options: map[string]string{},
			},
			wantResult: protocol.ResultInvalidKey,
		},
		{
			name: "NAME=ME with session",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME": "ME",
				},
			},
			session: session.NewBaseSession("test", session.StyleStream,
				&session.Destination{PublicKey: []byte("test-pub-key")}, nil, nil),
			wantResult: protocol.ResultOK,
			wantName:   "ME",
			wantValue:  true,
		},
		{
			name: "NAME=ME without session",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME": "ME",
				},
			},
			wantResult: protocol.ResultInvalidKey,
		},
		{
			name: "invalid name with newlines",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME": "test\nname",
				},
			},
			wantResult: protocol.ResultInvalidKey,
		},
		{
			name: ".i2p hostname lookup",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME": "example.i2p",
				},
			},
			wantResult: protocol.ResultKeyNotFound, // Not implemented yet
			wantName:   "example.i2p",
		},
		{
			name: ".b32.i2p address lookup",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv.b32.i2p",
				},
			},
			wantResult: protocol.ResultKeyNotFound, // Not implemented yet
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewNamingHandler(&mockManager{})
			ctx := NewContext(&mockConn{}, nil)
			ctx.Session = tt.session

			resp, err := handler.Handle(ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("Handle() = %q, want RESULT=%s", respStr, tt.wantResult)
			}

			if tt.wantName != "" && !strings.Contains(respStr, "NAME="+tt.wantName) {
				t.Errorf("Handle() = %q, want NAME=%s", respStr, tt.wantName)
			}

			if tt.wantValue && !strings.Contains(respStr, "VALUE=") {
				t.Errorf("Handle() = %q, want VALUE=", respStr)
			}
		})
	}
}

func TestNamingHandler_HandleNameMe(t *testing.T) {
	handler := NewNamingHandler(&mockManager{})

	t.Run("with valid session destination", func(t *testing.T) {
		ctx := NewContext(&mockConn{}, nil)
		ctx.Session = session.NewBaseSession("test", session.StyleStream,
			&session.Destination{PublicKey: []byte("my-dest-public-key")}, nil, nil)

		cmd := &protocol.Command{
			Verb:   "NAMING",
			Action: "LOOKUP",
			Options: map[string]string{
				"NAME": "ME",
			},
		}

		resp, err := handler.Handle(ctx, cmd)
		if err != nil {
			t.Fatalf("Handle() error = %v", err)
		}

		respStr := resp.String()
		if !strings.Contains(respStr, "RESULT=OK") {
			t.Errorf("Handle() = %q, want RESULT=OK", respStr)
		}
		if !strings.Contains(respStr, "VALUE=") {
			t.Errorf("Handle() = %q, want VALUE=", respStr)
		}
	})

	t.Run("with session but nil destination", func(t *testing.T) {
		ctx := NewContext(&mockConn{}, nil)
		ctx.Session = session.NewBaseSession("test", session.StyleStream, nil, nil, nil)

		cmd := &protocol.Command{
			Verb:   "NAMING",
			Action: "LOOKUP",
			Options: map[string]string{
				"NAME": "ME",
			},
		}

		resp, err := handler.Handle(ctx, cmd)
		if err != nil {
			t.Fatalf("Handle() error = %v", err)
		}

		respStr := resp.String()
		if !strings.Contains(respStr, "RESULT=INVALID_KEY") {
			t.Errorf("Handle() = %q, want RESULT=INVALID_KEY", respStr)
		}
	})
}

func TestIsValidName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"example.i2p", true},
		{"test.b32.i2p", true},
		{"ME", true},
		{"", false},
		{"name\nwith\nnewlines", false},
		{"name\twith\ttabs", false},
		{"name\rwith\rreturns", false},
		{"normal-name", true},
		{"name_with_underscores", true},
		{"name.with.dots", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidName(tt.name)
			if got != tt.want {
				t.Errorf("isValidName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsB32Address(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"abcdef.b32.i2p", true},
		{"ABCDEF.B32.I2P", true},
		{"abcdef.B32.i2p", true},
		{"example.i2p", false},
		{"example.com", false},
		{"", false},
		{".b32.i2p", true}, // technically valid format
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isB32Address(tt.name)
			if got != tt.want {
				t.Errorf("isB32Address(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsI2PHostname(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"example.i2p", true},
		{"EXAMPLE.I2P", true},
		{"sub.domain.i2p", true},
		{"abcdef.b32.i2p", false}, // b32 is not a regular hostname
		{"example.com", false},
		{"", false},
		{".i2p", true}, // technically valid format
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isI2PHostname(tt.name)
			if got != tt.want {
				t.Errorf("isI2PHostname(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsBase64Destination(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{strings.Repeat("A", 516), true},
		{strings.Repeat("a", 516), true},
		{strings.Repeat("0", 516), true},
		{strings.Repeat("-", 516), true},
		{strings.Repeat("~", 516), true},
		{strings.Repeat("A", 515), false}, // too short
		{"example.i2p", false},
		{"", false},
		{strings.Repeat("A", 516) + "!", false}, // invalid char at end
	}

	for _, tt := range tests {
		name := tt.name
		if len(name) > 20 {
			name = name[:20] + "..."
		}
		t.Run(name, func(t *testing.T) {
			got := isBase64Destination(tt.name)
			if got != tt.want {
				t.Errorf("isBase64Destination(%q) = %v, want %v", name, got, tt.want)
			}
		})
	}
}

func TestIsBase64Char(t *testing.T) {
	tests := []struct {
		char rune
		want bool
	}{
		{'A', true},
		{'Z', true},
		{'a', true},
		{'z', true},
		{'0', true},
		{'9', true},
		{'-', true},
		{'~', true},
		{'+', false}, // standard base64, not I2P
		{'/', false}, // standard base64, not I2P
		{'=', false}, // padding
		{'!', false},
		{' ', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			got := isBase64Char(tt.char)
			if got != tt.want {
				t.Errorf("isBase64Char(%q) = %v, want %v", tt.char, got, tt.want)
			}
		})
	}
}

func TestNamingResponses(t *testing.T) {
	t.Run("namingOK", func(t *testing.T) {
		resp := namingOK("example.i2p", "base64dest")
		got := resp.String()
		if !strings.Contains(got, "NAMING REPLY") {
			t.Errorf("namingOK() = %q, want 'NAMING REPLY'", got)
		}
		if !strings.Contains(got, "RESULT=OK") {
			t.Errorf("namingOK() = %q, want 'RESULT=OK'", got)
		}
		if !strings.Contains(got, "NAME=example.i2p") {
			t.Errorf("namingOK() = %q, want 'NAME=example.i2p'", got)
		}
		if !strings.Contains(got, "VALUE=base64dest") {
			t.Errorf("namingOK() = %q, want 'VALUE=base64dest'", got)
		}
	})

	t.Run("namingKeyNotFound", func(t *testing.T) {
		resp := namingKeyNotFound("unknown.i2p")
		got := resp.String()
		if !strings.Contains(got, "RESULT=KEY_NOT_FOUND") {
			t.Errorf("namingKeyNotFound() = %q, want 'RESULT=KEY_NOT_FOUND'", got)
		}
		if !strings.Contains(got, "NAME=unknown.i2p") {
			t.Errorf("namingKeyNotFound() = %q, want 'NAME=unknown.i2p'", got)
		}
	})

	t.Run("namingInvalidKey", func(t *testing.T) {
		resp := namingInvalidKey("bad", "bad format")
		got := resp.String()
		if !strings.Contains(got, "RESULT=INVALID_KEY") {
			t.Errorf("namingInvalidKey() = %q, want 'RESULT=INVALID_KEY'", got)
		}
		if !strings.Contains(got, "NAME=bad") {
			t.Errorf("namingInvalidKey() = %q, want 'NAME=bad'", got)
		}
		if !strings.Contains(got, "MESSAGE=") {
			t.Errorf("namingInvalidKey() = %q, want 'MESSAGE='", got)
		}
	})

	t.Run("namingInvalidKey empty name", func(t *testing.T) {
		resp := namingInvalidKey("", "missing name")
		got := resp.String()
		if !strings.Contains(got, "RESULT=INVALID_KEY") {
			t.Errorf("namingInvalidKey() = %q, want 'RESULT=INVALID_KEY'", got)
		}
		// Should not contain NAME= when name is empty
		if strings.Contains(got, "NAME=") {
			t.Errorf("namingInvalidKey() = %q, should not contain 'NAME=' for empty name", got)
		}
	})
}

func TestNamingErr(t *testing.T) {
	err := &namingErr{msg: "test error"}
	if err.Error() != "test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error")
	}
}

// mockLeasesetProvider implements LeasesetLookupProvider for testing.
type mockLeasesetProvider struct {
	result *LeasesetLookupResult
	err    error
}

func (m *mockLeasesetProvider) LookupWithOptions(name string) (*LeasesetLookupResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestNamingHandler_HandleOptionsTrue(t *testing.T) {
	tests := []struct {
		name         string
		command      *protocol.Command
		provider     *mockLeasesetProvider
		wantResult   string
		wantName     string
		wantValue    bool
		wantOption   string // expected OPTION: in response
		wantNoOption string // should NOT contain this OPTION:
	}{
		{
			name: "OPTIONS=true with successful lookup and options",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "true",
				},
			},
			provider: &mockLeasesetProvider{
				result: &LeasesetLookupResult{
					Destination: "base64destdata",
					Options: []LeasesetOption{
						{Key: "_smtp._tcp", Value: "1 86400 0 0 25 mailserver.b32.i2p"},
					},
					Found: true,
				},
			},
			wantResult: protocol.ResultOK,
			wantName:   "example.i2p",
			wantValue:  true,
			wantOption: "OPTION:_smtp._tcp=",
		},
		{
			name: "OPTIONS=true with leaseset not found",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "unknown.i2p",
					"OPTIONS": "true",
				},
			},
			provider: &mockLeasesetProvider{
				result: &LeasesetLookupResult{
					Found: false,
				},
			},
			wantResult: protocol.ResultLeasesetNotFound,
			wantName:   "unknown.i2p",
		},
		{
			name: "OPTIONS=true without provider",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "true",
				},
			},
			provider:   nil, // no provider set
			wantResult: protocol.ResultI2PError,
			wantName:   "example.i2p",
		},
		{
			name: "OPTIONS=true with provider error",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "true",
				},
			},
			provider: &mockLeasesetProvider{
				err: &namingErr{msg: "network error"},
			},
			wantResult: protocol.ResultI2PError,
			wantName:   "example.i2p",
		},
		{
			name: "OPTIONS=true filters invalid option keys with equals",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "true",
				},
			},
			provider: &mockLeasesetProvider{
				result: &LeasesetLookupResult{
					Destination: "base64destdata",
					Options: []LeasesetOption{
						{Key: "valid_key", Value: "valid_value"},
						{Key: "invalid=key", Value: "should_be_filtered"},
					},
					Found: true,
				},
			},
			wantResult:   protocol.ResultOK,
			wantOption:   "OPTION:valid_key=",
			wantNoOption: "OPTION:invalid=key",
		},
		{
			name: "OPTIONS=true filters option values with newlines",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "true",
				},
			},
			provider: &mockLeasesetProvider{
				result: &LeasesetLookupResult{
					Destination: "base64destdata",
					Options: []LeasesetOption{
						{Key: "valid_key", Value: "valid_value"},
						{Key: "newline_value", Value: "has\nnewline"},
					},
					Found: true,
				},
			},
			wantResult:   protocol.ResultOK,
			wantOption:   "OPTION:valid_key=",
			wantNoOption: "OPTION:newline_value",
		},
		{
			name: "OPTIONS=yes is treated as true",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "yes",
				},
			},
			provider: &mockLeasesetProvider{
				result: &LeasesetLookupResult{
					Destination: "base64destdata",
					Found:       true,
				},
			},
			wantResult: protocol.ResultOK,
			wantValue:  true,
		},
		{
			name: "OPTIONS=1 is treated as true",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "1",
				},
			},
			provider: &mockLeasesetProvider{
				result: &LeasesetLookupResult{
					Destination: "base64destdata",
					Found:       true,
				},
			},
			wantResult: protocol.ResultOK,
			wantValue:  true,
		},
		{
			name: "OPTIONS=false uses standard lookup",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME":    "example.i2p",
					"OPTIONS": "false",
				},
			},
			wantResult: protocol.ResultKeyNotFound, // standard lookup, not implemented
			wantName:   "example.i2p",
		},
		{
			name: "No OPTIONS uses standard lookup",
			command: &protocol.Command{
				Verb:   "NAMING",
				Action: "LOOKUP",
				Options: map[string]string{
					"NAME": "example.i2p",
				},
			},
			wantResult: protocol.ResultKeyNotFound, // standard lookup, not implemented
			wantName:   "example.i2p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewNamingHandler(&mockManager{})
			if tt.provider != nil {
				handler.SetLeasesetProvider(tt.provider)
			}
			ctx := NewContext(&mockConn{}, nil)

			resp, err := handler.Handle(ctx, tt.command)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if resp == nil {
				t.Fatal("Handle() returned nil response")
			}

			respStr := resp.String()
			if !strings.Contains(respStr, "RESULT="+tt.wantResult) {
				t.Errorf("Handle() = %q, want RESULT=%s", respStr, tt.wantResult)
			}

			if tt.wantName != "" && !strings.Contains(respStr, "NAME="+tt.wantName) {
				t.Errorf("Handle() = %q, want NAME=%s", respStr, tt.wantName)
			}

			if tt.wantValue && !strings.Contains(respStr, "VALUE=") {
				t.Errorf("Handle() = %q, want VALUE=", respStr)
			}

			if tt.wantOption != "" && !strings.Contains(respStr, tt.wantOption) {
				t.Errorf("Handle() = %q, want %s", respStr, tt.wantOption)
			}

			if tt.wantNoOption != "" && strings.Contains(respStr, tt.wantNoOption) {
				t.Errorf("Handle() = %q, should NOT contain %s", respStr, tt.wantNoOption)
			}
		})
	}
}

func TestIsOptionsTrue(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"yes", true},
		{"YES", true},
		{"1", true},
		{"false", false},
		{"FALSE", false},
		{"no", false},
		{"0", false},
		{"", false},
		{"  true  ", true}, // with whitespace
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isOptionsTrue(tt.input)
			if got != tt.want {
				t.Errorf("isOptionsTrue(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidLeasesetOption(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  bool
	}{
		{"valid key-value", "_smtp._tcp", "1 86400 0 0 25 mail.b32.i2p", true},
		{"empty key", "", "value", false},
		{"key with equals", "key=bad", "value", false},
		{"key with newline", "key\n", "value", false},
		{"key with carriage return", "key\r", "value", false},
		{"value with newline", "key", "value\nline2", false},
		{"value with carriage return", "key", "value\rline2", false},
		{"empty value is valid", "key", "", true},
		{"value with spaces is valid", "key", "value with spaces", true},
		{"value with equals is valid", "key", "value=with=equals", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidLeasesetOption(tt.key, tt.value)
			if got != tt.want {
				t.Errorf("isValidLeasesetOption(%q, %q) = %v, want %v", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestNamingLeasesetNotFound(t *testing.T) {
	resp := namingLeasesetNotFound("example.i2p")
	got := resp.String()

	if !strings.Contains(got, "NAMING REPLY") {
		t.Errorf("namingLeasesetNotFound() = %q, want 'NAMING REPLY'", got)
	}
	if !strings.Contains(got, "RESULT=LEASESET_NOT_FOUND") {
		t.Errorf("namingLeasesetNotFound() = %q, want 'RESULT=LEASESET_NOT_FOUND'", got)
	}
	if !strings.Contains(got, "NAME=example.i2p") {
		t.Errorf("namingLeasesetNotFound() = %q, want 'NAME=example.i2p'", got)
	}
}

func TestNamingI2PError(t *testing.T) {
	resp := namingI2PError("example.i2p", "test error message")
	got := resp.String()

	if !strings.Contains(got, "NAMING REPLY") {
		t.Errorf("namingI2PError() = %q, want 'NAMING REPLY'", got)
	}
	if !strings.Contains(got, "RESULT=I2P_ERROR") {
		t.Errorf("namingI2PError() = %q, want 'RESULT=I2P_ERROR'", got)
	}
	if !strings.Contains(got, "NAME=example.i2p") {
		t.Errorf("namingI2PError() = %q, want 'NAME=example.i2p'", got)
	}
	if !strings.Contains(got, "MESSAGE=") {
		t.Errorf("namingI2PError() = %q, want 'MESSAGE='", got)
	}
}

func TestNamingOKWithOptions(t *testing.T) {
	options := []LeasesetOption{
		{Key: "_smtp._tcp", Value: "1 86400 0 0 25 mail.b32.i2p"},
		{Key: "_http._tcp", Value: "1 86400 0 0 80 web.b32.i2p"},
	}
	resp := namingOKWithOptions("example.i2p", "base64dest", options)
	got := resp.String()

	if !strings.Contains(got, "RESULT=OK") {
		t.Errorf("namingOKWithOptions() = %q, want 'RESULT=OK'", got)
	}
	if !strings.Contains(got, "NAME=example.i2p") {
		t.Errorf("namingOKWithOptions() = %q, want 'NAME=example.i2p'", got)
	}
	if !strings.Contains(got, "VALUE=base64dest") {
		t.Errorf("namingOKWithOptions() = %q, want 'VALUE=base64dest'", got)
	}
	if !strings.Contains(got, "OPTION:_smtp._tcp=") {
		t.Errorf("namingOKWithOptions() = %q, want 'OPTION:_smtp._tcp='", got)
	}
	if !strings.Contains(got, "OPTION:_http._tcp=") {
		t.Errorf("namingOKWithOptions() = %q, want 'OPTION:_http._tcp='", got)
	}
}

func TestNamingHandler_SetLeasesetProvider(t *testing.T) {
	handler := NewNamingHandler(&mockManager{})

	// Initially nil
	if handler.leasesetProvider != nil {
		t.Error("expected leasesetProvider to be nil initially")
	}

	// Set provider
	provider := &mockLeasesetProvider{}
	handler.SetLeasesetProvider(provider)

	if handler.leasesetProvider != provider {
		t.Error("expected leasesetProvider to be set")
	}
}

func TestNamingHandler_HandleOptionsWithBase64Destination(t *testing.T) {
	// Test that NAME can be a full base64 destination when OPTIONS=true
	// Per SAM API 0.9.66, this is allowed
	handler := NewNamingHandler(&mockManager{})
	handler.SetLeasesetProvider(&mockLeasesetProvider{
		result: &LeasesetLookupResult{
			Destination: strings.Repeat("A", 516),
			Found:       true,
		},
	})

	ctx := NewContext(&mockConn{}, nil)
	cmd := &protocol.Command{
		Verb:   "NAMING",
		Action: "LOOKUP",
		Options: map[string]string{
			"NAME":    strings.Repeat("A", 516), // base64 destination
			"OPTIONS": "true",
		},
	}

	resp, err := handler.Handle(ctx, cmd)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	respStr := resp.String()
	if !strings.Contains(respStr, "RESULT=OK") {
		t.Errorf("Handle() = %q, want RESULT=OK", respStr)
	}
}
