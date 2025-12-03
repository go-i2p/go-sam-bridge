package protocol

import (
	"strings"
	"testing"
)

func TestResponse_String_Simple(t *testing.T) {
	r := NewResponse("PONG")
	got := r.String()
	want := "PONG\n"

	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestResponse_String_WithAction(t *testing.T) {
	r := NewResponse("HELLO").WithAction("REPLY").WithResult("OK")
	got := r.String()

	if !strings.HasPrefix(got, "HELLO REPLY ") {
		t.Errorf("String() = %q, should start with 'HELLO REPLY '", got)
	}

	if !strings.Contains(got, "RESULT=OK") {
		t.Errorf("String() = %q, should contain 'RESULT=OK'", got)
	}
}

func TestResponse_WithOptions(t *testing.T) {
	r := NewResponse("SESSION").
		WithAction("STATUS").
		WithResult("OK").
		With("DESTINATION", "testdest123")

	got := r.String()

	if !strings.Contains(got, "RESULT=OK") {
		t.Errorf("String() should contain RESULT=OK")
	}

	if !strings.Contains(got, "DESTINATION=testdest123") {
		t.Errorf("String() should contain DESTINATION=testdest123")
	}
}

func TestResponse_QuotedValue(t *testing.T) {
	r := NewResponse("NAMING").
		WithAction("REPLY").
		WithResult("OK").
		With("NAME", "test with spaces.i2p")

	got := r.String()

	if !strings.Contains(got, "NAME=\"test with spaces.i2p\"") {
		t.Errorf("String() = %q, should quote value with spaces", got)
	}
}

func TestResponse_EscapedQuote(t *testing.T) {
	r := NewResponse("TEST").
		WithResult("OK").
		With("VALUE", "test\"quote")

	got := r.String()

	if !strings.Contains(got, "VALUE=\"test\\\"quote\"") {
		t.Errorf("String() = %q, should escape quote in value", got)
	}
}

func TestResponse_EscapedBackslash(t *testing.T) {
	r := NewResponse("TEST").
		WithResult("OK").
		With("PATH", "C:\\test\\path")

	got := r.String()

	if !strings.Contains(got, "PATH=\"C:\\\\test\\\\path\"") {
		t.Errorf("String() = %q, should escape backslashes", got)
	}
}

func TestResponse_WithMessage(t *testing.T) {
	r := NewResponse("SESSION").
		WithAction("STATUS").
		WithResult("I2P_ERROR").
		WithMessage("Connection failed")

	got := r.String()

	if !strings.Contains(got, "MESSAGE=\"Connection failed\"") {
		t.Errorf("String() = %q, should contain quoted message", got)
	}
}

func TestHelloReply_OK(t *testing.T) {
	r := HelloReply("OK", "3.1")
	got := r.String()

	if !strings.HasPrefix(got, "HELLO REPLY ") {
		t.Errorf("HelloReply() should start with 'HELLO REPLY '")
	}

	if !strings.Contains(got, "RESULT=OK") {
		t.Errorf("HelloReply() should contain RESULT=OK")
	}

	if !strings.Contains(got, "VERSION=3.1") {
		t.Errorf("HelloReply() should contain VERSION=3.1")
	}
}

func TestHelloReply_NoVersion(t *testing.T) {
	r := HelloReply("NOVERSION", "")
	got := r.String()

	if !strings.Contains(got, "RESULT=NOVERSION") {
		t.Errorf("HelloReply() should contain RESULT=NOVERSION")
	}

	if strings.Contains(got, "VERSION=") {
		t.Errorf("HelloReply() should not contain VERSION when empty")
	}
}

func TestSessionStatus(t *testing.T) {
	tests := []struct {
		name   string
		result string
		want   string
	}{
		{"OK", "OK", "SESSION STATUS RESULT=OK\n"},
		{"DuplicatedID", "DUPLICATED_ID", "SESSION STATUS RESULT=DUPLICATED_ID\n"},
		{"InvalidKey", "INVALID_KEY", "SESSION STATUS RESULT=INVALID_KEY\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := SessionStatus(tt.result)
			got := r.String()

			if got != tt.want {
				t.Errorf("SessionStatus(%q) = %q, want %q", tt.result, got, tt.want)
			}
		})
	}
}

func TestStreamStatus(t *testing.T) {
	r := StreamStatus("OK")
	got := r.String()
	want := "STREAM STATUS RESULT=OK\n"

	if got != want {
		t.Errorf("StreamStatus() = %q, want %q", got, want)
	}
}

func TestDestReply(t *testing.T) {
	pubKey := "AAAA" + strings.Repeat("A", 512)
	privKey := "BBBB" + strings.Repeat("B", 512)

	r := DestReply(pubKey, privKey)
	got := r.String()

	if !strings.HasPrefix(got, "DEST REPLY ") {
		t.Errorf("DestReply() should start with 'DEST REPLY '")
	}

	if !strings.Contains(got, "RESULT=OK") {
		t.Errorf("DestReply() should contain RESULT=OK")
	}

	if !strings.Contains(got, "PUB="+pubKey) {
		t.Errorf("DestReply() should contain public key")
	}

	if !strings.Contains(got, "PRIV="+privKey) {
		t.Errorf("DestReply() should contain private key")
	}
}

func TestNamingReply(t *testing.T) {
	tests := []struct {
		name       string
		result     string
		lookupName string
		wantResult string
		wantName   bool
	}{
		{"OK", "OK", "example.i2p", "RESULT=OK", true},
		{"NotFound", "KEY_NOT_FOUND", "missing.i2p", "RESULT=KEY_NOT_FOUND", true},
		{"InvalidKey", "INVALID_KEY", "", "RESULT=INVALID_KEY", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NamingReply(tt.result, tt.lookupName)
			got := r.String()

			if !strings.Contains(got, tt.wantResult) {
				t.Errorf("NamingReply() should contain %s", tt.wantResult)
			}

			if tt.wantName && tt.lookupName != "" {
				if !strings.Contains(got, "NAME="+tt.lookupName) {
					t.Errorf("NamingReply() should contain NAME=%s", tt.lookupName)
				}
			}
		})
	}
}

func TestDatagramReceived(t *testing.T) {
	r := DatagramReceived(1024)
	got := r.String()

	if !strings.Contains(got, "DATAGRAM RECEIVED") {
		t.Errorf("DatagramReceived() should start with 'DATAGRAM RECEIVED'")
	}

	if !strings.Contains(got, "RESULT=OK") {
		t.Errorf("DatagramReceived() should contain RESULT=OK")
	}

	if !strings.Contains(got, "SIZE=1024") {
		t.Errorf("DatagramReceived() should contain SIZE=1024")
	}
}

func TestRawReceived(t *testing.T) {
	r := RawReceived(2048)
	got := r.String()

	if !strings.Contains(got, "RAW RECEIVED") {
		t.Errorf("RawReceived() should start with 'RAW RECEIVED'")
	}

	if !strings.Contains(got, "SIZE=2048") {
		t.Errorf("RawReceived() should contain SIZE=2048")
	}
}

func TestPong(t *testing.T) {
	r := Pong()
	got := r.String()
	want := "PONG\n"

	if got != want {
		t.Errorf("Pong() = %q, want %q", got, want)
	}
}

func TestErrorResponse(t *testing.T) {
	tests := []struct {
		name    string
		verb    string
		action  string
		result  string
		message string
	}{
		{"SessionError", "SESSION", "STATUS", "I2P_ERROR", "Tunnel build failed"},
		{"HelloError", "HELLO", "REPLY", "I2P_ERROR", "Router not ready"},
		{"NamingError", "NAMING", "REPLY", "KEY_NOT_FOUND", "Destination not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ErrorResponse(tt.verb, tt.action, tt.result, tt.message)
			got := r.String()

			if !strings.Contains(got, tt.verb) {
				t.Errorf("ErrorResponse() should contain verb %s", tt.verb)
			}

			if tt.action != "" && !strings.Contains(got, tt.action) {
				t.Errorf("ErrorResponse() should contain action %s", tt.action)
			}

			if !strings.Contains(got, "RESULT="+tt.result) {
				t.Errorf("ErrorResponse() should contain RESULT=%s", tt.result)
			}

			if !strings.Contains(got, "MESSAGE=") {
				t.Errorf("ErrorResponse() should contain MESSAGE field")
			}
		})
	}
}

func TestResponse_Bytes(t *testing.T) {
	r := HelloReply("OK", "3.1")
	bytes := r.Bytes()

	if len(bytes) == 0 {
		t.Error("Bytes() should not be empty")
	}

	// Should be UTF-8 encoded
	str := string(bytes)
	if !strings.Contains(str, "HELLO REPLY") {
		t.Errorf("Bytes() should contain 'HELLO REPLY'")
	}
}

func TestFormatOption_NoQuoting(t *testing.T) {
	tests := []struct {
		key   string
		value string
		want  string
	}{
		{"RESULT", "OK", "RESULT=OK"},
		{"VERSION", "3.1", "VERSION=3.1"},
		{"PORT", "12345", "PORT=12345"},
	}

	for _, tt := range tests {
		got := formatOption(tt.key, tt.value)
		if got != tt.want {
			t.Errorf("formatOption(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.want)
		}
	}
}

func TestFormatOption_WithQuoting(t *testing.T) {
	tests := []struct {
		key   string
		value string
		want  string
	}{
		{"MESSAGE", "test message", "MESSAGE=\"test message\""},
		{"NAME", "test.i2p", "NAME=test.i2p"},
		{"VALUE", "key=value", "VALUE=\"key=value\""},
		{"PATH", "test\\path", "PATH=\"test\\\\path\""},
		{"QUOTE", "say \"hi\"", "QUOTE=\"say \\\"hi\\\"\""},
	}

	for _, tt := range tests {
		got := formatOption(tt.key, tt.value)
		if got != tt.want {
			t.Errorf("formatOption(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.want)
		}
	}
}

func TestResponse_ChainedCalls(t *testing.T) {
	r := NewResponse("SESSION").
		WithAction("STATUS").
		WithResult("OK").
		With("DESTINATION", "dest123").
		With("STYLE", "STREAM").
		WithMessage("Session created successfully")

	got := r.String()

	expectedParts := []string{
		"SESSION STATUS",
		"RESULT=OK",
		"DESTINATION=dest123",
		"STYLE=STREAM",
		"MESSAGE=\"Session created successfully\"",
	}

	for _, part := range expectedParts {
		if !strings.Contains(got, part) {
			t.Errorf("String() should contain %q", part)
		}
	}
}
