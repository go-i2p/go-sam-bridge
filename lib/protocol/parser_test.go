package protocol

import (
	"errors"
	"testing"
)

func TestParser_Parse_BasicCommands(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantVerb   string
		wantAction string
		wantOpts   map[string]string
	}{
		{
			name:       "HELLO VERSION",
			input:      "HELLO VERSION MIN=3.0 MAX=3.3",
			wantVerb:   "HELLO",
			wantAction: "VERSION",
			wantOpts:   map[string]string{"MIN": "3.0", "MAX": "3.3"},
		},
		{
			name:       "SESSION CREATE",
			input:      "SESSION CREATE STYLE=STREAM ID=test123 DESTINATION=TRANSIENT",
			wantVerb:   "SESSION",
			wantAction: "CREATE",
			wantOpts:   map[string]string{"STYLE": "STREAM", "ID": "test123", "DESTINATION": "TRANSIENT"},
		},
		{
			name:       "STREAM CONNECT",
			input:      "STREAM CONNECT ID=test123 DESTINATION=abc123 SILENT=false",
			wantVerb:   "STREAM",
			wantAction: "CONNECT",
			wantOpts:   map[string]string{"ID": "test123", "DESTINATION": "abc123", "SILENT": "false"},
		},
		{
			name:       "DEST GENERATE",
			input:      "DEST GENERATE SIGNATURE_TYPE=7",
			wantVerb:   "DEST",
			wantAction: "GENERATE",
			wantOpts:   map[string]string{"SIGNATURE_TYPE": "7"},
		},
		{
			name:       "NAMING LOOKUP",
			input:      "NAMING LOOKUP NAME=test.i2p",
			wantVerb:   "NAMING",
			wantAction: "LOOKUP",
			wantOpts:   map[string]string{"NAME": "test.i2p"},
		},
		{
			name:       "PING with data",
			input:      "PING hello world",
			wantVerb:   "PING",
			wantAction: "",
			wantOpts:   map[string]string{},
		},
		{
			name:       "PING alone",
			input:      "PING",
			wantVerb:   "PING",
			wantAction: "",
			wantOpts:   map[string]string{},
		},
		{
			name:       "QUIT",
			input:      "QUIT",
			wantVerb:   "QUIT",
			wantAction: "",
			wantOpts:   map[string]string{},
		},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if cmd.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", cmd.Verb, tt.wantVerb)
			}
			if cmd.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", cmd.Action, tt.wantAction)
			}

			for k, v := range tt.wantOpts {
				if cmd.Get(k) != v {
					t.Errorf("Option[%q] = %q, want %q", k, cmd.Get(k), v)
				}
			}
		})
	}
}

func TestParser_Parse_CaseInsensitive(t *testing.T) {
	parser := NewParser()
	parser.CaseInsensitive = true

	tests := []struct {
		input      string
		wantVerb   string
		wantAction string
	}{
		{"hello version", "HELLO", "VERSION"},
		{"Hello Version", "HELLO", "VERSION"},
		{"HELLO VERSION", "HELLO", "VERSION"},
		{"session create", "SESSION", "CREATE"},
		{"ping", "PING", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cmd, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if cmd.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", cmd.Verb, tt.wantVerb)
			}
			if cmd.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", cmd.Action, tt.wantAction)
			}
		})
	}
}

func TestParser_Parse_QuotedValues(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		input    string
		key      string
		expected string
	}{
		{
			name:     "quoted value with space",
			input:    `SESSION CREATE ID="my session"`,
			key:      "ID",
			expected: "my session",
		},
		{
			name:     "quoted empty value",
			input:    `SESSION CREATE ID=""`,
			key:      "ID",
			expected: "",
		},
		{
			name:     "escaped quote in value",
			input:    `SESSION CREATE ID="say \"hello\""`,
			key:      "ID",
			expected: `say "hello"`,
		},
		{
			name:     "escaped backslash",
			input:    `SESSION CREATE PATH="C:\\test\\path"`,
			key:      "PATH",
			expected: `C:\test\path`,
		},
		{
			name:     "mixed escaped",
			input:    `SESSION CREATE MSG="line1\\nline2\""`,
			key:      "MSG",
			expected: `line1\nline2"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			got := cmd.Get(tt.key)
			if got != tt.expected {
				t.Errorf("Get(%q) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestParser_Parse_EmptyValues(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		input    string
		key      string
		hasKey   bool
		expected string
	}{
		{
			name:     "KEY (no equals)",
			input:    "SESSION CREATE SILENT",
			key:      "SILENT",
			hasKey:   true,
			expected: "",
		},
		{
			name:     "KEY= (equals, no value)",
			input:    "SESSION CREATE SILENT=",
			key:      "SILENT",
			hasKey:   true,
			expected: "",
		},
		{
			name:     "KEY=\"\" (quoted empty)",
			input:    `SESSION CREATE SILENT=""`,
			key:      "SILENT",
			hasKey:   true,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if cmd.Has(tt.key) != tt.hasKey {
				t.Errorf("Has(%q) = %v, want %v", tt.key, cmd.Has(tt.key), tt.hasKey)
			}

			if tt.hasKey && cmd.Get(tt.key) != tt.expected {
				t.Errorf("Get(%q) = %q, want %q", tt.key, cmd.Get(tt.key), tt.expected)
			}
		})
	}
}

func TestParser_Parse_MultipleSpaces(t *testing.T) {
	parser := NewParser()

	// SAM 3.2 allows multiple spaces between tokens
	input := "HELLO   VERSION    MIN=3.0    MAX=3.3"
	cmd, err := parser.Parse(input)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if cmd.Verb != "HELLO" {
		t.Errorf("Verb = %q, want HELLO", cmd.Verb)
	}
	if cmd.Action != "VERSION" {
		t.Errorf("Action = %q, want VERSION", cmd.Action)
	}
	if cmd.Get("MIN") != "3.0" {
		t.Errorf("MIN = %q, want 3.0", cmd.Get("MIN"))
	}
	if cmd.Get("MAX") != "3.3" {
		t.Errorf("MAX = %q, want 3.3", cmd.Get("MAX"))
	}
}

func TestParser_Parse_NewlineHandling(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name  string
		input string
	}{
		{"with newline", "HELLO VERSION\n"},
		{"with crlf", "HELLO VERSION\r\n"},
		{"without newline", "HELLO VERSION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if cmd.Verb != "HELLO" {
				t.Errorf("Verb = %q, want HELLO", cmd.Verb)
			}
		})
	}
}

func TestParser_Parse_Errors(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name      string
		input     string
		wantError error
	}{
		{
			name:      "empty command",
			input:     "",
			wantError: ErrEmptyCommand,
		},
		{
			name:      "whitespace only",
			input:     "   ",
			wantError: ErrEmptyCommand,
		},
		{
			name:      "unterminated quote at end",
			input:     `SESSION CREATE ID="unclosed`,
			wantError: ErrUnterminatedQuote,
		},
		{
			name:      "stray quote at end of unquoted value",
			input:     `SESSION CREATE ID=value"`,
			wantError: ErrUnterminatedQuote,
		},
		{
			name:      "stray quote in middle of value",
			input:     `SESSION CREATE ID=val"ue`,
			wantError: ErrUnterminatedQuote,
		},
		{
			name:      "unbalanced quotes multiple",
			input:     `SESSION CREATE ID="test" NAME="unclosed`,
			wantError: ErrUnterminatedQuote,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.Parse(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, tt.wantError) {
				t.Errorf("error = %v, want %v", err, tt.wantError)
			}
		})
	}
}

func TestParser_Parse_RawPreserved(t *testing.T) {
	parser := NewParser()

	input := "HELLO VERSION MIN=3.0"
	cmd, err := parser.Parse(input)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if cmd.Raw != input {
		t.Errorf("Raw = %q, want %q", cmd.Raw, input)
	}
}

func TestParser_Parse_UTF8(t *testing.T) {
	parser := NewParser()

	// UTF-8 is valid per SAM 3.2
	input := `SESSION CREATE ID="日本語" NAME="тест"`
	cmd, err := parser.Parse(input)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if cmd.Get("ID") != "日本語" {
		t.Errorf("ID = %q, want 日本語", cmd.Get("ID"))
	}
	if cmd.Get("NAME") != "тест" {
		t.Errorf("NAME = %q, want тест", cmd.Get("NAME"))
	}
}

func TestParseLine(t *testing.T) {
	cmd, err := ParseLine("HELLO VERSION")
	if err != nil {
		t.Fatalf("ParseLine error: %v", err)
	}
	if cmd.Verb != "HELLO" {
		t.Errorf("Verb = %q, want HELLO", cmd.Verb)
	}
}

func TestMustParse(t *testing.T) {
	cmd := MustParse("HELLO VERSION")
	if cmd.Verb != "HELLO" {
		t.Errorf("Verb = %q, want HELLO", cmd.Verb)
	}
}

func TestMustParse_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid command")
		}
	}()

	MustParse("") // should panic
}
