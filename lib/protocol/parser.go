package protocol

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Parser errors
var (
	ErrEmptyCommand      = errors.New("empty command")
	ErrInvalidUTF8       = errors.New("command contains invalid UTF-8")
	ErrUnterminatedQuote = errors.New("unterminated quoted value")
	ErrInvalidEscape     = errors.New("invalid escape sequence")
)

// Parser tokenizes SAM protocol commands.
// Per SAMv3.md, commands follow the format:
//
//	VERB [ACTION] [KEY=VALUE]...
//
// Parser handles UTF-8 encoding (SAM 3.2+), quoted values with escapes,
// and empty option values.
type Parser struct {
	// CaseInsensitive enables case-insensitive verb/action matching.
	// Per SAM spec, this is recommended but not required.
	CaseInsensitive bool
}

// NewParser creates a new parser with default settings.
// Case-insensitive matching is enabled by default per SAM spec recommendation.
func NewParser() *Parser {
	return &Parser{
		CaseInsensitive: true,
	}
}

// Parse parses a SAM command line into a Command struct.
// The input should be a single line without the trailing newline.
func (p *Parser) Parse(line string) (*Command, error) {
	line = strings.TrimRight(line, "\r\n")

	if err := p.validateLine(line); err != nil {
		return nil, err
	}

	tokens, err := p.tokenize(line)
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return nil, ErrEmptyCommand
	}

	return p.buildCommand(tokens, line)
}

// validateLine checks if the line is valid UTF-8.
func (p *Parser) validateLine(line string) error {
	if !utf8.ValidString(line) {
		return ErrInvalidUTF8
	}
	return nil
}

// buildCommand constructs a Command from tokens.
func (p *Parser) buildCommand(tokens []string, raw string) (*Command, error) {
	cmd := &Command{
		Options: make(map[string]string),
		Raw:     raw,
	}

	cmd.Verb = p.normalizeToken(tokens[0])
	tokenIdx := p.extractAction(cmd, tokens)
	p.extractOptions(cmd, tokens, tokenIdx)

	return cmd, nil
}

// normalizeToken normalizes a token based on case sensitivity setting.
func (p *Parser) normalizeToken(token string) string {
	if p.CaseInsensitive {
		return strings.ToUpper(token)
	}
	return token
}

// extractAction extracts the action from tokens if present.
// Returns the index to continue processing from.
func (p *Parser) extractAction(cmd *Command, tokens []string) int {
	if len(tokens) < 2 {
		return 1
	}

	action := tokens[1]
	if strings.Contains(action, "=") {
		return 1
	}

	if p.isAction(cmd.Verb, action) {
		cmd.Action = p.normalizeToken(action)
		return 2
	}
	return 1
}

// extractOptions parses key=value pairs from remaining tokens.
func (p *Parser) extractOptions(cmd *Command, tokens []string, startIdx int) {
	for i := startIdx; i < len(tokens); i++ {
		key, value := p.parseKeyValue(tokens[i])
		if key != "" {
			cmd.Options[key] = value
		}
	}
}

// tokenize splits a command line into tokens, handling quoted values.
func (p *Parser) tokenize(line string) ([]string, error) {
	t := &tokenizer{}
	return t.tokenize(line)
}

// tokenizer holds state during tokenization.
type tokenizer struct {
	tokens  []string
	current strings.Builder
	inQuote bool
	escaped bool
}

// tokenize splits a command line into tokens.
func (t *tokenizer) tokenize(line string) ([]string, error) {
	for i := 0; i < len(line); i++ {
		if err := t.processChar(line[i]); err != nil {
			return nil, err
		}
	}

	if t.inQuote {
		return nil, ErrUnterminatedQuote
	}

	t.finishToken()
	return t.tokens, nil
}

// processChar processes a single character during tokenization.
func (t *tokenizer) processChar(ch byte) error {
	if t.escaped {
		return t.processEscaped(ch)
	}
	return t.processNormal(ch)
}

// processEscaped handles an escaped character.
func (t *tokenizer) processEscaped(ch byte) error {
	switch ch {
	case '"', '\\':
		t.current.WriteByte(ch)
	default:
		t.current.WriteByte('\\')
		t.current.WriteByte(ch)
	}
	t.escaped = false
	return nil
}

// processNormal handles a non-escaped character.
func (t *tokenizer) processNormal(ch byte) error {
	switch ch {
	case '\\':
		if t.inQuote {
			t.escaped = true
		} else {
			t.current.WriteByte(ch)
		}
	case '"':
		t.inQuote = !t.inQuote
		t.current.WriteByte(ch)
	case ' ', '\t':
		if t.inQuote {
			t.current.WriteByte(ch)
		} else {
			t.finishToken()
		}
	default:
		t.current.WriteByte(ch)
	}
	return nil
}

// finishToken adds the current token to the list and resets.
func (t *tokenizer) finishToken() {
	if t.current.Len() > 0 {
		t.tokens = append(t.tokens, t.current.String())
		t.current.Reset()
	}
}

// parseKeyValue parses a token as a key=value pair.
// Handles empty values per SAM 3.2 (KEY, KEY=, KEY="").
func (p *Parser) parseKeyValue(token string) (key, value string) {
	// Find the first '=' that's not inside quotes
	eqIdx := -1
	inQuote := false
	for i := 0; i < len(token); i++ {
		if token[i] == '"' {
			inQuote = !inQuote
		} else if token[i] == '=' && !inQuote {
			eqIdx = i
			break
		}
	}

	if eqIdx < 0 {
		// No '=' found - empty value (KEY format per SAM 3.2)
		return token, ""
	}

	key = token[:eqIdx]
	value = token[eqIdx+1:]

	// Strip quotes from value if present
	value = stripQuotes(value)

	return key, value
}

// stripQuotes removes surrounding quotes and unescapes the value.
func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		// Unescape
		s = strings.ReplaceAll(s, "\\\"", "\"")
		s = strings.ReplaceAll(s, "\\\\", "\\")
	}
	return s
}

// isAction determines if a token should be treated as an action.
// Per SAM spec, some commands like PING don't have actions.
func (p *Parser) isAction(verb, token string) bool {
	// Normalize for comparison
	v := strings.ToUpper(verb)
	t := strings.ToUpper(token)

	// Known verb+action combinations
	switch v {
	case VerbHello:
		return t == ActionVersion
	case VerbSession:
		return t == ActionCreate || t == ActionAdd || t == ActionRemove
	case VerbStream:
		return t == ActionConnect || t == ActionAccept || t == ActionForward
	case VerbDatagram, VerbRaw:
		return t == ActionSend || t == ActionReceived
	case VerbDest:
		return t == ActionGenerate || t == ActionReply
	case VerbNaming:
		return t == ActionLookup
	case VerbAuth:
		return t == ActionEnable || t == ActionDisable || t == ActionAdd || t == ActionRemove
	case VerbPing, VerbPong, VerbQuit, VerbStop, VerbExit, VerbHelp:
		// These commands don't have actions
		return false
	default:
		// For unknown verbs, treat it as action if it doesn't contain '='
		return !strings.Contains(token, "=")
	}
}

// ParseLine is a convenience function that parses a line using default settings.
func ParseLine(line string) (*Command, error) {
	return NewParser().Parse(line)
}

// MustParse parses a line and panics on error. For testing only.
func MustParse(line string) *Command {
	cmd, err := ParseLine(line)
	if err != nil {
		panic(fmt.Sprintf("failed to parse command: %v", err))
	}
	return cmd
}
