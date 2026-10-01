// Package irc implements the small, wire-level portion of the IRC protocol
// used by Kairc. It deliberately has no knowledge of connections or rooms.
package irc

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// MaxPayloadBytes is the largest IRC line excluding the terminating CRLF.
// RFC 2812 limits a complete message to 512 bytes.
const MaxPayloadBytes = 510

var (
	ErrEmptyMessage = errors.New("irc: empty message")
	ErrLineTooLong  = errors.New("irc: line exceeds 512-byte wire limit")
	ErrInvalidLine  = errors.New("irc: line contains a forbidden byte")
	ErrTooManyArgs  = errors.New("irc: message has more than 15 parameters")
)

// Message is one parsed IRC protocol message.
type Message struct {
	Prefix  string
	Command string
	Params  []string
}

// Parse parses one IRC line. line must not contain the trailing CRLF.
func Parse(line string) (Message, error) {
	var msg Message

	if len(line) > MaxPayloadBytes {
		return msg, ErrLineTooLong
	}
	if strings.ContainsAny(line, "\x00\r\n") {
		return msg, ErrInvalidLine
	}

	rest := strings.TrimLeft(line, " ")
	if rest == "" {
		return msg, ErrEmptyMessage
	}

	if rest[0] == ':' {
		space := strings.IndexByte(rest, ' ')
		if space < 0 || space == 1 {
			return msg, ErrInvalidLine
		}
		msg.Prefix = rest[1:space]
		rest = strings.TrimLeft(rest[space+1:], " ")
	}

	space := strings.IndexByte(rest, ' ')
	if space < 0 {
		msg.Command = strings.ToUpper(rest)
		rest = ""
	} else {
		msg.Command = strings.ToUpper(rest[:space])
		rest = strings.TrimLeft(rest[space+1:], " ")
	}
	if !validCommand(msg.Command) {
		return Message{}, ErrInvalidLine
	}

	for rest != "" {
		if len(msg.Params) == 15 {
			return Message{}, ErrTooManyArgs
		}
		if rest[0] == ':' {
			msg.Params = append(msg.Params, rest[1:])
			break
		}
		space = strings.IndexByte(rest, ' ')
		if space < 0 {
			msg.Params = append(msg.Params, rest)
			break
		}
		msg.Params = append(msg.Params, rest[:space])
		rest = strings.TrimLeft(rest[space+1:], " ")
	}

	return msg, nil
}

func validCommand(command string) bool {
	if command == "" {
		return false
	}
	if len(command) == 3 {
		allDigits := true
		for _, r := range command {
			allDigits = allDigits && r >= '0' && r <= '9'
		}
		if allDigits {
			return true
		}
	}
	for _, r := range command {
		if r > unicode.MaxASCII || !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// Format creates a valid IRC wire message, including its terminating CRLF.
// It returns an empty string if command or any field contains unsafe bytes.
func Format(prefix, command string, params ...string) string {
	command = strings.ToUpper(command)
	if !validCommand(command) || strings.ContainsAny(prefix, "\x00\r\n ") || len(params) > 15 {
		return ""
	}

	var b strings.Builder
	if prefix != "" {
		b.WriteByte(':')
		b.WriteString(prefix)
		b.WriteByte(' ')
	}
	b.WriteString(command)
	for i, param := range params {
		if strings.ContainsAny(param, "\x00\r\n") {
			return ""
		}
		b.WriteByte(' ')
		last := i == len(params)-1
		if last && (param == "" || strings.ContainsRune(param, ' ') || strings.HasPrefix(param, ":")) {
			b.WriteByte(':')
			b.WriteString(param)
			continue
		}
		if param == "" || strings.ContainsRune(param, ' ') || strings.HasPrefix(param, ":") {
			return ""
		}
		b.WriteString(param)
	}
	if b.Len() > MaxPayloadBytes {
		return ""
	}
	b.WriteString("\r\n")
	return b.String()
}

// Numeric formats a three-digit server response.
func Numeric(prefix string, code int, params ...string) string {
	return Format(prefix, fmt.Sprintf("%03d", code), params...)
}
