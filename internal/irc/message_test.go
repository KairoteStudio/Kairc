package irc

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    Message
		wantErr error
	}{
		{name: "command", line: "PING :hello world", want: Message{Command: "PING", Params: []string{"hello world"}}},
		{name: "prefix", line: ":nick!u@h PRIVMSG #room :hello", want: Message{Prefix: "nick!u@h", Command: "PRIVMSG", Params: []string{"#room", "hello"}}},
		{name: "normalizes command", line: "nick alice", want: Message{Command: "NICK", Params: []string{"alice"}}},
		{name: "empty trailing", line: "CAP * LS :", want: Message{Command: "CAP", Params: []string{"*", "LS", ""}}},
		{name: "empty", line: "   ", wantErr: ErrEmptyMessage},
		{name: "newline", line: "PING x\nQUIT", wantErr: ErrInvalidLine},
		{name: "too long", line: strings.Repeat("x", MaxPayloadBytes+1), wantErr: ErrLineTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.line)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.Prefix != tt.want.Prefix || got.Command != tt.want.Command || strings.Join(got.Params, "\x00") != strings.Join(tt.want.Params, "\x00") {
				t.Fatalf("Parse() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestFormatRoundTrip(t *testing.T) {
	wire := Format("alice!a@example", "privmsg", "#lobby", "hello world")
	if wire != ":alice!a@example PRIVMSG #lobby :hello world\r\n" {
		t.Fatalf("Format() = %q", wire)
	}
	got, err := Parse(strings.TrimSuffix(wire, "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "PRIVMSG" || len(got.Params) != 2 || got.Params[1] != "hello world" {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestFormatRejectsInjection(t *testing.T) {
	if got := Format("", "PRIVMSG", "#room", "hello\r\nOPER root"); got != "" {
		t.Fatalf("Format accepted CRLF injection: %q", got)
	}
}
