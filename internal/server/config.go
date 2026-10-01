package server

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const Version = "0.1.0-dev"

// Config contains the protocol limits and public identity of one Kairc node.
type Config struct {
	Name                string
	Network             string
	MOTD                string
	MaxClients          int
	SendQueue           int
	MessagesPerSecond   float64
	MessageBurst        int
	RegistrationTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		Name:                "irc.kairote.local",
		Network:             "KairoteNet",
		MOTD:                "Welcome to Kairc — small rooms, open protocols, human conversations.",
		MaxClients:          1024,
		SendQueue:           256,
		MessagesPerSecond:   8,
		MessageBurst:        24,
		RegistrationTimeout: 30 * time.Second,
	}
}

func (c Config) validate() error {
	if err := validateToken("server name", c.Name, 128); err != nil {
		return err
	}
	if err := validateToken("network name", c.Network, 32); err != nil {
		return err
	}
	if c.MaxClients < 1 || c.SendQueue < 1 {
		return errors.New("max clients and send queue must be positive")
	}
	if c.MessagesPerSecond <= 0 || math.IsNaN(c.MessagesPerSecond) || math.IsInf(c.MessagesPerSecond, 0) || c.MessageBurst < 1 {
		return errors.New("rate limit and burst must be positive")
	}
	if c.RegistrationTimeout <= 0 {
		return errors.New("registration timeout must be positive")
	}
	for _, line := range strings.Split(c.MOTD, "\n") {
		if len(line) > 400 || strings.ContainsAny(line, "\x00\r") {
			return errors.New("each MOTD line must be at most 400 bytes and contain no CR or NUL")
		}
	}
	return nil
}

func validateToken(label, value string, max int) error {
	if value == "" || len(value) > max || strings.ContainsAny(value, " \t\x00\r\n:") {
		return fmt.Errorf("%s must be a non-empty protocol token of at most %d bytes", label, max)
	}
	return nil
}
