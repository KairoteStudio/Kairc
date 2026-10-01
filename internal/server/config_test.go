package server

import (
	"math"
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "server name injection", mutate: func(c *Config) { c.Name = "irc.test\r\nOPER" }},
		{name: "network space", mutate: func(c *Config) { c.Network = "Test Network" }},
		{name: "unbounded rate", mutate: func(c *Config) { c.MessagesPerSecond = math.Inf(1) }},
		{name: "long motd", mutate: func(c *Config) { c.MOTD = strings.Repeat("x", 401) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Fatal("validate() accepted unsafe configuration")
			}
		})
	}
}
