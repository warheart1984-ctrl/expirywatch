package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	defaultWarnDays     = 30
	defaultCriticalDays = 7
	defaultTimeout      = "10s"
)

type Config struct {
	WarnDays     *int   `json:"warn_days"`
	CriticalDays *int   `json:"critical_days"`
	Timeout      string `json:"timeout"`
	WebhookURL   string `json:"webhook_url"`
	// WebhookFormat is "json" (default), "slack" or "discord".
	WebhookFormat string `json:"webhook_format"`
	// WebhookSkipOK suppresses the webhook when every target is OK.
	WebhookSkipOK bool     `json:"webhook_skip_ok"`
	Targets       []Target `json:"targets"`
}

type Target struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Address      string `json:"address"`
	WarnDays     *int   `json:"warn_days"`
	CriticalDays *int   `json:"critical_days"`
	Timeout      string `json:"timeout"`
	ExpiryPath   string `json:"expiry_path"`
	TokenEnv     string `json:"token_env"`
	// AllIPs makes a tls target check every address its host resolves to.
	AllIPs bool `json:"all_ips"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.expandEnv(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// expandEnv expands ${VAR} in webhook_url and checks that every http target's
// address expands. Addresses are kept as written, so a secret in them never
// shows up in the table or the webhook report; HTTPChecker expands them again
// when it builds the request.
func (c *Config) expandEnv() error {
	webhook, err := expandEnv(c.WebhookURL)
	if err != nil {
		return fmt.Errorf("config: webhook_url: %w", err)
	}
	c.WebhookURL = webhook
	for _, t := range c.Targets {
		if t.Type != "http" {
			continue
		}
		if _, err := expandEnv(t.Address); err != nil {
			return fmt.Errorf("config: target %q: address: %w", t.Name, err)
		}
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.WarnDays == nil {
		w := defaultWarnDays
		c.WarnDays = &w
	}
	if c.CriticalDays == nil {
		d := defaultCriticalDays
		c.CriticalDays = &d
	}
	if c.Timeout == "" {
		c.Timeout = defaultTimeout
	}
	if c.WebhookFormat == "" {
		c.WebhookFormat = webhookFormatJSON
	}
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.Name == "" {
			t.Name = t.Address
		}
		if t.Timeout == "" {
			t.Timeout = c.Timeout
		}
	}
}

func (c *Config) warnDaysFor(t Target) int {
	if t.WarnDays != nil {
		return *t.WarnDays
	}
	return *c.WarnDays
}

func (c *Config) criticalDaysFor(t Target) int {
	if t.CriticalDays != nil {
		return *t.CriticalDays
	}
	return *c.CriticalDays
}

func (c *Config) timeoutFor(t Target) string {
	if t.Timeout != "" {
		return t.Timeout
	}
	return c.Timeout
}

func (c *Config) validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("config: at least one target is required")
	}
	if *c.WarnDays < 0 {
		return fmt.Errorf("config: warn_days must be >= 0")
	}
	if *c.CriticalDays < 0 {
		return fmt.Errorf("config: critical_days must be >= 0")
	}
	if *c.CriticalDays > *c.WarnDays {
		return fmt.Errorf("config: critical_days (%d) must be <= warn_days (%d)", *c.CriticalDays, *c.WarnDays)
	}
	if _, err := time.ParseDuration(c.Timeout); err != nil {
		return fmt.Errorf("config: invalid timeout %q: %w", c.Timeout, err)
	}
	switch c.WebhookFormat {
	case webhookFormatJSON, webhookFormatSlack, webhookFormatDiscord:
	default:
		return fmt.Errorf("config: unsupported webhook_format %q (want json, slack or discord)", c.WebhookFormat)
	}
	for i := range c.Targets {
		t := c.Targets[i]
		if t.Address == "" {
			return fmt.Errorf("config: target %d: address is required", i)
		}
		switch t.Type {
		case "tls", "domain":
		case "http":
			if t.ExpiryPath == "" {
				return fmt.Errorf("config: target %q: expiry_path is required", t.Name)
			}
		default:
			return fmt.Errorf("config: target %q: unsupported type %q", t.Name, t.Type)
		}
		if t.AllIPs && t.Type != "tls" {
			return fmt.Errorf("config: target %q: all_ips only applies to tls targets", t.Name)
		}
		warn := c.warnDaysFor(t)
		critical := c.criticalDaysFor(t)
		if warn < 0 {
			return fmt.Errorf("config: target %q: warn_days must be >= 0", t.Name)
		}
		if critical < 0 {
			return fmt.Errorf("config: target %q: critical_days must be >= 0", t.Name)
		}
		if critical > warn {
			return fmt.Errorf("config: target %q: critical_days (%d) must be <= warn_days (%d)", t.Name, critical, warn)
		}
		if _, err := time.ParseDuration(c.timeoutFor(t)); err != nil {
			return fmt.Errorf("config: target %q: invalid timeout %q: %w", t.Name, c.timeoutFor(t), err)
		}
	}
	return nil
}
