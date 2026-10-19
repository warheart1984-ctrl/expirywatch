package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func samplePayload() webhookPayload {
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	results := []Result{
		{Name: "ok site", Address: "ok.example:443", Status: StatusOK, ExpiresAt: &exp, DaysLeft: intPtr(80)},
		{Name: "soon", Address: "soon.example:443", Status: StatusWarn, ExpiresAt: &exp, DaysLeft: intPtr(20)},
		{Name: "dead", Address: "dead.example:443", Status: StatusCritical, ExpiresAt: &exp, DaysLeft: intPtr(-2)},
		{Name: "broken", Address: "broken.example", Status: StatusError, Err: "rdap: no expiration event"},
	}
	return webhookPayload{Tool: "expirywatch", Summary: summarize(results), Results: results}
}

func TestFormatMessage(t *testing.T) {
	msg := formatMessage(samplePayload())
	lines := strings.Split(msg, "\n")
	want := []string{
		"expirywatch: 1 critical, 1 warn, 1 error, 1 ok (total 4)",
		"- CRITICAL dead (dead.example:443): expires 2026-11-01 (expired 2 days ago)",
		"- ERROR broken (broken.example): rdap: no expiration event",
		"- WARN soon (soon.example:443): expires 2026-11-01 (20 days left)",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines:\n%s", len(lines), msg)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestWebhookBody(t *testing.T) {
	tests := []struct {
		format string
		key    string
	}{
		{webhookFormatSlack, "text"},
		{webhookFormatDiscord, "content"},
		{webhookFormatJSON, "results"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			body, err := webhookBody(tt.format, samplePayload())
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			if _, ok := m[tt.key]; !ok {
				t.Errorf("body missing %q: %s", tt.key, body)
			}
		})
	}
	if _, err := webhookBody("teams", samplePayload()); err == nil {
		t.Error("unknown format: want error")
	}
}

func TestDiscordTruncation(t *testing.T) {
	p := samplePayload()
	for i := 0; i < 100; i++ {
		p.Results = append(p.Results, Result{Name: strings.Repeat("x", 50), Status: StatusError, Err: "boom"})
	}
	body, err := webhookBody(webhookFormatDiscord, p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(m["content"])); n > discordMaxLen {
		t.Errorf("content length = %d, want <= %d", n, discordMaxLen)
	}
}

func TestShouldNotify(t *testing.T) {
	allOK := summary{OK: 3, Total: 3}
	oneWarn := summary{OK: 2, Warn: 1, Total: 3}
	if !shouldNotify(&Config{}, allOK) {
		t.Error("default config should always notify")
	}
	skip := &Config{WebhookSkipOK: true}
	if shouldNotify(skip, allOK) {
		t.Error("webhook_skip_ok: all OK should not notify")
	}
	if !shouldNotify(skip, oneWarn) {
		t.Error("webhook_skip_ok: a warning should notify")
	}
}
