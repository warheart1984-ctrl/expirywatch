package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandEnv(t *testing.T) {
	t.Setenv("EW_HOOK", "https://hooks.example.com/T000/B000/secret")
	t.Setenv("EW_TOKEN", "abc123")
	t.Setenv("EW_EMPTY", "")

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "no dollar", in: "https://example.com/x", want: "https://example.com/x"},
		{name: "whole value", in: "${EW_HOOK}", want: "https://hooks.example.com/T000/B000/secret"},
		{name: "inside a url", in: "https://api.example.com/v1?key=${EW_TOKEN}&x=1", want: "https://api.example.com/v1?key=abc123&x=1"},
		{name: "twice", in: "${EW_TOKEN}-${EW_TOKEN}", want: "abc123-abc123"},
		{name: "lone dollar is literal", in: "https://example.com/price$", want: "https://example.com/price$"},
		{name: "unbraced name is literal", in: "https://example.com/$EW_TOKEN", want: "https://example.com/$EW_TOKEN"},
		{name: "dollar dollar brace is an escape", in: "https://example.com/$${EW_TOKEN}", want: "https://example.com/${EW_TOKEN}"},
		{name: "unset", in: "https://example.com/${EW_NOT_SET_ANYWHERE}", wantErr: "EW_NOT_SET_ANYWHERE is not set"},
		{name: "empty", in: "${EW_EMPTY}", wantErr: "EW_EMPTY is empty"},
		{name: "unterminated", in: "https://example.com/${EW_TOKEN", wantErr: "unterminated"},
		{name: "invalid name", in: "${1BAD}", wantErr: "invalid variable name"},
		{name: "empty name", in: "${}", wantErr: "invalid variable name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandEnv(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expandEnv(%q) err = %v, want error containing %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandEnv(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("expandEnv(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigExpandsEnv(t *testing.T) {
	t.Setenv("EW_HOOK", "https://hooks.example.com/secret")
	t.Setenv("EW_KEY", "k3y")

	cfg, err := LoadConfig(writeConfig(t, `{
		"webhook_url": "${EW_HOOK}",
		"targets": [{"type": "http", "address": "https://api.example.com/?key=${EW_KEY}", "expiry_path": "x"}]
	}`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.WebhookURL != "https://hooks.example.com/secret" {
		t.Errorf("WebhookURL = %q, want the expanded value", cfg.WebhookURL)
	}
	// The address and the name defaulted from it stay as written, so the
	// secret never reaches the table or the webhook report.
	if got := cfg.Targets[0].Address; got != "https://api.example.com/?key=${EW_KEY}" {
		t.Errorf("Address = %q, want it unexpanded", got)
	}
	if got := cfg.Targets[0].Name; strings.Contains(got, "k3y") {
		t.Errorf("Name = %q, must not contain the secret", got)
	}
}

func TestLoadConfigUnsetEnv(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "webhook_url",
			body:    `{"webhook_url": "${EW_NOT_SET_ANYWHERE}", "targets": [{"type": "tls", "address": "example.com"}]}`,
			wantErr: "webhook_url: environment variable EW_NOT_SET_ANYWHERE is not set",
		},
		{
			name:    "http address",
			body:    `{"targets": [{"name": "api", "type": "http", "address": "https://x/${EW_NOT_SET_ANYWHERE}", "expiry_path": "x"}]}`,
			wantErr: `target "api": address: environment variable EW_NOT_SET_ANYWHERE is not set`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadConfig err = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigLeavesNonHTTPAddressesAlone(t *testing.T) {
	// Only http addresses are expanded; a "$" in a tls address is not touched.
	cfg, err := LoadConfig(writeConfig(t, `{"targets": [{"type": "tls", "address": "${EW_NOT_SET_ANYWHERE}:443"}]}`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.Targets[0].Address; got != "${EW_NOT_SET_ANYWHERE}:443" {
		t.Errorf("Address = %q, want it unchanged", got)
	}
}

func TestHTTPCheckerExpandsAddress(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		_, _ = w.Write([]byte(`{"expires":"2030-01-01"}`))
	}))
	defer srv.Close()
	t.Setenv("EW_KEY", "s3cret")

	cfg := &Config{
		WarnDays:     intPtr(30),
		CriticalDays: intPtr(7),
		Timeout:      "5s",
		Targets:      []Target{{Name: "api", Type: "http", Address: srv.URL + "/?key=${EW_KEY}", ExpiryPath: "expires"}},
	}
	r := checkTarget(context.Background(), cfg, cfg.Targets[0])
	if r.Status != StatusOK {
		t.Fatalf("Status = %q (err %q), want %q", r.Status, r.Err, StatusOK)
	}
	if gotKey != "s3cret" {
		t.Errorf("server got key %q, want %q", gotKey, "s3cret")
	}
	if strings.Contains(r.Address, "s3cret") {
		t.Errorf("result Address %q contains the secret", r.Address)
	}
}

func TestHTTPCheckerErrorHidesSecret(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // nothing listens any more, so the request fails to connect

	t.Setenv("EW_KEY", "s3cret")
	cfg := &Config{
		WarnDays:     intPtr(30),
		CriticalDays: intPtr(7),
		Timeout:      "5s",
		Targets:      []Target{{Name: "api", Type: "http", Address: addr + "/?key=${EW_KEY}", ExpiryPath: "expires"}},
	}
	r := checkTarget(context.Background(), cfg, cfg.Targets[0])
	if r.Status != StatusError {
		t.Fatalf("Status = %q, want %q", r.Status, StatusError)
	}
	if strings.Contains(r.Err, "s3cret") {
		t.Errorf("Err %q contains the secret", r.Err)
	}
}

func TestSendWebhookErrorHidesURL(t *testing.T) {
	fastRetry(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	hook := srv.URL + "/hooks/s3cret"
	srv.Close()

	err := sendWebhook(context.Background(), hook, webhookFormatJSON, webhookPayload{})
	if err == nil {
		t.Fatal("sendWebhook err = nil, want a connection error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("err %q contains the webhook URL", err)
	}
}
