package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name         string
		daysLeft     int
		warnDays     int
		criticalDays int
		want         string
	}{
		{"negative is critical", -5, 30, 7, StatusCritical},
		{"zero is critical", 0, 30, 7, StatusCritical},
		{"at critical boundary", 7, 30, 7, StatusCritical},
		{"just above critical", 8, 30, 7, StatusWarn},
		{"at warn boundary", 30, 30, 7, StatusWarn},
		{"just above warn", 31, 30, 7, StatusOK},
		{"zero warn means only critical", 15, 0, 7, StatusOK},
		{"zero critical", 1, 30, 0, StatusWarn},
		{"all zero boundary", 0, 0, 0, StatusCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.daysLeft, tt.warnDays, tt.criticalDays)
			if got != tt.want {
				t.Errorf("classify(%d, %d, %d) = %q, want %q",
					tt.daysLeft, tt.warnDays, tt.criticalDays, got, tt.want)
			}
		})
	}
}

func TestDaysUntil(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		expiry time.Time
		want   int
	}{
		{"same day", time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC), 1},
		{"already expired", time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC), -1},
		{"exact 24h", time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC), 1},
		{"24h plus one second rounds up", time.Date(2026, 1, 2, 12, 0, 1, 0, time.UTC), 2},
		{"ten days", time.Date(2026, 1, 11, 12, 0, 0, 0, time.UTC), 10},
		{"just under a day", time.Date(2026, 1, 2, 11, 59, 0, 0, time.UTC), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := daysUntil(tt.expiry, now)
			if got != tt.want {
				t.Errorf("daysUntil(%v, %v) = %d, want %d", tt.expiry, now, got, tt.want)
			}
		})
	}
}

func TestCheckerFor(t *testing.T) {
	tests := []struct {
		typ     string
		want    Checker
		wantErr bool
	}{
		{typ: "tls", want: &TLSChecker{}},
		{typ: "domain", want: &DomainChecker{}},
		{typ: "http", want: &HTTPChecker{}},
		{typ: "bogus", wantErr: true},
		{typ: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			got, err := checkerFor(Target{Type: tt.typ})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("checkerFor(%q) err = nil, want error", tt.typ)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkerFor(%q) unexpected error: %v", tt.typ, err)
			}
			if got.Type() != tt.typ {
				t.Errorf("checkerFor(%q).Type() = %q, want %q", tt.typ, got.Type(), tt.typ)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	ok := Result{Status: StatusOK}
	warn := Result{Status: StatusWarn}
	crit := Result{Status: StatusCritical}
	errored := Result{Status: StatusError}

	tests := []struct {
		name    string
		results []Result
		want    int
	}{
		{"nil results", nil, 0},
		{"all ok", []Result{ok, ok}, 0},
		{"warn only", []Result{ok, warn}, 0},
		{"critical present", []Result{ok, crit, warn}, 1},
		{"error beats critical", []Result{crit, errored}, 2},
		{"error only", []Result{errored}, 2},
		{"error first", []Result{errored, crit}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.results); got != tt.want {
				t.Errorf("exitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRunChecksHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"expires_at":"2030-06-15T00:00:00Z"}}`))
	}))
	defer srv.Close()

	cfg := &Config{
		WarnDays:     intPtr(30),
		CriticalDays: intPtr(7),
		Timeout:      "5s",
		Targets: []Target{
			{Name: "api", Type: "http", Address: srv.URL, ExpiryPath: "data.expires_at"},
		},
	}

	results := runChecks(cfg)
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Name != "api" {
		t.Errorf("Name = %q, want %q", r.Name, "api")
	}
	if r.Status != StatusOK {
		t.Errorf("Status = %q, want %q", r.Status, StatusOK)
	}
	if r.ExpiresAt == nil || r.ExpiresAt.Year() != 2030 {
		t.Errorf("ExpiresAt = %v, want year 2030", r.ExpiresAt)
	}
	if r.DaysLeft == nil || *r.DaysLeft <= 0 {
		t.Errorf("DaysLeft = %v, want positive", r.DaysLeft)
	}
	if r.Err != "" {
		t.Errorf("Err = %q, want empty", r.Err)
	}
}

func TestCheckTargetErrors(t *testing.T) {
	tests := []struct {
		name   string
		target Target
	}{
		{"unsupported type", Target{Name: "bad", Type: "smtp", Address: "example.com"}},
		{"missing http address", Target{Name: "noaddr", Type: "http", ExpiryPath: "x"}},
		{"invalid timeout", Target{Name: "badtimeout", Type: "http", Address: "http://x", Timeout: "not-a-duration"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				WarnDays:     intPtr(30),
				CriticalDays: intPtr(7),
				Timeout:      "5s",
				Targets:      []Target{tt.target},
			}
			r := checkTarget(context.Background(), cfg, tt.target)
			if r.Status != StatusError {
				t.Errorf("Status = %q, want %q", r.Status, StatusError)
			}
			if r.Err == "" {
				t.Error("Err is empty, want error message")
			}
		})
	}
}

func TestCheckTargetDeadlineExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	cfg := &Config{
		WarnDays:     intPtr(30),
		CriticalDays: intPtr(7),
		Timeout:      "10ms",
		Targets: []Target{
			{Name: "slow", Type: "http", Address: srv.URL, ExpiryPath: "data.expires_at"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	r := checkTarget(ctx, cfg, cfg.Targets[0])
	if r.Status != StatusError {
		t.Errorf("Status = %q, want %q", r.Status, StatusError)
	}
	if r.Err == "" {
		t.Error("Err is empty, want timeout error")
	}
}

func intPtr(n int) *int { return &n }
