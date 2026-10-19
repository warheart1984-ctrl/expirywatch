package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rdapServer answers /domain/<name> with an expiration event for the names
// it knows and 404 for the rest, and counts requests per path.
func rdapServer(t *testing.T, expiries map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		name := strings.TrimPrefix(r.URL.Path, "/domain/")
		date, ok := expiries[name]
		if !ok || !strings.HasPrefix(r.URL.Path, "/domain/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprintf(w, `{"events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},{"eventAction":"expiration","eventDate":%q}]}`, date)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// bootstrapServer serves an IANA-style dns.json and counts fetches.
func bootstrapServer(t *testing.T, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestDomainCheckerBootstrap(t *testing.T) {
	registry, registryHits := rdapServer(t, map[string]string{
		"example.com":    "2030-08-13T04:00:00Z",
		"shop.example":   "2031-02-01T00:00:00Z",
		"sub.example.uk": "2029-05-05T00:00:00Z",
	})
	fallback, fallbackHits := rdapServer(t, map[string]string{
		"example.org": "2028-01-01T00:00:00Z",
	})
	// The registry is listed with a plain http URL first and its https form
	// is unreachable here, so list only what the test server speaks. "co.uk"
	// style multi-label entries are matched by longest suffix.
	bootstrap, bootstrapHits := bootstrapServer(t, fmt.Sprintf(`{
		"version": "1.0",
		"services": [
			[["com", "NET"], [%q]],
			[["example"], [%q]],
			[["example.uk"], [%q]],
			[["broken"], []]
		]
	}`, registry.URL+"/", registry.URL, registry.URL+"/"))

	checker := DomainChecker{Bootstrap: newRDAPBootstrap(bootstrap.URL), FallbackURL: fallback.URL}
	check := func(address string) (time.Time, error) {
		return checker.Check(context.Background(), Target{Type: "domain", Address: address})
	}

	tests := []struct {
		address string
		want    string
	}{
		{"example.com", "2030-08-13"},
		{"https://EXAMPLE.com/whois", "2030-08-13"},
		{"shop.example", "2031-02-01"},   // registry URL without a trailing slash
		{"sub.example.uk", "2029-05-05"}, // longest suffix wins over "uk"
		{"example.org", "2028-01-01"},    // not listed: rdap.org fallback
	}
	for _, tt := range tests {
		got, err := check(tt.address)
		if err != nil {
			t.Errorf("%s: %v", tt.address, err)
			continue
		}
		if d := got.Format("2006-01-02"); d != tt.want {
			t.Errorf("%s: expires %s, want %s", tt.address, d, tt.want)
		}
	}

	if n := bootstrapHits.Load(); n != 1 {
		t.Errorf("bootstrap fetched %d times, want once per run", n)
	}
	if n := registryHits.Load(); n != 4 {
		t.Errorf("registry got %d requests, want 4", n)
	}
	if n := fallbackHits.Load(); n != 1 {
		t.Errorf("fallback got %d requests, want 1", n)
	}

	// A TLD that neither the bootstrap file nor rdap.org knows.
	if _, err := check("example.de"); err == nil || err.Error() != "no RDAP service for .de" {
		t.Errorf("example.de: err = %v, want %q", err, "no RDAP service for .de")
	}
	// A listed TLD where the registry has no such domain keeps the plain error.
	if _, err := check("missing.com"); err == nil || !strings.Contains(err.Error(), "rdap missing.com: unexpected status 404") {
		t.Errorf("missing.com: err = %v, want a 404 from the registry", err)
	}
}

func TestDomainCheckerBootstrapUnavailable(t *testing.T) {
	// When the bootstrap file can't be fetched, every lookup goes to rdap.org,
	// and a 404 there is not reported as "no RDAP service" since we don't know.
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	fallback, fallbackHits := rdapServer(t, map[string]string{"example.com": "2030-08-13T04:00:00Z"})
	checker := DomainChecker{Bootstrap: newRDAPBootstrap(downURL), FallbackURL: fallback.URL}

	got, err := checker.Check(context.Background(), Target{Type: "domain", Address: "example.com"})
	if err != nil {
		t.Fatalf("example.com: %v", err)
	}
	if d := got.Format("2006-01-02"); d != "2030-08-13" {
		t.Errorf("expires %s, want 2030-08-13", d)
	}
	if n := fallbackHits.Load(); n != 1 {
		t.Errorf("fallback got %d requests, want 1", n)
	}

	_, err = checker.Check(context.Background(), Target{Type: "domain", Address: "example.de"})
	if err == nil || !strings.Contains(err.Error(), "unexpected status 404") {
		t.Errorf("example.de: err = %v, want the plain 404 error", err)
	}
}

func TestFetchBootstrapErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"bad status", http.StatusInternalServerError, "", "unexpected status 500"},
		{"not json", http.StatusOK, "<html>", "decode"},
		{"empty services", http.StatusOK, `{"services": []}`, "no services listed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()
			_, err := fetchBootstrap(context.Background(), srv.URL)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPickRDAPURL(t *testing.T) {
	if got := pickRDAPURL([]string{"http://a.example/", "https://b.example/"}); got != "https://b.example/" {
		t.Errorf("got %q, want the https URL", got)
	}
	if got := pickRDAPURL([]string{"http://a.example/"}); got != "http://a.example/" {
		t.Errorf("got %q, want the only URL", got)
	}
	if got := pickRDAPURL(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
