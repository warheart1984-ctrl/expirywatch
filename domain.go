package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	ianaBootstrapURL = "https://data.iana.org/rdap/dns.json"
	rdapFallbackURL  = "https://rdap.org/"

	// bootstrapTimeout caps the one bootstrap fetch per run. It is separate
	// from the per-target timeout because every domain target shares it.
	bootstrapTimeout = 10 * time.Second
)

// defaultBootstrap is shared by every domain target in a run, so the IANA
// file is fetched at most once.
var defaultBootstrap = newRDAPBootstrap(ianaBootstrapURL)

type DomainChecker struct {
	// Bootstrap and FallbackURL default to the IANA file and rdap.org.
	Bootstrap   *rdapBootstrap
	FallbackURL string
}

func (DomainChecker) Type() string { return "domain" }

type rdapResponse struct {
	Events []rdapEvent `json:"events"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

func (c DomainChecker) Check(ctx context.Context, t Target) (time.Time, error) {
	domain := normalizeDomain(t.Address)
	if domain == "" {
		return time.Time{}, fmt.Errorf("missing domain in %q", t.Address)
	}
	bootstrap := c.Bootstrap
	if bootstrap == nil {
		bootstrap = defaultBootstrap
	}
	fallback := c.FallbackURL
	if fallback == "" {
		fallback = rdapFallbackURL
	}

	// Use the registry's own RDAP server when IANA lists one for the TLD.
	// Otherwise, or when the bootstrap file can't be fetched, ask rdap.org.
	base, listed := bootstrap.serverFor(domain)
	if !listed {
		base = fallback
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinRDAP(base, domain), nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "expirywatch/"+version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		// rdap.org answers 404 for TLDs that have no RDAP service anywhere.
		if !listed && resp.StatusCode == http.StatusNotFound && !bootstrap.failed() {
			return time.Time{}, fmt.Errorf("no RDAP service for .%s", tldOf(domain))
		}
		return time.Time{}, fmt.Errorf("rdap %s: unexpected status %s", domain, resp.Status)
	}

	var parsed rdapResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return time.Time{}, fmt.Errorf("rdap %s: decode response: %w", domain, err)
	}

	for _, ev := range parsed.Events {
		if !strings.EqualFold(ev.Action, "expiration") {
			continue
		}
		expires, err := time.Parse(time.RFC3339, ev.Date)
		if err != nil {
			return time.Time{}, fmt.Errorf("rdap %s: parse expiration %q: %w", domain, ev.Date, err)
		}
		return expires, nil
	}
	return time.Time{}, fmt.Errorf("rdap %s: no expiration event", domain)
}

// rdapBootstrap is the IANA RDAP bootstrap registry for domains (RFC 9224),
// fetched lazily on first use and then reused.
type rdapBootstrap struct {
	url string

	once     sync.Once
	services map[string]string // lower-case TLD (or label suffix) -> RDAP base URL
	err      error
}

func newRDAPBootstrap(url string) *rdapBootstrap {
	return &rdapBootstrap{url: url}
}

// serverFor returns the RDAP base URL for domain, matching the longest
// listed label suffix. ok is false when nothing matches or the bootstrap
// file couldn't be loaded.
func (b *rdapBootstrap) serverFor(domain string) (base string, ok bool) {
	b.once.Do(b.load)
	if b.err != nil {
		return "", false
	}
	labels := strings.Split(domain, ".")
	for i := range labels {
		if base, ok := b.services[strings.Join(labels[i:], ".")]; ok {
			return base, true
		}
	}
	return "", false
}

// failed reports whether loading the bootstrap file failed, in which case a
// 404 from the fallback can't be taken to mean the TLD has no RDAP.
func (b *rdapBootstrap) failed() bool {
	b.once.Do(b.load)
	return b.err != nil
}

func (b *rdapBootstrap) load() {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()
	b.services, b.err = fetchBootstrap(ctx, b.url)
}

// fetchBootstrap parses the bootstrap file's "services" list, where each
// entry is [[tld, ...], [url, ...]].
func fetchBootstrap(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "expirywatch/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("rdap bootstrap: unexpected status %s", resp.Status)
	}

	var file struct {
		Services [][][]string `json:"services"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&file); err != nil {
		return nil, fmt.Errorf("rdap bootstrap: decode: %w", err)
	}
	services := make(map[string]string)
	for _, entry := range file.Services {
		if len(entry) != 2 {
			continue
		}
		base := pickRDAPURL(entry[1])
		if base == "" {
			continue
		}
		for _, tld := range entry[0] {
			services[strings.ToLower(strings.TrimSuffix(tld, "."))] = base
		}
	}
	if len(services) == 0 {
		return nil, errors.New("rdap bootstrap: no services listed")
	}
	return services, nil
}

// pickRDAPURL prefers an https URL, as RFC 9224 recommends.
func pickRDAPURL(urls []string) string {
	for _, u := range urls {
		if strings.HasPrefix(u, "https://") {
			return u
		}
	}
	if len(urls) > 0 {
		return urls[0]
	}
	return ""
}

func joinRDAP(base, domain string) string {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + "domain/" + domain
}

func tldOf(domain string) string {
	if i := strings.LastIndexByte(domain, '.'); i >= 0 {
		return domain[i+1:]
	}
	return domain
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}
