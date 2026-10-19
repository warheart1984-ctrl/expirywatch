package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const rdapBaseURL = "https://rdap.org/domain/"

type DomainChecker struct{}

func (DomainChecker) Type() string { return "domain" }

type rdapResponse struct {
	Events []rdapEvent `json:"events"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

func (DomainChecker) Check(ctx context.Context, t Target) (time.Time, error) {
	domain := normalizeDomain(t.Address)
	if domain == "" {
		return time.Time{}, fmt.Errorf("missing domain in %q", t.Address)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapBaseURL+domain, nil)
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
