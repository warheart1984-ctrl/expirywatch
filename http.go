package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type HTTPChecker struct{}

func (HTTPChecker) Type() string { return "http" }

func (HTTPChecker) Check(ctx context.Context, t Target) (time.Time, error) {
	url := strings.TrimSpace(t.Address)
	if url == "" {
		return time.Time{}, fmt.Errorf("missing url in %q", t.Address)
	}
	path := strings.TrimSpace(t.ExpiryPath)
	if path == "" {
		return time.Time{}, fmt.Errorf("missing expiry_path for %q", t.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "expirywatch/"+version)
	if err := authorize(req, t); err != nil {
		return time.Time{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("http %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return time.Time{}, fmt.Errorf("http %s: unexpected status %s", url, resp.Status)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.UseNumber()
	var payload any
	if err := dec.Decode(&payload); err != nil {
		return time.Time{}, fmt.Errorf("http %s: decode response: %w", url, err)
	}
	raw, ok := lookupJSON(payload, path)
	if !ok {
		return time.Time{}, fmt.Errorf("http %s: expiry path %q not found", url, path)
	}
	expires, err := expiryFromJSON(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("http %s: parse expiry %v: %w", url, raw, err)
	}
	return expires, nil
}

func authorize(req *http.Request, t Target) error {
	name := strings.TrimSpace(t.TokenEnv)
	if name == "" {
		return nil
	}
	token := strings.TrimSpace(os.Getenv(name))
	if token == "" {
		return fmt.Errorf("token_env %q is empty", name)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func lookupJSON(value any, path string) (any, bool) {
	current := value
	for _, segment := range strings.Split(path, ".") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, false
		}
		if index, err := strconv.Atoi(segment); err == nil {
			items, ok := current.([]any)
			if !ok || index < 0 || index >= len(items) {
				return nil, false
			}
			current = items[index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func expiryFromJSON(value any) (time.Time, error) {
	switch v := value.(type) {
	case string:
		text := strings.TrimSpace(v)
		if parsed, err := time.Parse(time.RFC3339, text); err == nil {
			return parsed, nil
		}
		parsed, err := time.Parse("2006-01-02", text)
		if err != nil {
			return time.Time{}, err
		}
		return parsed.UTC(), nil
	case json.Number:
		seconds, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		if seconds > 1e12 || seconds < -1e12 {
			return time.UnixMilli(seconds).UTC(), nil
		}
		return time.Unix(seconds, 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported value type %T", value)
	}
}
