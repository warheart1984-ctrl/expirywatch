package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	webhookFormatJSON    = "json"
	webhookFormatSlack   = "slack"
	webhookFormatDiscord = "discord"

	// Discord rejects messages longer than 2000 characters.
	discordMaxLen = 2000
)

type summary struct {
	OK       int `json:"ok"`
	Warn     int `json:"warn"`
	Critical int `json:"critical"`
	Error    int `json:"error"`
	Total    int `json:"total"`
}

type webhookPayload struct {
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
	Summary summary   `json:"summary"`
	Results []Result  `json:"results"`
}

func summarize(results []Result) summary {
	var s summary
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			s.OK++
		case StatusWarn:
			s.Warn++
		case StatusCritical:
			s.Critical++
		case StatusError:
			s.Error++
		}
	}
	s.Total = len(results)
	return s
}

func printResults(results []Result, out io.Writer) {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tADDRESS\tSTATUS\tEXPIRES\tDAYS LEFT")
	for _, r := range results {
		expires := "-"
		if r.ExpiresAt != nil {
			expires = r.ExpiresAt.UTC().Format("2006-01-02 15:04 MST")
		}
		days := "-"
		if r.DaysLeft != nil {
			days = fmt.Sprintf("%d", *r.DaysLeft)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Type, r.Address, r.Status, expires, days)
	}
	tw.Flush()

	hasErrors := false
	for _, r := range results {
		if r.Err != "" {
			hasErrors = true
			break
		}
	}
	if hasErrors {
		fmt.Fprintln(out)
		for _, r := range results {
			if r.Err != "" {
				fmt.Fprintf(out, "error: %s (%s): %s\n", r.Name, r.Address, r.Err)
			}
		}
	}

	s := summarize(results)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "summary: %d ok, %d warn, %d critical, %d error (total %d)\n", s.OK, s.Warn, s.Critical, s.Error, s.Total)
}

// shouldNotify reports whether the webhook should fire for this run.
func shouldNotify(cfg *Config, s summary) bool {
	if !cfg.WebhookSkipOK {
		return true
	}
	return s.Warn+s.Critical+s.Error > 0
}

// webhookBody encodes the payload in the shape the receiving service expects.
func webhookBody(format string, payload webhookPayload) ([]byte, error) {
	switch format {
	case webhookFormatSlack:
		return json.Marshal(map[string]string{"text": formatMessage(payload)})
	case webhookFormatDiscord:
		return json.Marshal(map[string]string{"content": truncateRunes(formatMessage(payload), discordMaxLen)})
	case webhookFormatJSON, "":
		return json.Marshal(payload)
	default:
		return nil, fmt.Errorf("unsupported webhook format %q", format)
	}
}

// formatMessage renders a short human-readable report: a summary line, then
// one line per target that is not OK, most urgent first.
func formatMessage(payload webhookPayload) string {
	s := payload.Summary
	var b strings.Builder
	fmt.Fprintf(&b, "expirywatch: %d critical, %d warn, %d error, %d ok (total %d)",
		s.Critical, s.Warn, s.Error, s.OK, s.Total)
	for _, status := range []string{StatusCritical, StatusError, StatusWarn} {
		for _, r := range payload.Results {
			if r.Status != status {
				continue
			}
			fmt.Fprintf(&b, "\n- %s %s (%s)", r.Status, r.Name, r.Address)
			switch {
			case r.Err != "":
				fmt.Fprintf(&b, ": %s", r.Err)
			case r.ExpiresAt != nil && r.DaysLeft != nil:
				fmt.Fprintf(&b, ": expires %s (%s)", r.ExpiresAt.UTC().Format("2006-01-02"), describeDays(*r.DaysLeft))
			}
		}
	}
	return b.String()
}

func describeDays(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("expired %d days ago", -days)
	case days == 1:
		return "1 day left"
	default:
		return fmt.Sprintf("%d days left", days)
	}
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

func sendWebhook(ctx context.Context, url, format string, payload webhookPayload) error {
	body, err := webhookBody(format, payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return withoutURL(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "expirywatch/"+version)

	// The webhook URL is itself a secret, so keep it out of the error.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return withoutURL(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %s", resp.Status)
	}
	return nil
}
