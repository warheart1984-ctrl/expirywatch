package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fastRetry shortens the retry delay for the duration of a test.
func fastRetry(t *testing.T) {
	t.Helper()
	delay, timeout := webhookRetryDelay, webhookAttemptTimeout
	webhookRetryDelay, webhookAttemptTimeout = 10*time.Millisecond, 2*time.Second
	t.Cleanup(func() { webhookRetryDelay, webhookAttemptTimeout = delay, timeout })
}

type hookRequest struct {
	method      string
	contentType string
	body        []byte
}

// hookServer answers requests with the given statuses in order (200 once
// they run out) and records what it received. A status of 0 drops the
// connection without answering, which the client sees as a network error.
func hookServer(t *testing.T, statuses ...int) (*httptest.Server, func() []hookRequest) {
	t.Helper()
	var mu sync.Mutex
	var got []hookRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		n := len(got)
		got = append(got, hookRequest{r.Method, r.Header.Get("Content-Type"), body})
		mu.Unlock()

		status := http.StatusOK
		if n < len(statuses) {
			status = statuses[n]
		}
		if status == 0 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []hookRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]hookRequest(nil), got...)
	}
}

func TestSendWebhookFormats(t *testing.T) {
	fastRetry(t)
	payload := samplePayload()
	wantMessage := formatMessage(payload)

	tests := []struct {
		format string
		check  func(t *testing.T, body []byte)
	}{
		{webhookFormatSlack, func(t *testing.T, body []byte) {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			if m["text"] != wantMessage {
				t.Errorf("text = %q, want %q", m["text"], wantMessage)
			}
		}},
		{webhookFormatDiscord, func(t *testing.T, body []byte) {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			if m["content"] != wantMessage {
				t.Errorf("content = %q, want %q", m["content"], wantMessage)
			}
		}},
		{webhookFormatJSON, func(t *testing.T, body []byte) {
			var p webhookPayload
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
			if p.Tool != "expirywatch" || len(p.Results) != len(payload.Results) || p.Summary != payload.Summary {
				t.Errorf("payload = %+v, want %+v", p, payload)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			srv, requests := hookServer(t)
			if err := sendWebhook(context.Background(), srv.URL, tt.format, payload); err != nil {
				t.Fatalf("sendWebhook: %v", err)
			}
			got := requests()
			if len(got) != 1 {
				t.Fatalf("server got %d requests, want 1", len(got))
			}
			if got[0].method != http.MethodPost {
				t.Errorf("method = %s, want POST", got[0].method)
			}
			if got[0].contentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got[0].contentType)
			}
			tt.check(t, got[0].body)
		})
	}
}

func TestSendWebhookRetry(t *testing.T) {
	fastRetry(t)
	tests := []struct {
		name         string
		statuses     []int
		wantRequests int
		wantErr      string
	}{
		{name: "success", statuses: []int{200}, wantRequests: 1},
		{name: "500 then success", statuses: []int{500, 200}, wantRequests: 2},
		{name: "503 twice", statuses: []int{503, 503}, wantRequests: 2, wantErr: "503 Service Unavailable (after 1 retry)"},
		{name: "network error then success", statuses: []int{0, 200}, wantRequests: 2},
		{name: "400 is not retried", statuses: []int{400}, wantRequests: 1, wantErr: "400 Bad Request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, requests := hookServer(t, tt.statuses...)
			err := sendWebhook(context.Background(), srv.URL, webhookFormatSlack, samplePayload())
			if tt.wantErr == "" && err != nil {
				t.Fatalf("sendWebhook: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("sendWebhook err = %v, want error containing %q", err, tt.wantErr)
			}
			got := requests()
			if len(got) != tt.wantRequests {
				t.Fatalf("server got %d requests, want %d", len(got), tt.wantRequests)
			}
			// A retry must resend the same body.
			if len(got) == 2 && string(got[0].body) != string(got[1].body) {
				t.Errorf("retry body differs:\n%s\n%s", got[0].body, got[1].body)
			}
		})
	}
}

func TestSendWebhookNoRetryAfterCancel(t *testing.T) {
	fastRetry(t)
	webhookRetryDelay = time.Hour // the cancelled context must win over the wait
	srv, requests := hookServer(t, 500)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sendWebhook(ctx, srv.URL, webhookFormatJSON, samplePayload()) }()
	for len(requests()) == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("err = %v, want the 500 from the first attempt", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendWebhook did not return after the context was cancelled")
	}
	if n := len(requests()); n != 1 {
		t.Errorf("server got %d requests, want 1", n)
	}
}
