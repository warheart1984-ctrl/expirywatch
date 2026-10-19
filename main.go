package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

// version is a var so release builds can set it with -ldflags "-X main.version=...".
var version = "0.3.0"

const maxConcurrency = 8

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("expirywatch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "config.json", "path to config file")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	noWebhook := fs.Bool("no-webhook", false, "disable webhook notification")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if *showVersion {
		fmt.Println("expirywatch " + version)
		return 0
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "expirywatch:", err)
		return 3
	}

	results := runChecks(cfg)
	payload := webhookPayload{
		Tool:    "expirywatch",
		Version: version,
		Time:    time.Now().UTC(),
		Summary: summarize(results),
		Results: results,
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			fmt.Fprintln(os.Stderr, "expirywatch: encode output:", err)
			return 3
		}
	} else {
		printResults(results, os.Stdout)
	}

	if !*noWebhook && cfg.WebhookURL != "" && shouldNotify(cfg, payload.Summary) {
		// Room for two 10s attempts plus the retry delay.
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		if err := sendWebhook(ctx, cfg.WebhookURL, cfg.WebhookFormat, payload); err != nil {
			fmt.Fprintln(os.Stderr, "expirywatch: webhook:", err)
		}
		cancel()
	}

	return exitCode(results)
}

func runChecks(cfg *Config) []Result {
	results := make([]Result, len(cfg.Targets))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, t := range cfg.Targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = checkTarget(context.Background(), cfg, t)
		}(i, t)
	}
	wg.Wait()
	return results
}

func checkTarget(parent context.Context, cfg *Config, t Target) Result {
	result := Result{
		Name:    t.Name,
		Type:    t.Type,
		Address: t.Address,
	}

	checker, err := checkerFor(t)
	if err != nil {
		result.Status = StatusError
		result.Err = err.Error()
		return result
	}

	d, err := time.ParseDuration(cfg.timeoutFor(t))
	if err != nil {
		result.Status = StatusError
		result.Err = err.Error()
		return result
	}

	ctx, cancel := context.WithTimeout(parent, d)
	defer cancel()

	var expires time.Time
	if nc, ok := checker.(noteChecker); ok {
		expires, result.Note, err = nc.CheckWithNote(ctx, t)
	} else {
		expires, err = checker.Check(ctx, t)
	}
	if err != nil {
		result.Status = StatusError
		result.Err = err.Error()
		return result
	}

	daysLeft := daysUntil(expires, time.Now())
	result.ExpiresAt = &expires
	result.DaysLeft = &daysLeft
	result.Status = classify(daysLeft, cfg.warnDaysFor(t), cfg.criticalDaysFor(t))
	return result
}

func exitCode(results []Result) int {
	code := 0
	for _, r := range results {
		switch r.Status {
		case StatusError:
			return 2
		case StatusCritical:
			code = 1
		}
	}
	return code
}
