package main

import (
	"context"
	"fmt"
	"math"
	"time"
)

const (
	StatusOK       = "OK"
	StatusWarn     = "WARN"
	StatusCritical = "CRITICAL"
	StatusError    = "ERROR"
)

type Result struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Address   string     `json:"address"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	DaysLeft  *int       `json:"days_left,omitempty"`
	Err       string     `json:"error,omitempty"`
}

type Checker interface {
	Type() string
	Check(ctx context.Context, t Target) (time.Time, error)
}

func checkerFor(t Target) (Checker, error) {
	switch t.Type {
	case "tls":
		return TLSChecker{}, nil
	case "domain":
		return DomainChecker{}, nil
	case "http":
		return HTTPChecker{}, nil
	default:
		return nil, fmt.Errorf("unsupported target type %q", t.Type)
	}
}

func classify(daysLeft, warnDays, criticalDays int) string {
	switch {
	case daysLeft <= criticalDays:
		return StatusCritical
	case daysLeft <= warnDays:
		return StatusWarn
	default:
		return StatusOK
	}
}

func daysUntil(expires, now time.Time) int {
	return int(math.Ceil(expires.Sub(now).Hours() / 24))
}
