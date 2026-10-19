package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// tlsRoots is the trust store used to verify certificate chains.
// nil means the system store; tests replace it.
var tlsRoots *x509.CertPool

// lookupHost and dialTCP are how the TLS checker resolves and connects.
// Tests replace them to put several fake addresses behind one hostname.
var (
	lookupHost = net.DefaultResolver.LookupHost
	dialTCP    = (&net.Dialer{}).DialContext
)

type TLSChecker struct{}

func (TLSChecker) Type() string { return "tls" }

// Check returns the earliest expiry in the certificate chain the server
// presents, so an intermediate that runs out before the leaf is caught.
// An already expired certificate is returned as a past time rather than an
// error, so it is reported as CRITICAL with a negative day count.
func (c TLSChecker) Check(ctx context.Context, t Target) (time.Time, error) {
	expires, _, err := c.CheckWithNote(ctx, t)
	return expires, err
}

// CheckWithNote is Check plus a note for the report. With all_ips it checks
// every address the hostname resolves to, with SNI set to the hostname, and
// the note says which address served the earliest expiry.
func (TLSChecker) CheckWithNote(ctx context.Context, t Target) (time.Time, string, error) {
	host := t.Address
	port := "443"
	if h, p, err := net.SplitHostPort(t.Address); err == nil {
		host = h
		port = p
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		return time.Time{}, "", fmt.Errorf("missing host in %q", t.Address)
	}
	if !t.AllIPs {
		expires, err := checkTLSAddr(ctx, host, net.JoinHostPort(host, port))
		return expires, "", err
	}

	ips, err := resolveIPs(ctx, host)
	if err != nil {
		return time.Time{}, "", err
	}
	type ipResult struct {
		expires time.Time
		err     error
	}
	results := make([]ipResult, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			expires, err := checkTLSAddr(ctx, host, net.JoinHostPort(ip, port))
			results[i] = ipResult{expires, err}
		}(i, ip)
	}
	wg.Wait()

	// One bad node is what this option exists to catch, so any failure makes
	// the whole target an error, naming the address.
	var errs []string
	for i, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ips[i], r.err))
		}
	}
	if len(errs) > 0 {
		return time.Time{}, "", errors.New(strings.Join(errs, "; "))
	}
	earliest := 0
	for i, r := range results {
		if r.expires.Before(results[earliest].expires) {
			earliest = i
		}
	}
	note := fmt.Sprintf("earliest on %s, %d IPs checked", ips[earliest], len(ips))
	if len(ips) == 1 {
		note = fmt.Sprintf("on %s, 1 IP checked", ips[0])
	}
	return results[earliest].expires, note, nil
}

// resolveIPs returns the host's addresses, sorted and without duplicates.
// An IP literal resolves to itself.
func resolveIPs(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	addrs, err := lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var ips []string
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		ips = append(ips, ip.String())
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	sort.Strings(ips)
	return ips, nil
}

// checkTLSAddr connects to addr, sends host as SNI and returns the chain's expiry.
func checkTLSAddr(ctx context.Context, host, addr string) (time.Time, error) {
	conn, err := dialTCP(ctx, "tcp", addr)
	if err != nil {
		return time.Time{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// Verification is done by hand below so that an expired certificate can
	// still be inspected. Nothing is sent over this connection.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return time.Time{}, err
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no peer certificate presented")
	}
	return chainExpiry(certs, host, time.Now())
}

func chainExpiry(certs []*x509.Certificate, host string, now time.Time) (time.Time, error) {
	if earliest := earliestExpiry(certs); now.After(earliest) {
		return earliest, nil
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
		Roots:         tlsRoots,
		CurrentTime:   now,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate verification failed: %w", err)
	}

	// A client may use any of the valid chains, so the chain that lasts
	// longest decides when the site actually breaks.
	var best time.Time
	for _, chain := range chains {
		if e := earliestExpiry(chain); e.After(best) {
			best = e
		}
	}
	return best, nil
}

func earliestExpiry(certs []*x509.Certificate) time.Time {
	earliest := certs[0].NotAfter
	for _, c := range certs[1:] {
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}
	return earliest
}
