package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// tlsRoots is the trust store used to verify certificate chains.
// nil means the system store; tests replace it.
var tlsRoots *x509.CertPool

type TLSChecker struct{}

func (TLSChecker) Type() string { return "tls" }

// Check returns the earliest expiry in the certificate chain the server
// presents, so an intermediate that runs out before the leaf is caught.
// An already expired certificate is returned as a past time rather than an
// error, so it is reported as CRITICAL with a negative day count.
func (TLSChecker) Check(ctx context.Context, t Target) (time.Time, error) {
	host := t.Address
	port := "443"
	if h, p, err := net.SplitHostPort(t.Address); err == nil {
		host = h
		port = p
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		return time.Time{}, fmt.Errorf("missing host in %q", t.Address)
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
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
