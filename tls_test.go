package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCert(t *testing.T, name string, notAfter time.Time, parent *testCert, isCA bool) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"lb.test"}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: cert, key: key}
}

// serveTLS starts a TLS listener presenting chain (leaf first) and returns its address.
func serveTLS(t *testing.T, chain ...*testCert) string {
	t.Helper()
	tc := tls.Certificate{PrivateKey: chain[0].key, Leaf: chain[0].cert}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.cert.Raw)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tc}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
				conn.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().String()
}

func useRoots(t *testing.T, roots ...*testCert) {
	t.Helper()
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r.cert)
	}
	old := tlsRoots
	tlsRoots = pool
	t.Cleanup(func() { tlsRoots = old })
}

func checkTLS(t *testing.T, addr string) (time.Time, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return TLSChecker{}.Check(ctx, Target{Type: "tls", Address: addr})
}

func TestTLSIntermediateExpiresFirst(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	inter := newTestCert(t, "intermediate", now.Add(10*24*time.Hour), root, true)
	leaf := newTestCert(t, "leaf", now.Add(90*24*time.Hour), inter, false)
	useRoots(t, root)

	got, err := checkTLS(t, serveTLS(t, leaf, inter))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !got.Equal(inter.cert.NotAfter) {
		t.Errorf("Check() = %v, want intermediate expiry %v", got, inter.cert.NotAfter)
	}
}

func TestTLSLeafExpiry(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	leaf := newTestCert(t, "leaf", now.Add(45*24*time.Hour), root, false)
	useRoots(t, root)

	got, err := checkTLS(t, serveTLS(t, leaf))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !got.Equal(leaf.cert.NotAfter) {
		t.Errorf("Check() = %v, want leaf expiry %v", got, leaf.cert.NotAfter)
	}
}

func TestTLSExpiredIsReportedNotErrored(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	leaf := newTestCert(t, "leaf", now.Add(-24*time.Hour), root, false)
	useRoots(t, root)

	got, err := checkTLS(t, serveTLS(t, leaf))
	if err != nil {
		t.Fatalf("Check() error = %v, want expired time", err)
	}
	if days := daysUntil(got, now); days >= 0 {
		t.Errorf("daysUntil = %d, want negative", days)
	}
}

func TestTLSUntrustedChainErrors(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	other := newTestCert(t, "other root", now.Add(3650*24*time.Hour), nil, true)
	leaf := newTestCert(t, "leaf", now.Add(90*24*time.Hour), root, false)
	useRoots(t, other)

	_, err := checkTLS(t, serveTLS(t, leaf))
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("Check() error = %v, want verification failure", err)
	}
}
