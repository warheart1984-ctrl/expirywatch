package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNetwork makes "lb.test" resolve to the given fake IPs and routes a
// dial to <ip>:443 to that IP's local listener. It returns a counter of
// lookups.
func fakeNetwork(t *testing.T, nodes map[string]string, extraAddrs ...string) *atomic.Int32 {
	t.Helper()
	var lookups atomic.Int32
	oldLookup, oldDial := lookupHost, dialTCP
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		lookups.Add(1)
		if host != "lb.test" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var addrs []string
		for ip := range nodes {
			addrs = append(addrs, ip)
		}
		return append(addrs, extraAddrs...), nil
	}
	dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ip, port, _ := net.SplitHostPort(addr)
		local, ok := nodes[ip]
		if !ok || port != "443" {
			return nil, errors.New("fake network: no route to " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, local)
	}
	t.Cleanup(func() { lookupHost, dialTCP = oldLookup, oldDial })
	return &lookups
}

// serveTLSRecordSNI is serveTLS that also records the SNI names it was sent.
func serveTLSRecordSNI(t *testing.T, leaf *testCert) (string, func() []string) {
	t.Helper()
	cert := tls.Certificate{Certificate: [][]byte{leaf.cert.Raw}, PrivateKey: leaf.key, Leaf: leaf.cert}
	var mu sync.Mutex
	var names []string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			names = append(names, hello.ServerName)
			mu.Unlock()
			return &cert, nil
		},
	})
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
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

func checkAllIPs(t *testing.T, address string) (time.Time, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return TLSChecker{}.CheckWithNote(ctx, Target{Type: "tls", Address: address, AllIPs: true})
}

func TestAllIPsFindsStaleNode(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	fresh1 := newTestCert(t, "fresh 1", now.Add(80*24*time.Hour), root, false)
	stale := newTestCert(t, "stale", now.Add(10*24*time.Hour), root, false)
	fresh2 := newTestCert(t, "fresh 2", now.Add(85*24*time.Hour), root, false)
	useRoots(t, root)

	addr1, sni1 := serveTLSRecordSNI(t, fresh1)
	addr2, sni2 := serveTLSRecordSNI(t, stale)
	addr3, sni3 := serveTLSRecordSNI(t, fresh2)
	// 192.0.2.2 is listed twice, as resolvers sometimes do.
	fakeNetwork(t, map[string]string{"192.0.2.1": addr1, "192.0.2.2": addr2, "192.0.2.3": addr3}, "192.0.2.2")

	got, note, err := checkAllIPs(t, "lb.test:443")
	if err != nil {
		t.Fatalf("CheckWithNote: %v", err)
	}
	if !got.Equal(stale.cert.NotAfter) {
		t.Errorf("expiry = %v, want the stale node's %v", got, stale.cert.NotAfter)
	}
	if note != "earliest on 192.0.2.2, 3 IPs checked" {
		t.Errorf("note = %q", note)
	}
	for i, sni := range [][]string{sni1(), sni2(), sni3()} {
		if len(sni) != 1 || sni[0] != "lb.test" {
			t.Errorf("node %d got SNI %q, want exactly one handshake for lb.test", i+1, sni)
		}
	}
}

func TestAllIPsBadNodeIsAnError(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	other := newTestCert(t, "other root", now.Add(3650*24*time.Hour), nil, true)
	good := newTestCert(t, "good", now.Add(80*24*time.Hour), root, false)
	bad := newTestCert(t, "bad", now.Add(80*24*time.Hour), other, false)
	useRoots(t, root)

	addrGood, _ := serveTLSRecordSNI(t, good)
	addrBad, _ := serveTLSRecordSNI(t, bad)
	fakeNetwork(t, map[string]string{"192.0.2.1": addrGood, "192.0.2.9": addrBad})

	_, _, err := checkAllIPs(t, "lb.test")
	if err == nil {
		t.Fatal("CheckWithNote err = nil, want the bad node's error")
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "192.0.2.9: certificate verification failed") || strings.Contains(msg, "192.0.2.1") {
		t.Errorf("err = %q, want only 192.0.2.9's verification failure", msg)
	}
}

func TestAllIPsSingleAddressAndLiteral(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	leaf := newTestCert(t, "leaf", now.Add(40*24*time.Hour), root, false)
	useRoots(t, root)
	addr, _ := serveTLSRecordSNI(t, leaf)

	fakeNetwork(t, map[string]string{"192.0.2.5": addr})
	if _, note, err := checkAllIPs(t, "lb.test"); err != nil || note != "on 192.0.2.5, 1 IP checked" {
		t.Errorf("one address: note %q, err %v", note, err)
	}

	// An IP literal needs no lookup. The certificate is for 127.0.0.1.
	lookups := fakeNetwork(t, nil)
	dialTCP = (&net.Dialer{}).DialContext
	_, port, _ := net.SplitHostPort(addr)
	if _, note, err := checkAllIPs(t, net.JoinHostPort("127.0.0.1", port)); err != nil || note != "on 127.0.0.1, 1 IP checked" {
		t.Errorf("IP literal: note %q, err %v", note, err)
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("IP literal did %d lookups, want 0", n)
	}
}

func TestAllIPsLookupFails(t *testing.T) {
	fakeNetwork(t, nil)
	_, _, err := checkAllIPs(t, "nowhere.test")
	if err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("err = %v, want a lookup error", err)
	}
}

func TestWithoutAllIPsNoLookup(t *testing.T) {
	now := time.Now()
	root := newTestCert(t, "root", now.Add(3650*24*time.Hour), nil, true)
	leaf := newTestCert(t, "leaf", now.Add(40*24*time.Hour), root, false)
	useRoots(t, root)
	lookups := fakeNetwork(t, nil)
	dialTCP = (&net.Dialer{}).DialContext

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, note, err := TLSChecker{}.CheckWithNote(ctx, Target{Type: "tls", Address: serveTLS(t, leaf)})
	if err != nil || note != "" {
		t.Errorf("note %q, err %v; want no note and no error", note, err)
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("did %d lookups without all_ips, want 0", n)
	}
}

func TestAllIPsConfig(t *testing.T) {
	if _, err := LoadConfig(writeConfig(t, `{"targets": [{"type": "tls", "address": "example.com", "all_ips": true}]}`)); err != nil {
		t.Errorf("tls with all_ips: %v", err)
	}
	_, err := LoadConfig(writeConfig(t, `{"targets": [{"name": "d", "type": "domain", "address": "example.com", "all_ips": true}]}`))
	if err == nil || !strings.Contains(err.Error(), `target "d": all_ips only applies to tls targets`) {
		t.Errorf("domain with all_ips: err = %v", err)
	}
}

func TestNoteInReports(t *testing.T) {
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	results := []Result{{Name: "lb", Address: "lb.test:443", Status: StatusWarn, ExpiresAt: &exp, DaysLeft: intPtr(12), Note: "earliest on 192.0.2.2, 3 IPs checked"}}

	msg := formatMessage(webhookPayload{Summary: summarize(results), Results: results})
	if want := "- WARN lb (lb.test:443): expires 2026-11-01 (12 days left), earliest on 192.0.2.2, 3 IPs checked"; !strings.Contains(msg, want) {
		t.Errorf("message:\n%s\nwant line %q", msg, want)
	}

	var b strings.Builder
	printResults(results, &b)
	if want := "note: lb (lb.test:443): earliest on 192.0.2.2, 3 IPs checked"; !strings.Contains(b.String(), want) {
		t.Errorf("table output:\n%s\nwant line %q", b.String(), want)
	}
}
