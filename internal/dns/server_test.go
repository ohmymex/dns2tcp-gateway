package dns

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/config"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
	"github.com/ohmymex/dns2tcp-gateway/internal/tunnel"
)

func testConfig(addr string) config.Config {
	return config.Config{
		Domains:      []string{"test.io"},
		DNSAddr:      addr,
		APIAddr:      ":0",
		Nameservers:  []string{"ns1.test.io", "ns2.test.io"},
		GatewayIP:    "10.0.0.1",
		SessionTTL:   1 * time.Hour,
		DNSUDPSize:   4096,
		AdminContact: "admin.test.io",
	}
}

func startTestServer(t *testing.T) (*Server, session.Store, string) {
	t.Helper()

	// Find a free port for the test DNS server.
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := ln.LocalAddr().String()
	ln.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := session.NewMemoryStore(logger)
	cfg := testConfig(addr)

	tunnelMgr := tunnel.NewManager(store, "", logger)
	srv := New(cfg, store, tunnelMgr, logger)
	if err := srv.Start(); err != nil {
		t.Fatalf("starting dns server: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	return srv, store, addr
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)

	client := new(dns.Client)
	client.Timeout = 2 * time.Second
	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("dns query for %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

func TestSOAQuery(t *testing.T) {
	_, _, addr := startTestServer(t)

	resp := query(t, addr, "test.io", dns.TypeSOA)

	if len(resp.Answer) == 0 {
		t.Fatal("expected SOA answer, got none")
	}
	soa, ok := resp.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("expected SOA record, got %T", resp.Answer[0])
	}
	if soa.Ns != "ns1.test.io." {
		t.Errorf("SOA ns = %q, want %q", soa.Ns, "ns1.test.io.")
	}
	if soa.Minttl != 1 {
		t.Errorf("SOA minttl = %d, want 1", soa.Minttl)
	}
	if !resp.Authoritative {
		t.Error("expected authoritative response")
	}
}

func TestNSQuery(t *testing.T) {
	_, _, addr := startTestServer(t)

	resp := query(t, addr, "test.io", dns.TypeNS)

	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 NS answers, got %d", len(resp.Answer))
	}

	for _, rr := range resp.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			t.Fatalf("expected NS record, got %T", rr)
		}
		if ns.Ns != "ns1.test.io." && ns.Ns != "ns2.test.io." {
			t.Errorf("unexpected NS target: %s", ns.Ns)
		}
	}

	// Should have glue A records in extra section.
	if len(resp.Extra) == 0 {
		t.Error("expected glue records in extra section")
	}
}

func TestWildcardAQuery(t *testing.T) {
	_, _, addr := startTestServer(t)

	resp := query(t, addr, "anything.test.io", dns.TypeA)

	if len(resp.Answer) == 0 {
		t.Fatal("expected A answer for wildcard subdomain")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if a.A.String() != "10.0.0.1" {
		t.Errorf("A record = %s, want 10.0.0.1", a.A.String())
	}
	if a.Hdr.Ttl != 0 {
		t.Errorf("wildcard TTL = %d, want 0 (no caching for tunnel subdomains)", a.Hdr.Ttl)
	}
}

func TestTXTQueryWithSession(t *testing.T) {
	_, store, addr := startTestServer(t)

	// Create a session.
	sess := &session.Session{
		ID:         "test-id-123",
		Subdomain:  "abc123",
		Mode:       session.ModeTCP,
		TargetIP:   "1.2.3.4",
		TargetPort: 22,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		OwnerIP:    "127.0.0.1",
	}
	if err := store.Put(context.Background(), sess); err != nil {
		t.Fatalf("storing session: %v", err)
	}

	resp := query(t, addr, "abc123.test.io", dns.TypeTXT)

	if len(resp.Answer) == 0 {
		t.Fatal("expected TXT answer for session subdomain")
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", resp.Answer[0])
	}
	if len(txt.Txt) == 0 {
		t.Fatal("expected non-empty TXT data")
	}
}

func TestTXTQueryNoSession(t *testing.T) {
	_, _, addr := startTestServer(t)

	resp := query(t, addr, "nonexistent.test.io", dns.TypeTXT)

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestNSDelegation(t *testing.T) {
	_, store, addr := startTestServer(t)

	// Create an NS mode session.
	sess := &session.Session{
		ID:         "ns-test-123",
		Subdomain:  "nstest",
		Mode:       session.ModeNS,
		TargetIP:   "5.6.7.8",
		TargetPort: 53,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		OwnerIP:    "127.0.0.1",
	}
	if err := store.Put(context.Background(), sess); err != nil {
		t.Fatalf("storing session: %v", err)
	}

	resp := query(t, addr, "nstest.test.io", dns.TypeNS)

	if len(resp.Answer) == 0 {
		t.Fatal("expected NS answer for delegated subdomain")
	}
	ns, ok := resp.Answer[0].(*dns.NS)
	if !ok {
		t.Fatalf("expected NS record, got %T", resp.Answer[0])
	}
	if ns.Ns != "5.6.7.8." {
		t.Errorf("NS target = %q, want %q", ns.Ns, "5.6.7.8.")
	}
}
