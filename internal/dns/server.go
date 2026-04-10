package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/config"
	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
	"github.com/ohmymex/dns2tcp-gateway/internal/tunnel"
)

// Server is an authoritative DNS server for the gateway zone.
type Server struct {
	udp     *dns.Server
	tcp     *dns.Server
	store   session.Store
	tunnel  *tunnel.Manager
	cfg     config.Config
	logger  *slog.Logger
}

// New creates a new DNS server wired to the given session store, tunnel manager, and config.
func New(cfg config.Config, store session.Store, tunnelMgr *tunnel.Manager, logger *slog.Logger) *Server {
	s := &Server{
		store:  store,
		tunnel: tunnelMgr,
		cfg:    cfg,
		logger: logger.With("component", "dns"),
	}

	mux := dns.NewServeMux()
	// Register the query handler for each configured domain zone.
	for _, zone := range cfg.FQDNs() {
		mux.HandleFunc(zone, s.handleQuery)
	}

	s.udp = &dns.Server{
		Addr:    cfg.DNSAddr,
		Net:     "udp",
		Handler: mux,
		UDPSize: int(cfg.DNSUDPSize),
	}

	s.tcp = &dns.Server{
		Addr:    cfg.DNSAddr,
		Net:     "tcp",
		Handler: mux,
	}

	return s
}

// Start launches the UDP and TCP DNS listeners. It blocks until both servers
// are ready or one of them fails. Use Shutdown to stop.
func (s *Server) Start() error {
	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	errCh := make(chan error, 2)

	s.udp.NotifyStartedFunc = func() { close(udpReady) }
	s.tcp.NotifyStartedFunc = func() { close(tcpReady) }

	go func() {
		if err := s.udp.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("dns udp: %w", err)
		}
	}()

	go func() {
		if err := s.tcp.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("dns tcp: %w", err)
		}
	}()

	// Wait for both listeners to be ready, or fail fast on error.
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			return err
		case <-udpReady:
			udpReady = nil // already received, avoid double-select
		case <-tcpReady:
			tcpReady = nil
		}
	}

	s.logger.Info("dns server listening",
		"addr", s.cfg.DNSAddr,
		"zones", s.cfg.FQDNs(),
		"udp_size", s.cfg.DNSUDPSize,
	)
	return nil
}

// Shutdown gracefully stops the DNS server.
func (s *Server) Shutdown(ctx context.Context) error {
	udpErr := s.udp.ShutdownContext(ctx)
	tcpErr := s.tcp.ShutdownContext(ctx)

	if udpErr != nil {
		return fmt.Errorf("dns udp shutdown: %w", udpErr)
	}
	if tcpErr != nil {
		return fmt.Errorf("dns tcp shutdown: %w", tcpErr)
	}
	return nil
}

// matchZone returns the FQDN zone that the query name belongs to.
// It iterates through all configured domains and returns the first match.
// Falls back to the primary domain if no match is found (shouldn't happen
// because the mux only routes matching queries to us).
func (s *Server) matchZone(qname string) string {
	qname = dns.CanonicalName(qname)
	for _, zone := range s.cfg.FQDNs() {
		canonical := dns.CanonicalName(zone)
		if qname == canonical || strings.HasSuffix(qname, "."+canonical) {
			return zone
		}
	}
	return s.cfg.PrimaryFQDN()
}

// handleQuery is the main DNS query handler for the zone.
func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = false
	msg.Compress = true

	if len(r.Question) == 0 {
		msg.SetRcode(r, dns.RcodeFormatError)
		s.writeMsg(w, msg)
		return
	}

	q := r.Question[0]
	s.logger.Debug("dns query",
		"name", q.Name,
		"type", dns.TypeToString[q.Qtype],
		"remote", w.RemoteAddr().String(),
	)

	// Determine which configured zone this query belongs to.
	zone := s.matchZone(q.Name)

	switch q.Qtype {
	case dns.TypeSOA:
		msg.Answer = append(msg.Answer, s.soaRecord(zone))
	case dns.TypeNS:
		s.handleNS(msg, q, zone)
	case dns.TypeA:
		s.handleA(msg, q, zone)
	case dns.TypeTXT:
		s.handleTXT(msg, q, zone)
	case dns.TypeANY:
		msg.Answer = append(msg.Answer, s.soaRecord(zone))
		for _, ns := range s.nsRecords(zone) {
			msg.Answer = append(msg.Answer, ns)
		}
	default:
		// For unsupported types, return SOA in authority section (proper NODATA response).
		msg.Ns = append(msg.Ns, s.soaRecord(zone))
	}

	// EDNS0: mirror the client's OPT record if present.
	if opt := r.IsEdns0(); opt != nil {
		edns := new(dns.OPT)
		edns.Hdr.Name = "."
		edns.Hdr.Rrtype = dns.TypeOPT
		edns.SetUDPSize(opt.UDPSize())
		msg.Extra = append(msg.Extra, edns)
	}

	s.writeMsg(w, msg)
}

func (s *Server) handleNS(msg *dns.Msg, q dns.Question, zone string) {
	// Check if this is a session subdomain with NS mode.
	subdomain := extractSubdomain(q.Name, zone)
	if subdomain != "" {
		sess, ok := s.store.Get(context.Background(), subdomain)
		if ok && sess.Mode == session.ModeNS {
			// Delegate to the user's nameserver.
			nsTarget := dns.Fqdn(sess.TargetIP)
			msg.Answer = append(msg.Answer, &dns.NS{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				Ns: nsTarget,
			})
			// Add glue A record if the NS target is an IP.
			if ip := net.ParseIP(sess.TargetIP); ip != nil && ip.To4() != nil {
				msg.Extra = append(msg.Extra, &dns.A{
					Hdr: dns.RR_Header{
						Name:   nsTarget,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					A: ip.To4(),
				})
			}
			return
		}
	}

	// Zone-level NS query: return our nameservers.
	for _, ns := range s.nsRecords(q.Name) {
		msg.Answer = append(msg.Answer, ns)
	}

	// Add glue A records for our nameservers.
	gwIP := net.ParseIP(s.cfg.GatewayIP)
	if gwIP != nil {
		for _, nsName := range s.cfg.Nameservers {
			msg.Extra = append(msg.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(nsName),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: gwIP.To4(),
			})
		}
	}
}

func (s *Server) handleA(msg *dns.Msg, q dns.Question, zone string) {
	gwIP := net.ParseIP(s.cfg.GatewayIP).To4()

	// For the zone apex or any known subdomain, return our gateway IP.
	// This is the "wildcard" behavior, same as interactsh.
	name := q.Name
	subdomain := extractSubdomain(name, zone)

	ttl := uint32(60)
	if subdomain != "" {
		// Tunnel subdomain queries get low TTL to prevent caching.
		ttl = 0
	}

	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: gwIP,
	})
}

func (s *Server) handleTXT(msg *dns.Msg, q dns.Question, zone string) {

	// Try to decode as dns2tcp protocol query.
	parsed, err := protocol.DecodeQuery(q.Name, zone)
	if err != nil {
		s.logger.Debug("not a dns2tcp query, treating as plain", "name", q.Name, "error", err)
		s.handlePlainTXT(msg, q, zone)
		return
	}

	if parsed.Packet == nil && parsed.Command == "" {
		s.handlePlainTXT(msg, q, zone)
		return
	}

	// Route through tunnel manager.
	resp, err := s.tunnel.HandleQuery(context.Background(), parsed)
	if err != nil {
		s.logger.Debug("tunnel query failed, falling back to plain", "error", err, "name", q.Name)
		s.handlePlainTXT(msg, q, zone)
		return
	}

	// If the tunnel manager doesn't recognize the session and there's no
	// active command, fall back to plain TXT handling. This prevents random
	// subdomains from being treated as tunnel protocol queries.
	if resp.Type == protocol.TypeErr && parsed.Command == "" {
		s.handlePlainTXT(msg, q, zone)
		return
	}

	// Encode response as TXT record, split into 63-byte chunks.
	// The dns2tcp C client expects DNS-label-style encoding (max 63 bytes
	// per character-string). miekg/dns encodes each Txt slice entry as a
	// separate character-string with a length prefix, matching this format.
	chunks := protocol.EncodeTXTChunks(resp, 0)
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: chunks,
	})
}

func (s *Server) handlePlainTXT(msg *dns.Msg, q dns.Question, zone string) {
	subdomain := extractSubdomain(q.Name, zone)

	if subdomain == "" {
		msg.Ns = append(msg.Ns, s.soaRecord(zone))
		return
	}

	sess, ok := s.store.Get(context.Background(), subdomain)
	if !ok {
		msg.SetRcode(msg, dns.RcodeNameError)
		msg.Ns = append(msg.Ns, s.soaRecord(zone))
		return
	}

	txt := fmt.Sprintf("session=%s mode=%s target=%s", sess.ID, sess.Mode, sess.Target())
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: []string{txt},
	})
}

func (s *Server) soaRecord(zone string) *dns.SOA {
	ns := "ns1." + zone
	if len(s.cfg.Nameservers) > 0 {
		ns = dns.Fqdn(s.cfg.Nameservers[0])
	}

	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      ns,
		Mbox:    dns.Fqdn(s.cfg.AdminContact),
		Serial:  uint32(time.Now().Unix()),
		Refresh: 3600,
		Retry:   900,
		Expire:  86400,
		Minttl:  1, // Low negative cache TTL, critical for tunnel operations.
	}
}

func (s *Server) nsRecords(zone string) []dns.RR {
	records := make([]dns.RR, 0, len(s.cfg.Nameservers))
	for _, ns := range s.cfg.Nameservers {
		records = append(records, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ns: dns.Fqdn(ns),
		})
	}
	return records
}

func (s *Server) writeMsg(w dns.ResponseWriter, msg *dns.Msg) {
	if err := w.WriteMsg(msg); err != nil {
		s.logger.Error("failed to write dns response", "error", err)
	}
}
