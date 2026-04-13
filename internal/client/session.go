package client

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
)

const commandTimeout = 5 * time.Second

/* Session handles the dns2tcp handshake: auth, resource listing, and connect.
 * All operations are synchronous request-response over the transport. */
type Session struct {
	transport Transport
	domain    string
	key       string
	sessionID uint16
	logger    *slog.Logger
}

/* NewSession creates a session handler for the given tunnel domain.
 * domain is the full tunnel domain including subdomain (e.g. "m6kfjz.tun.numex.sh"). */
func NewSession(transport Transport, domain, key string, logger *slog.Logger) *Session {
	return &Session{
		transport: transport,
		domain:    strings.TrimSuffix(domain, "."),
		key:       key,
		logger:    logger,
	}
}

/* Authenticate performs the 2-step CHAP handshake with the server.
 * Step 1: request a challenge. Step 2: respond with HMAC-SHA1. */
func (s *Session) Authenticate(_ context.Context) error {
	// Step 1: request challenge (session_id=0 signals new client).
	step1 := &protocol.Packet{
		SessionID: 0,
		Seq:       1,
		Type:      protocol.TypeOK,
	}

	resp, err := s.sendCommand(step1, protocol.CmdAuth)
	if err != nil {
		return fmt.Errorf("auth step 1: %w", err)
	}
	if resp.Type == protocol.TypeErr {
		return fmt.Errorf("auth step 1 rejected: %s", resp.Payload)
	}

	s.sessionID = resp.SessionID
	challenge := string(resp.Payload)
	s.logger.Info("auth challenge received", "session_id", s.sessionID)

	// Step 2: send HMAC-SHA1(key, challenge).
	hmacResp := protocol.ComputeHMAC(s.key, challenge)

	step2 := &protocol.Packet{
		SessionID: s.sessionID,
		Seq:       2,
		Type:      protocol.TypeOK,
		Payload:   []byte(hmacResp),
	}

	resp2, err := s.sendCommand(step2, protocol.CmdAuth)
	if err != nil {
		return fmt.Errorf("auth step 2: %w", err)
	}
	if resp2.Type == protocol.TypeErr {
		return fmt.Errorf("auth failed: %s", resp2.Payload)
	}

	s.logger.Info("authenticated", "session_id", s.sessionID)
	return nil
}

/* ListResources queries the server for available tunnel resources.
 * Returns the raw resource string (e.g. "tunnel:1.2.3.4:22"). */
func (s *Session) ListResources(_ context.Context) (string, error) {
	pkt := &protocol.Packet{
		SessionID: s.sessionID,
		Seq:       3,
		Type:      protocol.TypeOK,
	}

	resp, err := s.sendCommand(pkt, protocol.CmdResource)
	if err != nil {
		return "", fmt.Errorf("resource list: %w", err)
	}
	if resp.Type == protocol.TypeErr {
		return "", fmt.Errorf("resource list error: %s", resp.Payload)
	}

	return string(resp.Payload), nil
}

// Connect tells the server to open a TCP connection to the named resource.
func (s *Session) Connect(_ context.Context, resource string) error {
	pkt := &protocol.Packet{
		SessionID: s.sessionID,
		Seq:       4,
		Type:      protocol.TypeOK,
		Payload:   []byte(resource),
	}

	resp, err := s.sendCommand(pkt, protocol.CmdConnect)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if resp.Type == protocol.TypeErr {
		return fmt.Errorf("connect rejected: %s", resp.Payload)
	}

	s.logger.Info("connected to resource", "resource", resource)
	return nil
}

// SessionID returns the session ID assigned by the server during auth.
func (s *Session) SessionID() uint16 {
	return s.sessionID
}

/* sendCommand builds a DNS TXT query for a protocol command and waits
 * for the server's response. Retries up to 3 times on timeout. */
func (s *Session) sendCommand(pkt *protocol.Packet, command string) (*protocol.Packet, error) {
	qname := protocol.EncodeQuery(pkt, command, s.domain)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			msg.Id = dns.Id()
			s.logger.Debug("retrying command", "command", command, "attempt", attempt+1)
		}

		resp, err := s.transport.SendAndReceive(msg, commandTimeout)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("DNS error: %s", dns.RcodeToString[resp.Rcode])
		}

		for _, rr := range resp.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				return protocol.DecodeTXTResponse(txt.Txt)
			}
		}
		return nil, fmt.Errorf("no TXT record in DNS response")
	}

	return nil, fmt.Errorf("command %q failed after 3 attempts: %w", command, lastErr)
}
