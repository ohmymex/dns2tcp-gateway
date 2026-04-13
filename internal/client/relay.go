package client

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/miekg/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
)

/*
 * Sliding window constants matching the C dns2tcpc client.
 * QUEUE_SIZE = 48, WINDOW_SIZE = QUEUE_SIZE/2 = 24 max outstanding queries,
 * NOP_SIZE = WINDOW_SIZE/3 = 8 minimum NOP polls maintained,
 * MAX_DATA = WINDOW_SIZE - NOP_SIZE = 16 max data queries in flight.
 */
const (
	queueSize  = 48
	windowSize = queueSize / 2  // max outstanding queries
	nopSize    = windowSize / 3 // min NOP polls to maintain
	maxDataOut = windowSize - nopSize

	retryAfter = 1 * time.Second  // resend after this (C client: REPLY_TIMEOUT=1)
	maxErrors  = 10               // consecutive DNS errors before giving up
	tickRate   = 100 * time.Millisecond
)

type windowSlot struct {
	seq    uint16
	txID   uint16
	sentAt time.Time
	isNOP  bool
	packed []byte // raw DNS message bytes (for resend with new txID)
}

/*
 * Relay handles steady-state bidirectional data transfer over the DNS tunnel.
 *
 * Upstream (local -> server): reads local TCP/stdin, sends as DNS TXT queries.
 * Downstream (server -> local): receives TXT responses, writes to local TCP/stdout.
 *
 * Maintains a sliding window of outstanding queries matching the C client's
 * behavior: NOP polls keep the pipeline full, data queries carry upstream payload.
 * Queries that don't get a response within retryAfter are resent with a new txID.
 */
type Relay struct {
	transport  Transport
	local      io.ReadWriteCloser
	domain     string
	sessionID  uint16
	maxPayload int
	logger     *slog.Logger

	seq         uint16                  // next sequence number
	window      map[uint16]*windowSlot  // seq -> slot
	txToSeq     map[uint16]uint16       // DNS txID -> seq
	outstanding int
	nopPending  int
	dataPending int

	upBuf  []byte // buffered upstream data waiting to be sent
	errors int    // consecutive DNS errors

	/*
	 * Downstream ordering buffer. DNS responses arrive out of order through
	 * public resolvers. We buffer by seq and flush to local in order,
	 * same pattern as the server's incomingBuf/flushIncoming.
	 */
	downBuf     map[uint16][]byte // downstream data buffered by seq
	downSeen    map[uint16]bool   // seqs seen (including empty NOP responses)
	nextDownSeq uint16            // next seq to write to local
}

// NewRelay creates a relay for an authenticated and connected tunnel session.
func NewRelay(transport Transport, local io.ReadWriteCloser, domain string, sessionID uint16, logger *slog.Logger) *Relay {
	return &Relay{
		transport:  transport,
		local:      local,
		domain:     domain,
		sessionID:  sessionID,
		maxPayload: protocol.MaxQueryPayload(domain),
		logger:      logger.With("component", "relay"),
		window:      make(map[uint16]*windowSlot),
		txToSeq:     make(map[uint16]uint16),
		downBuf:     make(map[uint16][]byte),
		downSeen:    make(map[uint16]bool),
		nextDownSeq: 1, // relay seqs start at 1 (nextSeq skips 0)
	}
}

/* Run starts the bidirectional relay loop. Blocks until ctx is cancelled,
 * the server sends DESAUTH, or a fatal error occurs. */
func (r *Relay) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	respCh := r.transport.Responses()
	localCh := make(chan []byte, 16)
	errCh := make(chan error, 2)

	// Local reader: TCP socket or stdin.
	go func() {
		buf := make([]byte, r.maxPayload)
		for {
			n, err := r.local.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case localCh <- data:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errCh <- err
				return
			}
		}
	}()

	ticker := time.NewTicker(tickRate)
	defer ticker.Stop()

	r.logger.Info("relay started", "max_payload", r.maxPayload)

	for {
		r.fillNOPs()

		select {
		case msg := <-respCh:
			done, err := r.handleResponse(msg)
			if err != nil {
				r.logger.Debug("response handling error", "error", err)
			}
			if done {
				return nil
			}
			r.drainUpstream()

		case data := <-localCh:
			r.upBuf = append(r.upBuf, data...)
			r.drainUpstream()

		case <-ticker.C:
			r.checkRetries()

		case err := <-errCh:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Local connection closed. Drain remaining data, then disconnect.
			r.drainUpstream()
			r.sendDesauth()
			return err

		case <-ctx.Done():
			r.sendDesauth()
			return ctx.Err()
		}
	}
}

/* nextSeq increments and returns the next sequence number, skipping zero.
 * Matches C client: if (!++client->num_seq) client->num_seq++; */
func (r *Relay) nextSeq() uint16 {
	r.seq++
	if r.seq == 0 {
		r.seq = 1
	}
	return r.seq
}

/* fillNOPs sends NOP queries to maintain the minimum NOP pool size.
 * The server uses NOP responses to push downstream data. */
func (r *Relay) fillNOPs() {
	for r.nopPending < nopSize && r.outstanding < windowSize {
		if err := r.sendNOP(); err != nil {
			r.logger.Debug("NOP send failed", "error", err)
			return
		}
	}
}

func (r *Relay) sendNOP() error {
	seq := r.nextSeq()
	pkt := &protocol.Packet{
		SessionID: r.sessionID,
		Seq:       seq,
		Type:      protocol.TypeNOP,
	}

	packed, txID, err := r.buildAndSend(pkt, "")
	if err != nil {
		return err
	}

	if old, collision := r.txToSeq[txID]; collision {
		r.logger.Warn("txid collision on NOP", "txid", txID, "new_seq", seq, "old_seq", old)
	}
	r.window[seq] = &windowSlot{
		seq:    seq,
		txID:   txID,
		sentAt: time.Now(),
		isNOP:  true,
		packed: packed,
	}
	r.txToSeq[txID] = seq
	r.outstanding++
	r.nopPending++
	return nil
}

/* drainUpstream sends buffered local data as DNS queries, respecting
 * the sliding window limits (max outstanding, max data queries). */
func (r *Relay) drainUpstream() {
	for len(r.upBuf) > 0 && r.dataPending < maxDataOut && r.outstanding < windowSize {
		n := len(r.upBuf)
		if n > r.maxPayload {
			n = r.maxPayload
		}

		seq := r.nextSeq()
		pkt := &protocol.Packet{
			SessionID: r.sessionID,
			Seq:       seq,
			Type:      protocol.TypeData,
			Payload:   r.upBuf[:n],
		}

		packed, txID, err := r.buildAndSend(pkt, "")
		if err != nil {
			r.logger.Debug("data send failed", "error", err)
			return
		}

		r.upBuf = r.upBuf[n:]
		if old, collision := r.txToSeq[txID]; collision {
			r.logger.Warn("txid collision on data", "txid", txID, "new_seq", seq, "old_seq", old)
		}
		r.window[seq] = &windowSlot{
			seq:    seq,
			txID:   txID,
			sentAt: time.Now(),
			isNOP:  false,
			packed: packed,
		}
		r.txToSeq[txID] = seq
		r.outstanding++
		r.dataPending++
	}
}

/* handleResponse processes a DNS response, buffers downstream data by seq,
 * and flushes to local in order. Returns true if the session should end. */
func (r *Relay) handleResponse(msg *dns.Msg) (bool, error) {
	seq, ok := r.txToSeq[msg.Id]
	if !ok {
		return false, nil
	}

	slot, ok := r.window[seq]
	if !ok {
		delete(r.txToSeq, msg.Id)
		return false, nil
	}

	// DNS-level errors (SERVFAIL, NXDOMAIN, etc).
	if msg.Rcode != dns.RcodeSuccess {
		r.errors++
		if r.errors >= maxErrors {
			r.removeSlot(slot)
			return true, fmt.Errorf("too many DNS errors (%d consecutive)", r.errors)
		}
		return false, fmt.Errorf("DNS %s (seq=%d)", dns.RcodeToString[msg.Rcode], seq)
	}
	r.errors = 0

	// Decode the TXT answer.
	var pkt *protocol.Packet
	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			var err error
			pkt, err = protocol.DecodeTXTResponse(txt.Txt)
			if err != nil {
				r.removeSlot(slot)
				return false, fmt.Errorf("decode TXT: %w", err)
			}
			break
		}
	}

	if pkt == nil {
		r.removeSlot(slot)
		return false, fmt.Errorf("no TXT record in response (seq=%d)", seq)
	}

	// Stale duplicate detection: the server echoes the query seq in pkt.Seq.
	// If it doesn't match slot.seq, a late response from the DoT resolver
	// arrived after its txID was recycled for a different query — drop it.
	if pkt.Seq != slot.seq {
		r.logger.Debug("stale duplicate dropped",
			"txid", msg.Id, "slot_seq", slot.seq, "pkt_seq", pkt.Seq)
		return false, nil
	}

	if pkt.IsDesauth() {
		r.removeSlot(slot)
		r.logger.Info("server sent DESAUTH")
		return true, nil
	}

	// Buffer downstream data by seq for in-order delivery.
	if pkt.IsData() && len(pkt.Payload) > 0 {
		data := make([]byte, len(pkt.Payload))
		copy(data, pkt.Payload)
		r.downBuf[seq] = data
		preview := data
		if len(preview) > 8 {
			preview = preview[:8]
		}
		r.logger.Debug("recv data", "seq", seq, "txid", msg.Id, "bytes", len(data), "hex", hex.EncodeToString(preview))
	}
	r.downSeen[seq] = true
	r.removeSlot(slot)

	// Flush buffered data in order.
	if err := r.flushDownstream(); err != nil {
		return false, err
	}
	return false, nil
}

// flushDownstream writes buffered downstream data to local in seq order.
func (r *Relay) flushDownstream() error {
	for {
		if data, ok := r.downBuf[r.nextDownSeq]; ok {
			if _, err := r.local.Write(data); err != nil {
				return fmt.Errorf("local write: %w", err)
			}
			preview := data
			if len(preview) > 8 {
				preview = preview[:8]
			}
			r.logger.Debug("downstream", "bytes", len(data), "seq", r.nextDownSeq, "hex", hex.EncodeToString(preview))
			delete(r.downBuf, r.nextDownSeq)
			delete(r.downSeen, r.nextDownSeq)
		} else if r.downSeen[r.nextDownSeq] {
			// NOP response (no data) -- skip this seq.
			delete(r.downSeen, r.nextDownSeq)
		} else {
			return nil // gap, wait for missing seq
		}

		r.nextDownSeq++
		if r.nextDownSeq == 0 {
			r.nextDownSeq = 1
		}
	}
}


func (r *Relay) removeSlot(slot *windowSlot) {
	delete(r.txToSeq, slot.txID)
	delete(r.window, slot.seq)
	r.outstanding--
	if slot.isNOP {
		r.nopPending--
	} else {
		r.dataPending--
	}
}

/* checkRetries resends queries older than retryAfter with a fresh DNS txID.
 * Matches the C client's check_for_resent() behavior. */
func (r *Relay) checkRetries() {
	now := time.Now()
	for _, slot := range r.window {
		if now.Sub(slot.sentAt) < retryAfter {
			continue
		}

		// Unique txID: avoid aliasing with another in-flight slot.
		newID := dns.Id()
		for _, exists := r.txToSeq[newID]; exists; _, exists = r.txToSeq[newID] {
			newID = dns.Id()
		}
		binary.BigEndian.PutUint16(slot.packed[0:2], newID)

		if err := r.transport.Send(slot.packed); err != nil {
			r.logger.Debug("retry failed", "seq", slot.seq, "error", err)
			continue
		}

		delete(r.txToSeq, slot.txID)
		slot.txID = newID
		slot.sentAt = now
		r.txToSeq[newID] = slot.seq

		r.logger.Debug("retried", "seq", slot.seq, "new_txid", newID)
	}
}

func (r *Relay) sendDesauth() {
	pkt := &protocol.Packet{
		SessionID: r.sessionID,
		Seq:       r.nextSeq(),
		Type:      protocol.TypeDesauth,
	}
	if _, _, err := r.buildAndSend(pkt, ""); err != nil {
		r.logger.Debug("desauth send failed", "error", err)
	}
}

/* buildAndSend constructs a DNS TXT query from a protocol packet and sends it.
 * Returns the packed message (for retries) and the DNS transaction ID.
 *
 * Ensures the generated txID is unique across all in-flight window slots.
 * With up to 24 outstanding queries and 65536 possible IDs, collisions are
 * rare (~0.04%) but can cause a stale response to be attributed to the wrong
 * seq. This loop resolves it without meaningful overhead. */
func (r *Relay) buildAndSend(pkt *protocol.Packet, command string) ([]byte, uint16, error) {
	qname := protocol.EncodeQuery(pkt, command, r.domain)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)

	// Guarantee txID uniqueness among in-flight queries.
	for _, exists := r.txToSeq[msg.Id]; exists; _, exists = r.txToSeq[msg.Id] {
		msg.Id = dns.Id()
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("packing query: %w", err)
	}

	if err := r.transport.Send(packed); err != nil {
		return nil, 0, fmt.Errorf("sending query: %w", err)
	}

	return packed, msg.Id, nil
}
