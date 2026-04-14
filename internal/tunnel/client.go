package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
)

const (
	// QueueSize matches dns2tcp's QUEUE_SIZE (max pending queries per client).
	QueueSize = 48

	MaxPayloadSize = 100 // max raw bytes per DNS response after headers + base64 + overhead
	ReadBufferSize = 4096

	/*
	 * slotExpiry: how long a USED slot waits before NOP reply.
	 * Matches C server's REQUEST_UTIMEOUT = 500ms. Must be shorter than
	 * Cloudflare's retry interval (~500ms) and well under SERVFAIL (~3s).
	 */
	slotExpiry    = 500 * time.Millisecond
	sweepInterval = 100 * time.Millisecond // expiry ticker interval
	DrainWait     = 600 * time.Millisecond // safety-net timeout, sweep should NOP first
)

// slotStatus tracks the lifecycle of a seq slot in the ring.
type slotStatus int

const (
	slotUsed    slotStatus = iota // query registered, waiting for data
	slotReplied                   // response sent, cached for retries
)

/*
 * seqSlot: a DNS query in the seq window, waiting for TCP data or expiry.
 * Lifecycle: USED (query arrives) -> REPLIED (data/NOP dispatched).
 * After head advances past a REPLIED slot, the reply moves to the
 * dispatched cache and the slot is deleted from the ring.
 */
type seqSlot struct {
	status    slotStatus
	seq       uint16
	maxBytes  int
	result    chan *protocol.Packet
	reply     *protocol.Packet
	arrivedAt time.Time
}

/*
 * Client: an authenticated dns2tcp tunnel client.
 *
 * Data flow (mirrors C server architecture):
 *   DNS query -> DrainPending: retry = cached response, new = ring[seq] + inline dispatch
 *   TCP data  -> readLoop buffers -> tryDispatch from head forward
 *   100ms tick -> sweep old USED slots with NOP -> advance head
 *
 * Ring is a map keyed by seq. nextDispatchSeq is the head (lowest seq
 * that gets the next data chunk), matching C server's positional ring.
 */
type Client struct {
	mu        sync.Mutex
	SessionID uint16
	Subdomain string
	Challenge string
	IsAuthed  bool
	authedCh  chan struct{} // closed when IsAuthed becomes true
	Resource  string
	CreatedAt time.Time

	tcpConn     net.Conn
	pendingData []byte
	connecting  bool // guards concurrent ConnectTCP

	ring            map[uint16]*seqSlot         // active query slots by seq
	nextDispatchSeq uint16                      // head: next seq to receive data
	headReady       bool                        // set when TCP connects (head = 1)
	headGapSince    time.Time                   // non-zero when head seq absent from ring
	dispatched      map[uint16]*protocol.Packet // evicted reply cache for retries

	stopSweep chan struct{}
	sweepOnce sync.Once

	/* incoming data: buffered by seq, flushed to TCP in order */
	incomingBuf   map[uint16][]byte
	nextIncomSeq  uint16
	incomSeqReady bool
	seenSeqs      map[uint16]bool
	flushing      bool

	isClosed bool
	logger   *slog.Logger
}

// NewClient creates a new unauthenticated client with the given session ID.
func NewClient(sessionID uint16, logger *slog.Logger) *Client {
	return &Client{
		SessionID:  sessionID,
		CreatedAt:  time.Now(),
		authedCh:   make(chan struct{}),
		ring:       make(map[uint16]*seqSlot),
		dispatched: make(map[uint16]*protocol.Packet),
		stopSweep:  make(chan struct{}),
		logger:     logger.With("session_id", sessionID),
	}
}

/*
 * ConnectSOCKS5 sets up the client for SOCKS5 proxy mode using net.Pipe().
 * Instead of dialing a fixed target at connect time, it creates two connected
 * in-process net.Conn ends: clientEnd feeds into the existing ring buffer /
 * readLoop machinery, serverEnd runs the SOCKS5 server goroutine which reads
 * the negotiation from the byte stream and dials dynamically.
 * The tunnel layer sees no difference -- tcpConn is just a net.Conn.
 */
func (c *Client) ConnectSOCKS5() error {
	c.mu.Lock()
	if c.tcpConn != nil || c.connecting {
		c.mu.Unlock()
		c.logger.Debug("socks5 already connected or connecting, ignoring")
		return nil
	}

	serverEnd, clientEnd := net.Pipe()
	c.tcpConn = clientEnd
	c.nextDispatchSeq = 1
	c.headReady = true
	c.mu.Unlock()

	c.logger.Info("socks5 proxy ready")

	go runSOCKS5Server(serverEnd, c.logger)
	go c.readLoop()
	c.sweepOnce.Do(func() { go c.expirySweep() })

	return nil
}

// ConnectTCP opens a TCP connection to the target resource.
func (c *Client) ConnectTCP(target string) error {
	c.mu.Lock()
	if c.tcpConn != nil || c.connecting {
		c.mu.Unlock()
		c.logger.Debug("tcp already connected or connecting, ignoring", "target", target)
		return nil
	}
	c.connecting = true
	c.mu.Unlock()

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	c.mu.Lock()
	c.connecting = false
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("tunnel: connecting to %s: %w", target, err)
	}
	c.tcpConn = conn
	c.nextDispatchSeq = 1 // relay always starts at seq=1
	c.headReady = true
	c.mu.Unlock()

	c.logger.Info("tcp connection established", "target", target)

	go c.readLoop()
	c.sweepOnce.Do(func() { go c.expirySweep() })

	return nil
}

func (c *Client) readLoop() {
	buf := make([]byte, ReadBufferSize)
	for {
		n, err := c.tcpConn.Read(buf)
		if n > 0 {
			c.mu.Lock()
			c.pendingData = append(c.pendingData, buf[:n]...)
			c.tryDispatch()
			c.mu.Unlock()
			c.logger.Debug("tcp data buffered", "bytes", n)
		}
		if err != nil {
			if err != io.EOF {
				c.logger.Debug("tcp read error", "error", err)
			}
			c.mu.Lock()
			c.isClosed = true
			c.tryDispatch()
			c.mu.Unlock()
			c.logger.Info("tcp connection closed")
			return
		}
	}
}

// tryDispatch: dispatch data from head forward. Must hold c.mu.
func (c *Client) tryDispatch() {
	if !c.headReady {
		return
	}

	for {
		slot, ok := c.ring[c.nextDispatchSeq]
		if !ok || slot.status != slotUsed {
			return
		}

		if c.isClosed && len(c.pendingData) == 0 {
			pkt := &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       slot.seq,
				Type:      protocol.TypeDesauth,
			}
			c.replySlot(slot, pkt)
			c.advanceHead()
			continue
		}

		if len(c.pendingData) == 0 {
			return
		}

		pkt := c.makeDataPacket(slot.seq, slot.maxBytes)
		c.replySlot(slot, pkt)
		c.advanceHead()
	}
}

// replySlot: send packet to slot and mark REPLIED. Must hold c.mu.
func (c *Client) replySlot(slot *seqSlot, pkt *protocol.Packet) {
	slot.reply = pkt
	slot.status = slotReplied
	select {
	case slot.result <- pkt:
	default:
	}
}

/* advanceHead: move past REPLIED slots, evict to cache. Must hold c.mu.
 * Stops at any gap (missing seq) -- doSweep handles stuck-head advancement. */
func (c *Client) advanceHead() {
	for {
		slot, ok := c.ring[c.nextDispatchSeq]
		if !ok {
			return // gap: wait for seq to arrive or doSweep to advance
		}
		if slot.status == slotUsed {
			return // still waiting for data or expiry NOP
		}
		// REPLIED: evict to dispatched cache.
		if slot.reply != nil {
			c.dispatched[c.nextDispatchSeq] = slot.reply
		}
		delete(c.ring, c.nextDispatchSeq)
		c.nextDispatchSeq++
		if c.nextDispatchSeq == 0 {
			c.nextDispatchSeq = 1
		}
	}
}

// expirySweep: background NOP for old USED slots (C server's queue_flush_expired_data).
func (c *Client) expirySweep() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.doSweep()
			c.mu.Unlock()
		case <-c.stopSweep:
			return
		}
	}
}

// doSweep: expire old USED slots, advance head. Must hold c.mu.
func (c *Client) doSweep() {
	now := time.Now()
	for seq, slot := range c.ring {
		if slot.status != slotUsed {
			continue
		}
		if now.Sub(slot.arrivedAt) < slotExpiry {
			continue
		}
		nop := &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       seq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
		c.logger.Debug("expiry NOP", "seq", seq, "age_ms", now.Sub(slot.arrivedAt).Milliseconds())
		c.replySlot(slot, nop)
	}
	c.advanceHead()

	/*
	 * Stuck-head advancement: if the head seq is absent from the ring
	 * (query genuinely lost in transit, no retry arrived), advance past it
	 * after slotExpiry. This unblocks pendingData when a single query packet
	 * is dropped end-to-end despite the relay's retry logic.
	 */
	if c.headReady {
		if _, ok := c.ring[c.nextDispatchSeq]; !ok {
			if c.headGapSince.IsZero() {
				c.headGapSince = now
			} else if now.Sub(c.headGapSince) >= slotExpiry {
				c.logger.Debug("stuck head advanced", "seq", c.nextDispatchSeq)
				c.headGapSince = time.Time{}
				c.nextDispatchSeq++
				if c.nextDispatchSeq == 0 {
					c.nextDispatchSeq = 1
				}
				c.advanceHead()
				c.tryDispatch()
			}
		} else {
			c.headGapSince = time.Time{}
		}
	}

	if len(c.dispatched) > QueueSize*2 {
		c.pruneDispatched()
	}
}

func (c *Client) pruneDispatched() {
	for seq := range c.dispatched {
		if seqBefore(seq, c.nextDispatchSeq) {
			diff := c.nextDispatchSeq - seq
			if diff > QueueSize*2 {
				delete(c.dispatched, seq)
			}
		}
	}
}

// makeDataPacket: consume chunk from pendingData. Must hold c.mu.
func (c *Client) makeDataPacket(seq uint16, maxBytes int) *protocol.Packet {
	n := len(c.pendingData)
	if n > maxBytes {
		n = maxBytes
	}
	chunk := make([]byte, n)
	copy(chunk, c.pendingData[:n])

	preview := chunk
	if len(preview) > 8 {
		preview = preview[:8]
	}
	c.pendingData = c.pendingData[n:]

	c.logger.Debug("dispatch data", "seq", seq, "bytes", n, "remaining", len(c.pendingData),
		"hex", fmt.Sprintf("%x", preview))

	return &protocol.Packet{
		SessionID: c.SessionID,
		Seq:       seq,
		AckSeq:    0,
		Type:      protocol.TypeACK | protocol.TypeData,
		Payload:   chunk,
	}
}

// MarkNOPSeen: record NOP query seq so flushIncoming can skip gaps.
func (c *Client) MarkNOPSeen(seq uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.seenSeqs == nil {
		c.seenSeqs = make(map[uint16]bool)
	}
	c.seenSeqs[seq] = true

	if !c.incomSeqReady {
		c.nextIncomSeq = seq
		c.incomSeqReady = true
	}
	if !c.flushing && seqBefore(seq, c.nextIncomSeq) {
		c.nextIncomSeq = seq
	}

	if c.tcpConn != nil && !c.isClosed {
		_ = c.flushIncoming()
	}
}

// HandleData: buffer incoming client data by seq, flush to TCP in order.
func (c *Client) HandleData(seq uint16, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tcpConn == nil {
		return fmt.Errorf("tunnel: no tcp connection")
	}
	if c.isClosed {
		return fmt.Errorf("tunnel: tcp connection closed")
	}
	if len(data) == 0 {
		return nil
	}

	if c.incomingBuf == nil {
		c.incomingBuf = make(map[uint16][]byte)
	}
	if c.seenSeqs == nil {
		c.seenSeqs = make(map[uint16]bool)
	}

	if c.flushing && c.incomSeqReady && seqBefore(seq, c.nextIncomSeq) {
		c.logger.Debug("seq already flushed, rejecting", "seq", seq, "nextIncomSeq", c.nextIncomSeq)
		return nil
	}

	if c.seenSeqs[seq] {
		c.logger.Debug("duplicate incoming seq, skipping", "seq", seq)
		return nil
	}

	c.seenSeqs[seq] = true
	if !c.incomSeqReady {
		c.nextIncomSeq = seq
		c.incomSeqReady = true
	}
	if !c.flushing && seqBefore(seq, c.nextIncomSeq) {
		c.nextIncomSeq = seq
	}

	buf := make([]byte, len(data))
	copy(buf, data)
	c.incomingBuf[seq] = buf

	return c.flushIncoming()
}

// flushIncoming: write buffered data to TCP in seq order. Must hold c.mu.
func (c *Client) flushIncoming() error {
	for {
		if data, ok := c.incomingBuf[c.nextIncomSeq]; ok {
			c.flushing = true
			if _, err := c.tcpConn.Write(data); err != nil {
				return fmt.Errorf("tunnel: writing to tcp: %w", err)
			}
			c.logger.Debug("forwarded to tcp", "bytes", len(data), "seq", c.nextIncomSeq)
			delete(c.incomingBuf, c.nextIncomSeq)
		} else if c.seenSeqs[c.nextIncomSeq] {
			c.logger.Debug("skipping NOP gap", "seq", c.nextIncomSeq)
		} else {
			return nil
		}

		c.nextIncomSeq++
		if c.nextIncomSeq == 0 {
			c.nextIncomSeq = 1
		}
	}
}

// seqBefore returns true if a comes before b in the uint16 sequence space.
func seqBefore(a, b uint16) bool {
	return int16(a-b) < 0
}

/*
 * DrainPending: register query in seq window, wait for data or expiry NOP.
 * Retries for already-dispatched seqs return cached response immediately.
 */
func (c *Client) DrainPending(clientSeq uint16, maxBytes int) *protocol.Packet {
	c.mu.Lock()

	// Check ring first: retry for a slot still in the window.
	if slot, ok := c.ring[clientSeq]; ok && slot.status == slotReplied {
		c.mu.Unlock()
		c.logger.Debug("replay from ring", "seq", clientSeq)
		return slot.reply
	}

	// Check evicted cache: retry for a seq that advanced past.
	if cached, ok := c.dispatched[clientSeq]; ok {
		c.mu.Unlock()
		preview := cached.Payload
		if len(preview) > 8 {
			preview = preview[:8]
		}
		c.logger.Debug("replay from cache", "seq", clientSeq, "type", cached.Type,
			"hex", fmt.Sprintf("%x", preview))
		return cached
	}

	// TCP closed with no remaining data.
	if c.isClosed && len(c.pendingData) == 0 {
		c.mu.Unlock()
		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			Type:      protocol.TypeDesauth,
		}
	}

	// Stale: seq is behind the current dispatch head.
	if c.headReady && seqBefore(clientSeq, c.nextDispatchSeq) {
		c.mu.Unlock()
		c.logger.Debug("stale seq behind head, NOP", "seq", clientSeq, "head", c.nextDispatchSeq)
		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
	}

	if existing, ok := c.ring[clientSeq]; ok && existing.status == slotUsed {
		c.mu.Unlock()
		// Wait on the existing slot's result channel.
		select {
		case pkt := <-existing.result:
			return pkt
		case <-time.After(DrainWait):
			return &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       clientSeq,
				AckSeq:    0,
				Type:      protocol.TypeACK | protocol.TypeNOP,
			}
		}
	}

	result := make(chan *protocol.Packet, 1)
	c.ring[clientSeq] = &seqSlot{
		status:    slotUsed,
		seq:       clientSeq,
		maxBytes:  maxBytes,
		result:    result,
		arrivedAt: time.Now(),
	}

	c.tryDispatch()

	c.mu.Unlock()

	select {
	case pkt := <-result:
		return pkt
	case <-time.After(DrainWait):
		/* safety net: sweep should have NOP'd already */
		c.mu.Lock()
		if slot, ok := c.ring[clientSeq]; ok && slot.status == slotUsed {
			nop := &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       clientSeq,
				AckSeq:    0,
				Type:      protocol.TypeACK | protocol.TypeNOP,
			}
			c.replySlot(slot, nop)
			c.advanceHead()
		}
		c.mu.Unlock()

		select {
		case pkt := <-result:
			return pkt
		default:
		}

		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
	}
}

// Close shuts down the client's TCP connection and stops the sweep.
func (c *Client) Close() {
	c.mu.Lock()
	if c.tcpConn != nil && !c.isClosed {
		c.tcpConn.Close()
		c.isClosed = true
	}
	for seq, slot := range c.ring {
		if slot.status == slotUsed {
			pkt := &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       seq,
				Type:      protocol.TypeDesauth,
			}
			c.replySlot(slot, pkt)
		}
	}
	c.ring = make(map[uint16]*seqSlot)
	c.mu.Unlock()

	select {
	case c.stopSweep <- struct{}{}:
	default:
	}
}

// SetAuthed: mark authenticated, unblock WaitAuthed callers.
func (c *Client) SetAuthed() {
	c.mu.Lock()
	c.IsAuthed = true
	c.mu.Unlock()
	close(c.authedCh)
}

// WaitAuthed: block until authenticated or timeout. Returns true if authed.
func (c *Client) WaitAuthed(timeout time.Duration) bool {
	c.mu.Lock()
	if c.IsAuthed {
		c.mu.Unlock()
		return true
	}
	c.mu.Unlock()

	select {
	case <-c.authedCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

// IsClosed returns whether the TCP backend connection is closed.
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosed
}
