package client

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/* dotTransport sends DNS queries over TLS (RFC 7858) on port 853.
 *
 * Wire format: 2-byte big-endian length prefix followed by the DNS
 * message, same as DNS-over-TCP. A single persistent TLS connection
 * is shared; a mutex serializes writes while the read loop dispatches
 * responses to waiters or to respCh.
 */
type dotTransport struct {
	conn *tls.Conn

	mu      sync.Mutex
	waiters map[uint16]chan *dns.Msg

	respCh chan *dns.Msg
	done   chan struct{}
}

func newDoTTransport(addr string) (*dotTransport, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parsing DoT address %s: %w", addr, err)
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to DoT resolver %s: %w", addr, err)
	}

	t := &dotTransport{
		conn:    conn,
		waiters: make(map[uint16]chan *dns.Msg),
		respCh:  make(chan *dns.Msg, 64),
		done:    make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

/* Send packs raw bytes and fires them asynchronously; the response
 * goes to Responses(). */
func (t *dotTransport) Send(data []byte) error {
	return t.writeFrame(data)
}

/* SendAndReceive writes the query and blocks until the matching
 * response arrives or the timeout expires. */
func (t *dotTransport) SendAndReceive(msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS message: %w", err)
	}

	ch := make(chan *dns.Msg, 1)
	t.mu.Lock()
	t.waiters[msg.Id] = ch
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.waiters, msg.Id)
		t.mu.Unlock()
	}()

	if err := t.writeFrame(packed); err != nil {
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for DoT response")
	case <-t.done:
		return nil, fmt.Errorf("transport closed")
	}
}

func (t *dotTransport) Responses() <-chan *dns.Msg {
	return t.respCh
}

/* writeFrame sends a length-prefixed DNS message over the TLS connection. */
func (t *dotTransport) writeFrame(data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("DNS message too large for DoT: %d bytes", len(data))
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, err := t.conn.Write(hdr[:]); err != nil {
		return wrapSendError("DoT", err)
	}
	if _, err := t.conn.Write(data); err != nil {
		return wrapSendError("DoT", err)
	}
	return nil
}

func (t *dotTransport) readLoop() {
	for {
		t.conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		var hdr [2]byte
		if _, err := io.ReadFull(t.conn, hdr[:]); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-t.done:
					return
				default:
					continue
				}
			}
			return
		}

		msgLen := binary.BigEndian.Uint16(hdr[:])
		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(t.conn, buf); err != nil {
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buf); err != nil {
			continue
		}

		t.mu.Lock()
		if ch, ok := t.waiters[msg.Id]; ok {
			delete(t.waiters, msg.Id)
			t.mu.Unlock()
			ch <- msg
			continue
		}
		t.mu.Unlock()

		select {
		case t.respCh <- msg:
		default:
		}
	}
}

func (t *dotTransport) Close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	t.conn.Close()
}
