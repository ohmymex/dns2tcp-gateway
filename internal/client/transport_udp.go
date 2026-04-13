package client

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/* udpTransport is a plain DNS-over-UDP transport.
 *
 * Synchronous waiters take priority: if a response matches a registered
 * waiter (by DNS txID), it goes there. Otherwise it goes to the async channel.
 */
type udpTransport struct {
	conn *net.UDPConn

	mu      sync.Mutex
	waiters map[uint16]chan *dns.Msg

	respCh chan *dns.Msg
	done   chan struct{}
}

func newUDPTransport(resolver string) (*udpTransport, error) {
	addr, err := net.ResolveUDPAddr("udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", resolver, err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", resolver, err)
	}

	t := &udpTransport{
		conn:    conn,
		waiters: make(map[uint16]chan *dns.Msg),
		respCh:  make(chan *dns.Msg, 64),
		done:    make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

func (t *udpTransport) Send(data []byte) error {
	_, err := t.conn.Write(data)
	return err
}

/* SendAndReceive sends a DNS message and blocks until the matching response
 * arrives or the timeout expires. Used for synchronous protocol steps. */
func (t *udpTransport) SendAndReceive(msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
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

	if _, err := t.conn.Write(packed); err != nil {
		return nil, fmt.Errorf("sending DNS query: %w", err)
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for DNS response")
	case <-t.done:
		return nil, fmt.Errorf("transport closed")
	}
}

func (t *udpTransport) Responses() <-chan *dns.Msg {
	return t.respCh
}

func (t *udpTransport) readLoop() {
	buf := make([]byte, 4096)
	for {
		t.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := t.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-t.done:
					return
				default:
					continue
				}
			}
			select {
			case <-t.done:
			default:
			}
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
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

func (t *udpTransport) Close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	t.conn.Close()
}
