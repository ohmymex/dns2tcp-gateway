package client

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/*
 * Transport is a DNS UDP transport layer.
 *
 * It supports two modes of receiving responses:
 *   - Synchronous: SendAndReceive blocks until the matching response arrives.
 *     Used during auth, resource listing, and connect phases.
 *   - Asynchronous: responses flow to the Responses() channel.
 *     Used by the relay during steady-state data transfer.
 *
 * Both modes share a single UDP socket and reader goroutine.
 * Synchronous waiters take priority: if a response matches a registered
 * waiter (by DNS txID), it goes there. Otherwise it goes to the async channel.
 */
type Transport struct {
	conn *net.UDPConn

	mu      sync.Mutex
	waiters map[uint16]chan *dns.Msg

	respCh chan *dns.Msg
	done   chan struct{}
}

// NewTransport connects to the given DNS resolver over UDP ("ip:port").
func NewTransport(resolver string) (*Transport, error) {
	addr, err := net.ResolveUDPAddr("udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", resolver, err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", resolver, err)
	}

	t := &Transport{
		conn:    conn,
		waiters: make(map[uint16]chan *dns.Msg),
		respCh:  make(chan *dns.Msg, 64),
		done:    make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

// Send writes a pre-packed DNS message to the resolver.
func (t *Transport) Send(data []byte) error {
	_, err := t.conn.Write(data)
	return err
}

/* SendAndReceive sends a DNS message and blocks until the matching response
 * arrives or the timeout expires. Used for synchronous protocol steps. */
func (t *Transport) SendAndReceive(msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
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

// Responses returns the async response channel used by the relay.
func (t *Transport) Responses() <-chan *dns.Msg {
	return t.respCh
}

func (t *Transport) readLoop() {
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
			// Non-timeout error: check if we're shutting down.
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

		// Synchronous waiters take priority.
		t.mu.Lock()
		if ch, ok := t.waiters[msg.Id]; ok {
			delete(t.waiters, msg.Id)
			t.mu.Unlock()
			ch <- msg
			continue
		}
		t.mu.Unlock()

		// Async: relay picks these up.
		select {
		case t.respCh <- msg:
		default:
		}
	}
}

// Close shuts down the transport and its reader goroutine.
func (t *Transport) Close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	t.conn.Close()
}
