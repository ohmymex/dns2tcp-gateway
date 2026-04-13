package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

/* dohTransport sends DNS queries over HTTPS (RFC 8484).
 *
 * Each query is a POST to the resolver URL with Content-Type
 * application/dns-message. HTTP/2 is used automatically by the
 * stdlib transport, so no explicit multiplexing is needed.
 *
 * Async Send spawns a goroutine per query and routes the response
 * to respCh. SendAndReceive uses a context deadline instead.
 */
type dohTransport struct {
	url    string
	client *http.Client

	respCh chan *dns.Msg
	done   chan struct{}
}

func newDoHTransport(url string) (*dohTransport, error) {
	return &dohTransport{
		url:    url,
		client: &http.Client{},
		respCh: make(chan *dns.Msg, 64),
		done:   make(chan struct{}),
	}, nil
}

/* Send fires an async DoH request and routes the response to Responses().
 *
 * We copy data before spawning the goroutine because the relay's retry
 * path (checkRetries) mutates slot.packed in-place after Send returns.
 * A synchronous UDP Write copies into the kernel buffer immediately so
 * the same caller mutation is safe there; DoH cannot make that guarantee. */
func (t *dohTransport) Send(data []byte) error {
	wire := make([]byte, len(data))
	copy(wire, data)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := t.post(ctx, wire)
		if err != nil {
			return
		}

		select {
		case t.respCh <- resp:
		case <-t.done:
		default:
		}
	}()

	return nil
}

/* SendAndReceive posts the query and blocks until the response arrives
 * or the timeout expires. */
func (t *dohTransport) SendAndReceive(msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS message: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return t.post(ctx, packed)
}

func (t *dohTransport) Responses() <-chan *dns.Msg {
	return t.respCh
}

func (t *dohTransport) Close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

/* post sends a single DNS-over-HTTPS request and returns the parsed response. */
func (t *dohTransport) post(ctx context.Context, wire []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("building DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, wrapSendError("DoH", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH resolver returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading DoH response: %w", err)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking DoH response: %w", err)
	}

	return msg, nil
}
