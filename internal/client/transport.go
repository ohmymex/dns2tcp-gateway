package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

/* Transport is the DNS transport abstraction used by the client.
 *
 * Two modes:
 *   - Synchronous: SendAndReceive blocks until the matching response arrives.
 *     Used during auth, resource listing, and connect phases.
 *   - Asynchronous: responses flow to the Responses() channel.
 *     Used by the relay during steady-state data transfer.
 */
type Transport interface {
	Send(data []byte) error
	SendAndReceive(msg *dns.Msg, timeout time.Duration) (*dns.Msg, error)
	Responses() <-chan *dns.Msg
	Close()
}

/* NewTransport creates a transport based on the resolver address format:
 *   "1.1.1.1" or "1.1.1.1:53"              -> UDP (plain DNS)
 *   "https://1.1.1.1/dns-query"             -> DoH (DNS over HTTPS)
 *   "tls://1.1.1.1" or "tls://1.1.1.1:853" -> DoT (DNS over TLS)
 */
func NewTransport(resolver string) (Transport, error) {
	switch {
	case strings.HasPrefix(resolver, "https://"):
		return newDoHTransport(resolver)
	case strings.HasPrefix(resolver, "tls://"):
		addr := strings.TrimPrefix(resolver, "tls://")
		if !strings.Contains(addr, ":") {
			addr += ":853"
		}
		return newDoTTransport(addr)
	default:
		if !strings.Contains(resolver, ":") {
			resolver += ":53"
		}
		return newUDPTransport(resolver)
	}
}

/* resolverDescription returns a human-readable description of the resolver format. */
func resolverDescription() string {
	return `DNS resolver address. Formats:
    1.1.1.1 or 1.1.1.1:53              plain UDP (default)
    https://1.1.1.1/dns-query          DNS over HTTPS (DoH)
    tls://1.1.1.1 or tls://1.1.1.1:853 DNS over TLS (DoT)

  Well-known DoH endpoints:
    https://1.1.1.1/dns-query          Cloudflare
    https://9.9.9.9/dns-query          Quad9
    https://dns.quad9.net/dns-query    Quad9 (hostname)

  Note: Google 8.8.8.8 is incompatible (0x20 case randomization corrupts base64 payloads).`
}

func wrapSendError(transport string, err error) error {
	return fmt.Errorf("%s send: %w", transport, err)
}
