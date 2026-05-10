package tunnel

import (
	"context"
	"net"
)

/*
 * DialFunc establishes an outbound TCP connection.
 * Injecting it lets the gateway route exits through a SOCKS5 proxy
 * (e.g. Mullvad) without the tunnel package depending on proxy internals.
 */
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

/* DefaultDialFn returns a DialFunc that dials TCP directly (no proxy). */
func DefaultDialFn() DialFunc {
	d := &net.Dialer{}
	return d.DialContext
}
