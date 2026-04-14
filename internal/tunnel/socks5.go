package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"
)

/*
 * SOCKS5 proxy server (RFC 1928) for dns2tcp-gateway.
 *
 * When a session is created with ModeSOCKS5, the tunnel client uses
 * net.Pipe() instead of a fixed TCP dial. One end of the pipe feeds
 * into the existing ring buffer machinery; the other end runs this
 * SOCKS5 server, which reads the negotiation from the DNS tunnel byte
 * stream, dials the requested destination, then pipes bidirectionally.
 *
 * The tunnel layer sees no difference -- it just has a net.Conn backend.
 * SOCKS5 protocol is entirely handled here, above the DNS layer.
 */

const (
	socks5Version    = 0x05
	socks5NoAuth     = 0x00
	socks5CmdConnect = 0x01
	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04

	socks5DialTimeout = 10 * time.Second

	// SOCKS5 reply codes (RFC 1928 section 6)
	socks5ReplyOK          = 0x00
	socks5ReplyNotAllowed  = 0x02
	socks5ReplyCmdUnsup    = 0x07
	socks5ReplyAddrUnsup   = 0x08
	socks5ReplyConnRefused = 0x05
	socks5ReplyHostUnreach = 0x04
)

/*
 * runSOCKS5Server runs the SOCKS5 protocol on conn (one end of net.Pipe()).
 * It blocks until the session ends or an error occurs.
 * Errors are logged at debug level; they are expected on normal shutdown.
 */
func runSOCKS5Server(conn net.Conn, logger *slog.Logger) {
	defer conn.Close()
	if err := handleSOCKS5(conn, logger); err != nil {
		logger.Debug("socks5 session ended", "error", err)
	}
}

func handleSOCKS5(conn net.Conn, logger *slog.Logger) error {
	// Step 1: auth negotiation.
	// Client sends: VER(1) NMETHODS(1) METHODS(n)
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading auth header: %w", err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading auth methods: %w", err)
	}
	// Always respond with no-auth (0x00). We rely on the tunnel key for auth.
	if _, err := conn.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return fmt.Errorf("writing auth response: %w", err)
	}

	// Step 2: CONNECT request.
	// Client sends: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return fmt.Errorf("reading request: %w", err)
	}
	if req[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version in request: %d", req[0])
	}
	if req[1] != socks5CmdConnect {
		socks5Reply(conn, socks5ReplyCmdUnsup)
		return fmt.Errorf("unsupported command %d (only CONNECT supported)", req[1])
	}

	host, err := readSOCKS5Addr(conn, req[3])
	if err != nil {
		socks5Reply(conn, socks5ReplyAddrUnsup)
		return err
	}

	var port uint16
	if err := binary.Read(conn, binary.BigEndian, &port); err != nil {
		return fmt.Errorf("reading port: %w", err)
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// SSRF protection: block private/reserved IPs (direct and via DNS resolution).
	if err := checkSOCKS5Target(host); err != nil {
		socks5Reply(conn, socks5ReplyNotAllowed)
		logger.Warn("socks5 blocked target", "target", target, "reason", err)
		return err
	}

	upstream, err := net.DialTimeout("tcp", target, socks5DialTimeout)
	if err != nil {
		socks5Reply(conn, socks5ReplyHostUnreach)
		return fmt.Errorf("dialing %s: %w", target, err)
	}
	defer upstream.Close()

	// Success response: VER REP RSV ATYP(IPv4) BND.ADDR(4) BND.PORT(2)
	socks5Reply(conn, socks5ReplyOK)
	logger.Info("socks5 connected", "target", target)

	// Bidirectional pipe: conn <-> upstream.
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(upstream, conn) //nolint:errcheck // copy errors on shutdown are expected
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite() //nolint:errcheck // best-effort half-close
		}
	}()
	io.Copy(conn, upstream) //nolint:errcheck // copy errors on shutdown are expected
	<-done
	return nil
}

func readSOCKS5Addr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socks5AddrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("reading IPv4: %w", err)
		}
		return net.IP(addr).String(), nil

	case socks5AddrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("reading IPv6: %w", err)
		}
		return net.IP(addr).String(), nil

	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("reading domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("reading domain: %w", err)
		}
		return string(domain), nil

	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

/* checkSOCKS5Target blocks private/reserved IP addresses to prevent SSRF.
 * For domain names, all resolved IPs are checked before dialing. */
func checkSOCKS5Target(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if socks5IsPrivate(ip) {
			return fmt.Errorf("private/reserved IP %s not allowed", host)
		}
		return nil
	}

	// Domain name: resolve and check every returned IP.
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", host, err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && socks5IsPrivate(ip) {
			return fmt.Errorf("domain %s resolves to private IP %s", host, addr)
		}
	}
	return nil
}

/*
 * socks5IsPrivate mirrors the SSRF check in api/handlers.go.
 * Private, loopback, link-local, and CGNAT ranges are all blocked.
 * Kept local to this package to avoid a cross-package dependency.
 */
func socks5IsPrivate(ip net.IP) bool {
	for _, block := range socks5PrivateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

var socks5PrivateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10", "::/128",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		socks5PrivateRanges = append(socks5PrivateRanges, block)
	}
}

/* socks5Reply sends a minimal SOCKS5 reply with the given code.
 * BND.ADDR is zeroed (0.0.0.0:0) since we don't expose the bound address. */
func socks5Reply(conn net.Conn, code byte) {
	conn.Write([]byte{socks5Version, code, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0}) //nolint:errcheck // best-effort reply
}
