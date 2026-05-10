# Changelog

## v0.4.0

### Features

* `GATEWAY_EXIT_SOCKS5`: route all outbound tunnel TCP connections through a SOCKS5 proxy (e.g. Mullvad) for liability shielding. Format: `host:port` or `user:pass@host:port`. Both TCP forward mode and SOCKS5 proxy mode route through the configured proxy.

### Fixes

* IPv6 system resolver: `dns2tcp-client` no longer produces invalid addresses when `/etc/resolv.conf` contains an IPv6 nameserver. IPv6 addresses are now wrapped in brackets before appending the port.

### Internal

* `DialFunc` abstraction: outbound TCP connections in the tunnel layer now use an injectable dialer function, keeping SOCKS5 proxy construction decoupled from internal packages.

## v0.3.0

### Features

* SOCKS5 proxy mode: `POST /v1/socks5` creates a tunnel where the destination is determined dynamically by SOCKS5 protocol inside the byte stream. No fixed IP:PORT at creation time. The DNS tunnel acts as a full SOCKS5 proxy.
  * Gateway runs an in-process SOCKS5 server (RFC 1928) using `net.Pipe()`; the tunnel layer is transparent
  * Supports IPv4, IPv6, and domain name destinations
  * SSRF protection: private/reserved IP ranges blocked at both direct IP and DNS pre-resolution level
  * Use: `dns2tcp-client -z SUB.domain -r tunnel -l 1080 -d RESOLVER`, then point any SOCKS5-aware tool at `localhost:1080`

### Fixes

* IPv6 SOCKS5 targets now formatted correctly with brackets (`[addr]:port` via `net.JoinHostPort`)

## v0.2.1

### Features

* DoT transport: `dns2tcp-client` now accepts `tls://` resolver prefix for DNS-over-TLS (e.g., `-d tls://1.1.1.1`)
* DoH transport: accepts `https://` resolver prefix for DNS-over-HTTPS (e.g., `-d https://1.1.1.1/dns-query`)

### Fixes

* DNS case normalization: caching resolvers (Cloudflare, Quad9) lowercase QNAMEs before cache lookups. dns2tcp base64 uses A-Z (values 0-25) and a-z (26-51), so seq=N and seq=N+26 produce identical lowercased QNAMEs, causing the wrong cached response to be returned. Fixed by prepending a 4-hex sequence label to all Go client queries (`0001.data...` vs `001b.data...`), making colliding sequences distinct after lowercasing. C client (dns2tcpc) is unaffected and sends no prefix.

## v0.2.0

### Features

* Native Go client (`dns2tcp-client`): drop-in replacement for dns2tcpc, zero external dependencies
  * Port forwarding mode (`-l <port>`) and SSH ProxyCommand mode (`-l -`)
  * Sliding window with NOP pool matching C client behavior (QUEUE_SIZE=48, WINDOW=24, NOP=8)
  * Downstream ordering buffer for public resolver query reordering
  * Retry with fresh DNS txID after 1 second timeout
  * Compatible with all tested resolvers: Direct, Cloudflare, Quad9, Verisign
* `GET /v1/tunnels`: list your tunnels by IP (tokens hidden for security)
* `PATCH /v1/{subdomain}`: extend tunnel TTL with Bearer token auth
* Configurable per-IP tunnel limit via `GATEWAY_MAX_TUNNELS_PER_IP` (default raised from 5 to 10)
* Tunnel limit error now returns 429 with hint to list/delete endpoints

### Changes

* Both binaries (`dns2tcp-gateway` + `dns2tcp-client`) ship in the same release archive
* Bearer token extraction refactored into shared helper

## v0.1.5

### Features

* Multi-domain support: `GATEWAY_DOMAIN=domain1.com,domain2.com` (contributed by [@extencil](https://github.com/extencil))
* API responses include `domains` field listing all configured domain aliases
* DNS server registers handlers for all configured zones
* All domains share the same session store

## v0.1.4

### Security

* Cap tunnel clients at 1000, reject new auth when full
* Reap unauthenticated clients after 30 seconds (prevents memory exhaustion from DNS auth spam)
* Require Bearer token for DELETE endpoint (prevents unauthorized tunnel deletion)
* Block private/reserved IP ranges on TCP and NS endpoints (SSRF fix, reported by [@extencil](https://github.com/extencil))
* Only trust X-Forwarded-For when GATEWAY_REVERSE_PROXY=true (XFF spoofing fix)
* Consistent IP extraction for rate limiter and tunnel ownership

### Changes

* Tunnel creation now returns a `token` field, required for deletion
* RTCP message shows domain instead of raw IP
* Warn at startup if GATEWAY_TUNNEL_KEY is not set

## v0.1.0

Initial release.

### Features

* Full dns2tcp protocol implementation (auth, resource, connect, data relay)
* REST API for tunnel management (TCP forward, NS delegation, RTCP skeleton)
* Authoritative DNS server with SOA, NS, A, TXT (EDNS0) support
* Let's Encrypt TLS autocert for the API
* Reverse proxy mode for running behind nginx/caddy
* Session store with auto cleanup
* Ring buffer dispatch architecture for server to client data ordering
* 500ms per slot expiry sweep matching the C server's REQUEST_UTIMEOUT
* 50ms head grace period for public resolver query reordering
* Response cache for DNS retry deduplication
* Colored startup banner with build version injection

### Tested resolvers

* Direct, Cloudflare (1.1.1.1), Quad9 (9.9.9.9), Verisign (64.6.64.6): working
* Google (8.8.8.8): incompatible due to 0x20 case randomization
