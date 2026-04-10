# Changelog

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
