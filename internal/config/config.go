package config

import (
	"fmt"
	"net"
	"time"
)

// Config holds all configuration for the gateway.
type Config struct {
	// Domains is the list of base domains for tunnel subdomains (e.g. ["thc.io", "example.com"]).
	// The first domain is the primary one, used in API responses and banner output.
	// All domains share the same session store, so a tunnel created on any domain
	// is reachable through any other domain in the list.
	Domains []string

	// DNSAddr is the listen address for the DNS server (e.g. ":53").
	DNSAddr string

	// APIAddr is the listen address for the REST API (e.g. ":8080").
	APIAddr string

	// Nameservers are the NS records returned for the zone (e.g. ["ns1.thc.io", "ns2.thc.io"]).
	Nameservers []string

	// GatewayIP is the public IP of this gateway server.
	GatewayIP string

	// SessionTTL is how long a tunnel session stays alive before auto-expiry.
	SessionTTL time.Duration

	// CleanupInterval is how often the session store runs expired session cleanup.
	CleanupInterval time.Duration

	// RTCPPortMin is the start of the RTCP port pool range.
	RTCPPortMin int

	// RTCPPortMax is the end of the RTCP port pool range.
	RTCPPortMax int

	// RateLimit is the max tunnel creation requests per IP per hour.
	RateLimit int

	// MaxTunnelsPerIP is the max concurrent tunnels allowed per source IP.
	MaxTunnelsPerIP int

	// DNSUDPSize is the EDNS0 UDP buffer size advertised by the DNS server.
	DNSUDPSize uint16

	// AdminContact is the RNAME field in the SOA record (email in DNS format).
	AdminContact string

	// TLSEnabled enables automatic TLS via Let's Encrypt.
	// When true, the gateway handles TLS itself (autocert on port 443).
	TLSEnabled bool

	// TLSHosts is the list of hostnames allowed for TLS certificates.
	TLSHosts []string

	// TLSCertDir is the directory for caching Let's Encrypt certificates.
	TLSCertDir string

	// ReverseProxy indicates the gateway sits behind a reverse proxy (nginx, caddy, etc).
	// When true, the gateway runs plain HTTP and trusts X-Forwarded-For headers.
	// TLS termination is the reverse proxy's responsibility.
	ReverseProxy bool
}

// Default returns a Config populated with sensible production defaults.
func Default() Config {
	return Config{
		Domains:         []string{"thc.io"},
		DNSAddr:         ":53",
		APIAddr:         ":8080",
		Nameservers:     []string{}, // derived from Domain in main.go
		GatewayIP:       "127.0.0.1",
		SessionTTL:      1 * time.Hour,
		CleanupInterval: 5 * time.Minute,
		RTCPPortMin:     30000,
		RTCPPortMax:     40000,
		RateLimit:       30,
		MaxTunnelsPerIP: 5,
		DNSUDPSize:      4096,
		AdminContact:    "",    // derived from Domain in main.go
		TLSEnabled:      false,
		TLSCertDir:      "",
		ReverseProxy:    false,
	}
}

// ApplyDomainDefaults derives nameservers and admin contact from the primary domain
// if they haven't been explicitly set.
func (c *Config) ApplyDomainDefaults() {
	primary := c.PrimaryDomain()
	if len(c.Nameservers) == 0 {
		c.Nameservers = []string{"ns1." + primary, "ns2." + primary}
	}
	if c.AdminContact == "" {
		c.AdminContact = "admin." + primary
	}
	if c.TLSCertDir == "" {
		c.TLSCertDir = "/var/lib/dns2tcp/certs"
	}
}

// Validate checks that all required fields are set and values are within acceptable ranges.
func (c Config) Validate() error {
	if len(c.Domains) == 0 || c.Domains[0] == "" {
		return fmt.Errorf("config: at least one domain is required")
	}
	if c.DNSAddr == "" {
		return fmt.Errorf("config: dns address must not be empty")
	}
	if c.APIAddr == "" {
		return fmt.Errorf("config: api address must not be empty")
	}
	if len(c.Nameservers) == 0 {
		return fmt.Errorf("config: at least one nameserver is required")
	}
	if net.ParseIP(c.GatewayIP) == nil {
		return fmt.Errorf("config: invalid gateway ip %q", c.GatewayIP)
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("config: session ttl must be positive")
	}
	if c.RTCPPortMin >= c.RTCPPortMax {
		return fmt.Errorf("config: rtcp port min (%d) must be less than max (%d)", c.RTCPPortMin, c.RTCPPortMax)
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("config: rate limit must be positive")
	}
	if c.DNSUDPSize < 512 {
		return fmt.Errorf("config: dns udp size must be at least 512")
	}
	return nil
}

// PrimaryDomain returns the first (primary) domain from the list.
// The primary domain is used in API responses, banner output, and as the
// default zone for operations that need a single domain reference.
func (c Config) PrimaryDomain() string {
	if len(c.Domains) == 0 {
		return ""
	}
	return c.Domains[0]
}

// PrimaryFQDN returns the primary domain as a fully qualified domain name (trailing dot).
func (c Config) PrimaryFQDN() string {
	return fqdn(c.PrimaryDomain())
}

// FQDNs returns all configured domains as fully qualified domain names (trailing dots).
func (c Config) FQDNs() []string {
	fqdns := make([]string, len(c.Domains))
	for i, d := range c.Domains {
		fqdns[i] = fqdn(d)
	}
	return fqdns
}

// fqdn ensures a domain has a trailing dot.
func fqdn(d string) string {
	if d == "" {
		return "."
	}
	if d[len(d)-1] != '.' {
		d += "."
	}
	return d
}
