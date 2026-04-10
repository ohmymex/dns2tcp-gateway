# DNS2TCP Gateway

DNS tunnel gateway as a service. Eliminates the pain of setting up domain servers, domain names, and public IPs for DNS tunneling. Users curl a REST API to get a randomly generated subdomain, then use that subdomain with dns2tcpc, iodine, or sshimpanzee.

Based on [THC hackerschoice/ToolsWeNeed](https://github.com/orgs/hackerschoice/projects/4/views/1?pane=issue&itemId=54763597) by SkyperTHC.

## What it solves

```
TARGET                                                              RECEIVER
  |                                                                    |
  +-- TCP traffic                                                      |
  v                                                                    |
dns2tcpc --DNS queries--> [Global DNS] --> [xxx.domain.com] --> dns2tcp ---+
                                           XXXXXXXXXXXXX               v
                                           this gateway            TCP output
```

The part marked with `XXX` is the pain point for most users: you need a domain, NS delegation, a public server, and a running dns2tcpd. This gateway handles all of that. Just curl and go.

## Three modes

**TCP forward:** tunnel to any IP:PORT through DNS

```bash
curl https://domain.com/v1/tcp/1.2.3.4/31337
# -> "DNS tunnel to adsgr.domain.com will forward to 1.2.3.4:31337"
```

**NS delegation:** point a subdomain's NS to your own server (for iodine, custom dns2tcpd, etc)

```bash
curl https://domain.com/v1/ns/1.2.3.4/53
# -> "adsgr.domain.com NS will point to 1.2.3.4:53"
```

**Reverse TCP (RTCP):** connect TO the gateway and wait for the DNS tunnel to activate

```bash
curl https://domain.com/v1/rtcp
# -> "use 'nc domain.com 31337'. DNS tunnel to adsgr.domain.com will terminate here."
```

## Public service

A public instance is running at **tun.numex.sh**. Try it without setting up anything:

```bash
# Create a tunnel to any TCP target
SUB=$(curl -s -X POST https://tun.numex.sh/v1/tcp/<ip>/<port> | jq -r .subdomain)

# Start dns2tcp client (pick any supported resolver)
dns2tcpc -r tunnel -z $SUB.tun.numex.sh -l 2222 1.1.1.1

# Connect through the tunnel (example: SSH)
ssh -p 2222 user@127.0.0.1
```

Replace `<ip>` and `<port>` with your target. Works with any TCP service, not just SSH.

## Supported DNS resolvers

| Resolver | Status | Notes |
|----------|--------|-------|
| Direct (gateway IP) | Works | Best performance, no intermediary |
| Cloudflare 1.1.1.1 | Works | |
| Quad9 9.9.9.9 | Works | |
| Verisign 64.6.64.6 | Works | |
| Google 8.8.8.8 | Incompatible | 0x20 case randomization breaks base64 in QNAME |

Google Public DNS applies case randomization to query names for cache poisoning resistance. Since dns2tcp encodes payload as case sensitive base64 in DNS labels, this mangles the data. There is no server side fix for this. Use Cloudflare, Quad9, or Verisign instead.

## Self hosting

### Prerequisites

1. A VPS with a public IP
2. A domain with NS delegation configured (see DNS Setup below)
3. `dns2tcpc` installed on the client (`apt install dns2tcp` on Debian/Ubuntu)

### DNS Setup (Cloudflare example)

Add these records in your DNS settings. Both must be DNS only (not proxied):

```
tun.domain.com      NS    ns1.tun.domain.com
ns1.tun.domain.com  A     <VPS_PUBLIC_IP>
```

This delegates all queries for `*.tun.domain.com` to your VPS.

### Run the gateway

```bash
GATEWAY_DOMAIN=tun.domain.com \
GATEWAY_IP=<VPS_PUBLIC_IP> \
GATEWAY_DNS_ADDR=:53 \
GATEWAY_TLS=true \
./dns2tcp-gateway
```

Port 53 requires root or `setcap cap_net_bind_service=+ep ./dns2tcp-gateway`.

### Multiple domains

The gateway can serve multiple domains simultaneously. Pass a comma-separated list to `GATEWAY_DOMAIN`:

```bash
GATEWAY_DOMAIN=tun.domain.com,tun.example.com \
GATEWAY_IP=<VPS_PUBLIC_IP> \
GATEWAY_DNS_ADDR=:53 \
./dns2tcp-gateway
```

The first domain in the list is the primary one, used in API responses and banner output. All domains share the same session store, so a tunnel created via any domain is reachable through any other domain in the list.

Each domain needs its own NS delegation:

```
tun.domain.com       NS    ns1.tun.domain.com
ns1.tun.domain.com   A     <VPS_PUBLIC_IP>

tun.example.com      NS    ns1.tun.example.com
ns1.tun.example.com  A     <VPS_PUBLIC_IP>
```

The API response includes a `domains` field listing all available domain aliases for the tunnel:

```json
{
  "subdomain": "a3f2bc",
  "domain": "a3f2bc.tun.domain.com",
  "domains": ["a3f2bc.tun.domain.com", "a3f2bc.tun.example.com"],
  "mode": "tcp",
  "target": "1.2.3.4:4444"
}
```

### Create a tunnel and connect

```bash
# Create tunnel (from any machine)
SUB=$(curl -s -X POST https://tun.domain.com/v1/tcp/<ip>/<port> | jq -r .subdomain)

# Start dns2tcp client (pick any supported resolver)
dns2tcpc -r tunnel -z $SUB.tun.domain.com -l <local_port> 1.1.1.1

# Connect through the tunnel
nc 127.0.0.1 <local_port>
```

## API

### Create TCP tunnel

```
POST /v1/tcp/{ip}/{port}
```

Creates a tunnel that forwards to `ip:port`. Returns a subdomain to use with dns2tcpc.

```bash
curl -X POST https://tun.domain.com/v1/tcp/10.0.0.5/4444
```

```json
{
  "subdomain": "a3f2bc",
  "domain": "a3f2bc.tun.domain.com",
  "domains": ["a3f2bc.tun.domain.com"],
  "token": "c2334e6cfda45870a132286ac5d298e4",
  "mode": "tcp",
  "target": "10.0.0.5:4444",
  "message": "DNS tunnel to a3f2bc.tun.domain.com will forward to 10.0.0.5:4444"
}
```

The `domains` field lists all configured domain aliases for the tunnel. When the gateway serves multiple domains, all of them appear here. Save the `token` value. You need it to delete the tunnel.

### Create NS delegation

```
POST /v1/ns/{ip}/{port}
```

Delegates NS for the subdomain to `ip:port`. Use this if you run your own DNS tunnel server (iodine, dns2tcpd, etc).

```bash
curl -X POST https://tun.domain.com/v1/ns/5.6.7.8/53
```

### Create reverse TCP tunnel

```
POST /v1/rtcp
```

Allocates a port on the gateway. Connect to it with `nc`, and the DNS tunnel terminates there.

```bash
curl -X POST https://tun.domain.com/v1/rtcp
```

### Check tunnel status

```
GET /v1/status/{subdomain}
```

### Delete tunnel

```
DELETE /v1/{subdomain}
Authorization: Bearer <token>
```

Requires the token returned during tunnel creation.

```bash
curl -X DELETE https://tun.domain.com/v1/a3f2bc -H "Authorization: Bearer c2334e6cfda45870a132286ac5d298e4"
```

### Health check

```
GET /health
```

## Configuration

All configuration is through environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_DOMAIN` | `domain.com` | Base domain(s) for tunnel subdomains (comma-separated for multiple) |
| `GATEWAY_IP` | `127.0.0.1` | Public IP of this server |
| `GATEWAY_DNS_ADDR` | `:53` | DNS listen address |
| `GATEWAY_API_ADDR` | `:8080` | API listen address (`:443` when TLS enabled) |
| `GATEWAY_TLS` | `false` | Enable Let's Encrypt autocert |
| `GATEWAY_REVERSE_PROXY` | `false` | Run behind nginx/caddy |
| `GATEWAY_TUNNEL_KEY` | (empty) | Shared auth key, empty = no auth |
| `LOG_LEVEL` | `info` | Log level: debug, info, warn, error |

## Build from source

```bash
git clone https://github.com/ohmymex/dns2tcp-gateway.git
cd dns2tcp-gateway
make build
```

Cross compile for Linux:

```bash
GOOS=linux GOARCH=amd64 make build
```

## Install with go

```bash
go install github.com/ohmymex/dns2tcp-gateway/cmd/dns2tcp@latest
```

## Systemd service

Copy `dns2tcp-gateway.service` to `/etc/systemd/system/` and adjust the environment variables:

```bash
cp dns2tcp-gateway.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dns2tcp-gateway
systemctl start dns2tcp-gateway
```

## Compatible tools

| Tool | Mode | How to use |
|------|------|------------|
| [dns2tcp](https://github.com/alex-sector/dns2tcp) | TCP | `dns2tcpc -r tunnel -z SUB.domain -l PORT RESOLVER` |
| [sshimpanzee](https://github.com/lexfo/sshimpanzee) | TCP | Uses dns2tcp protocol internally |
| [iodine](https://github.com/yarrick/iodine) | NS | Create NS delegation, run your own iodined |

## Disclaimer

This tool is intended for authorized security testing, research, and legitimate use cases where DNS tunneling is appropriate (restricted networks, CTF competitions, penetration testing with written authorization). Misuse of this software for unauthorized access to computer systems is illegal and unethical. The authors are not responsible for any damages or legal consequences resulting from misuse.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/thing`)
3. Commit your changes
4. Push to the branch (`git push origin feature/thing`)
5. Open a Pull Request

Run tests before submitting:

```bash
make test
make lint
```

## License

MIT

## Credits

Created by [NumeX](https://numex.sh). Based on the [THC ToolsWeNeed](https://github.com/orgs/hackerschoice/projects/4/views/1?pane=issue&itemId=54763597) proposal by SkyperTHC.
