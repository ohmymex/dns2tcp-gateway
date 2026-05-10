package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/client"
	"github.com/ohmymex/dns2tcp-gateway/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	zone := flag.String("z", "", "DNS zone (e.g. m6kfjz.tun.numex.sh)")
	resource := flag.String("r", "", "resource name (e.g. tunnel)")
	listen := flag.String("l", "", "local port or - for stdio")
	key := flag.String("k", "", "tunnel authentication key")
	resolver := flag.String("d", "", "DNS resolver: 1.1.1.1 (UDP), https://1.1.1.1/dns-query (DoH), tls://1.1.1.1 (DoT). Default: system resolver.")
	showVersion := flag.Bool("version", false, "show version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "dns2tcp-client %s\n\n", version.String())
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  dns2tcp-client -z <domain> -r <resource> -l <port|-> [-k key] [-d resolver]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  dns2tcp-client -z abc123.tun.numex.sh -r tunnel -l 2222 -d 1.1.1.1\n")
		fmt.Fprintf(os.Stderr, "  dns2tcp-client -z abc123.tun.numex.sh -r tunnel -l 2222 -d https://1.1.1.1/dns-query\n")
		fmt.Fprintf(os.Stderr, "  dns2tcp-client -z abc123.tun.numex.sh -r tunnel -l 2222 -d tls://1.1.1.1\n")
		fmt.Fprintf(os.Stderr, "  ssh -o ProxyCommand=\"dns2tcp-client -z abc123.tun.numex.sh -r tunnel -l - -d 1.1.1.1\" user@target\n\n")
		fmt.Fprintf(os.Stderr, "  Note: Google 8.8.8.8 is incompatible (0x20 case randomization corrupts payloads).\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("dns2tcp-client %s\n", version.String())
		return nil
	}

	if *zone == "" || *listen == "" {
		flag.Usage()
		return fmt.Errorf("required: -z (zone) and -l (listen port or -)")
	}

	resolverAddr, err := resolveServer(*resolver)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Stdio mode: single session on stdin/stdout.
	if *listen == "-" {
		return runSession(ctx, resolverAddr, *zone, *resource, *key, stdioPipe{}, logger)
	}

	// TCP listener mode: one tunnel session per incoming connection.
	addr := "127.0.0.1:" + *listen
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()
	logger.Info("listening", "addr", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		logger.Info("new connection", "remote", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			if err := runSession(ctx, resolverAddr, *zone, *resource, *key, conn, logger); err != nil {
				if ctx.Err() == nil {
					logger.Error("session error", "error", err)
				}
			}
		}()
	}
}

/* runSession performs the full tunnel lifecycle for a single connection:
 * authenticate, connect to resource, relay data. */
func runSession(ctx context.Context, resolver, domain, resource, key string, local io.ReadWriteCloser, logger *slog.Logger) error {
	transport, err := client.NewTransport(resolver)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer transport.Close()

	sess := client.NewSession(transport, domain, key, logger)
	if err := sess.Authenticate(ctx); err != nil {
		return err
	}

	// No resource specified: list available resources and exit.
	if resource == "" {
		list, err := sess.ListResources(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "available resources: %s\n", list)
		return nil
	}

	if err := sess.Connect(ctx, resource); err != nil {
		return err
	}

	relay := client.NewRelay(transport, local, domain, sess.SessionID(), logger)
	return relay.Run(ctx)
}

func resolveServer(explicit string) (string, error) {
	if explicit != "" {
		if !strings.Contains(explicit, ":") {
			explicit += ":53"
		}
		return explicit, nil
	}

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("reading /etc/resolv.conf: %w (use -d to specify resolver)", err)
	}
	if len(config.Servers) == 0 {
		return "", fmt.Errorf("no nameservers in /etc/resolv.conf (use -d to specify resolver)")
	}
	server := config.Servers[0]
	if strings.Contains(server, ":") {
		server = "[" + server + "]"
	}
	return server + ":" + config.Port, nil
}

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// stdioPipe wraps stdin/stdout as an io.ReadWriteCloser for ProxyCommand mode.
type stdioPipe struct{}

func (stdioPipe) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdioPipe) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdioPipe) Close() error                { return nil }
