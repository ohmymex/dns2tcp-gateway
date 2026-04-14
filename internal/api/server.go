package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"

	"github.com/ohmymex/dns2tcp-gateway/internal/config"
	"github.com/ohmymex/dns2tcp-gateway/internal/relay"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
)

// Server is the REST API server for tunnel management.
type Server struct {
	http   *http.Server
	store  session.Store
	relay  *relay.Manager
	cfg    config.Config
	logger *slog.Logger
	tls    bool
}

// New creates a new API server wired to the given session store, relay manager, and config.
func New(cfg config.Config, store session.Store, relayMgr *relay.Manager, logger *slog.Logger) *Server {
	s := &Server{
		store:  store,
		relay:  relayMgr,
		cfg:    cfg,
		logger: logger.With("component", "api"),
		tls:    cfg.TLSEnabled,
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.http = &http.Server{
		Addr:         cfg.APIAddr,
		Handler:      s.withMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if s.tls {
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLSHosts...),
			Cache:      autocert.DirCache(cfg.TLSCertDir),
		}

		s.http.TLSConfig = &tls.Config{
			GetCertificate: manager.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}

		// HTTP-01 challenge listener on port 80.
		go func() {
			h := manager.HTTPHandler(nil)
			srv := &http.Server{
				Addr:         ":80",
				Handler:      h,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Error("acme http-01 challenge server failed", "error", err)
			}
		}()
	}

	return s
}

// Start begins serving HTTP(S) requests. It blocks until the server stops.
func (s *Server) Start() error {
	if s.tls {
		s.logger.Info("api server listening (tls)", "addr", s.cfg.APIAddr)
		if err := s.http.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("api server: %w", err)
		}
	} else {
		s.logger.Info("api server listening", "addr", s.cfg.APIAddr)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("api server: %w", err)
		}
	}
	return nil
}

// Shutdown gracefully stops the API server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/tunnels", s.handleList)
	mux.HandleFunc("POST /v1/tcp/{ip}/{port}", s.handleCreateTCP)
	mux.HandleFunc("POST /v1/ns/{ip}/{port}", s.handleCreateNS)
	mux.HandleFunc("POST /v1/socks5", s.handleCreateSOCKS5)
	mux.HandleFunc("POST /v1/rtcp", s.handleCreateRTCP)
	mux.HandleFunc("GET /v1/status/{subdomain}", s.handleStatus)
	mux.HandleFunc("PATCH /v1/{subdomain}", s.handleExtend)
	mux.HandleFunc("DELETE /v1/{subdomain}", s.handleDelete)
	mux.HandleFunc("GET /health", s.handleHealth)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return s.logMiddleware(s.rateLimitMiddleware(next))
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

/* per-IP rate limiter: 10 req/s, burst 20, stale cleanup every 5m */
type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*visitorLimiter
}

type visitorLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter() *ipLimiter {
	il := &ipLimiter{
		limiters: make(map[string]*visitorLimiter),
	}
	go il.cleanup()
	return il
}

func (il *ipLimiter) get(ip string) *rate.Limiter {
	il.mu.Lock()
	defer il.mu.Unlock()

	v, ok := il.limiters[ip]
	if !ok {
		limiter := rate.NewLimiter(10, 20)
		il.limiters[ip] = &visitorLimiter{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}
	v.lastSeen = time.Now()
	return v.limiter
}

func (il *ipLimiter) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		il.mu.Lock()
		for ip, v := range il.limiters {
			if time.Since(v.lastSeen) > 10*time.Minute {
				delete(il.limiters, ip)
			}
		}
		il.mu.Unlock()
	}
}

var limiter = newIPLimiter()

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r, s.cfg.ReverseProxy)

		if !limiter.get(ip).Allow() {
			s.logger.Warn("rate limited", "remote", ip)
			http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
