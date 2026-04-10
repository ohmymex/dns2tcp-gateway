package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/session"
)

// tunnelResponse is the JSON response for tunnel creation.
type tunnelResponse struct {
	ID        string   `json:"id"`
	Subdomain string   `json:"subdomain"`
	Domain    string   `json:"domain"`
	Domains   []string `json:"domains,omitempty"`
	Token     string   `json:"token,omitempty"`
	Mode      string   `json:"mode"`
	Target    string   `json:"target,omitempty"`
	RTCPPort  int      `json:"rtcp_port,omitempty"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at"`
	Message   string   `json:"message"`
}

// errorResponse is the JSON response for errors.
type errorResponse struct {
	Error string `json:"error"`
}

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10", "::/128",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// tunnelDomains returns all configured domains with the subdomain prepended.
// Used in API responses so clients know all available domain aliases for the tunnel.
func (s *Server) tunnelDomains(subdomain string) []string {
	domains := make([]string, len(s.cfg.Domains))
	for i, d := range s.cfg.Domains {
		domains[i] = fmt.Sprintf("%s.%s", subdomain, d)
	}
	return domains
}

func (s *Server) handleCreateTCP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	portStr := r.PathValue("port")

	parsed := net.ParseIP(ip)
	if parsed == nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}
	if isPrivateIP(parsed) {
		s.writeError(w, http.StatusForbidden, "private/reserved ip addresses are not allowed")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.writeError(w, http.StatusBadRequest, "invalid port number")
		return
	}

	sess, err := s.createSession(r, session.ModeTCP, ip, port)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.PrimaryDomain())
	s.writeJSON(w, http.StatusCreated, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Domains:   s.tunnelDomains(sess.Subdomain),
		Token:     sess.Token,
		Mode:      sess.Mode.String(),
		Target:    sess.Target(),
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		Message:   fmt.Sprintf("DNS tunnel to %s will forward to %s", fqdn, sess.Target()),
	})
}

func (s *Server) handleCreateNS(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	portStr := r.PathValue("port")

	parsed := net.ParseIP(ip)
	if parsed == nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}
	if isPrivateIP(parsed) {
		s.writeError(w, http.StatusForbidden, "private/reserved ip addresses are not allowed")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.writeError(w, http.StatusBadRequest, "invalid port number")
		return
	}

	sess, err := s.createSession(r, session.ModeNS, ip, port)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.PrimaryDomain())
	s.writeJSON(w, http.StatusCreated, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Domains:   s.tunnelDomains(sess.Subdomain),
		Token:     sess.Token,
		Mode:      sess.Mode.String(),
		Target:    sess.Target(),
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		Message:   fmt.Sprintf("%s NS will point to %s:%d", fqdn, ip, port),
	})
}

func (s *Server) handleCreateRTCP(w http.ResponseWriter, r *http.Request) {
	sess, err := s.createSession(r, session.ModeRTCP, "", 0)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Allocate an RTCP port and start listening.
	rtcpSess, err := s.relay.Create(r.Context(), sess.Subdomain)
	if err != nil {
		s.store.Delete(r.Context(), sess.Subdomain)
		s.writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	sess.RTCPPort = rtcpSess.Port

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.PrimaryDomain())
	s.writeJSON(w, http.StatusCreated, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Domains:   s.tunnelDomains(sess.Subdomain),
		Token:     sess.Token,
		Mode:      sess.Mode.String(),
		RTCPPort:  rtcpSess.Port,
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		Message:   fmt.Sprintf("use 'nc %s %d'. DNS tunnel to %s will terminate here.", s.cfg.PrimaryDomain(), rtcpSess.Port, fqdn),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	subdomain := r.PathValue("subdomain")

	sess, ok := s.store.Get(r.Context(), subdomain)
	if !ok {
		s.writeError(w, http.StatusNotFound, "tunnel not found or expired")
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.PrimaryDomain())
	s.writeJSON(w, http.StatusOK, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Domains:   s.tunnelDomains(sess.Subdomain),
		Mode:      sess.Mode.String(),
		Target:    sess.Target(),
		RTCPPort:  sess.RTCPPort,
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	subdomain := r.PathValue("subdomain")

	/* extract token from Authorization: Bearer <token> */
	token := ""
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		token = auth[7:]
	}
	if token == "" {
		s.writeError(w, http.StatusUnauthorized, "missing Authorization: Bearer <token>")
		return
	}

	sess, ok := s.store.Get(r.Context(), subdomain)
	if !ok {
		s.writeError(w, http.StatusNotFound, "tunnel not found")
		return
	}
	if sess.Token != token {
		s.writeError(w, http.StatusForbidden, "invalid token")
		return
	}

	s.store.Delete(r.Context(), subdomain)
	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("tunnel %s deleted", subdomain),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"sessions": s.store.Count(),
	})
}

func (s *Server) createSession(r *http.Request, mode session.Mode, ip string, port int) (*session.Session, error) {
	// Check per-IP tunnel limit.
	ownerIP := extractClientIP(r, s.cfg.ReverseProxy)
	existing := s.store.ListByOwner(r.Context(), ownerIP)
	if len(existing) >= s.cfg.MaxTunnelsPerIP {
		return nil, fmt.Errorf("max tunnels per ip reached (%d)", s.cfg.MaxTunnelsPerIP)
	}

	id, err := session.GenerateID()
	if err != nil {
		return nil, fmt.Errorf("generating session id: %w", err)
	}

	subdomain, err := session.GenerateSubdomain()
	if err != nil {
		return nil, fmt.Errorf("generating subdomain: %w", err)
	}

	token, err := session.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	now := time.Now()
	sess := &session.Session{
		ID:         id,
		Subdomain:  subdomain,
		Token:      token,
		Mode:       mode,
		TargetIP:   ip,
		TargetPort: port,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.SessionTTL),
		OwnerIP:    ownerIP,
	}

	if err := s.store.Put(r.Context(), sess); err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return sess, nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Error("failed to encode json response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, errorResponse{Error: msg})
}

/* extractClientIP: only trust XFF when behind a reverse proxy */
func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
