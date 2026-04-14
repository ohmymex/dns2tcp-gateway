package tunnel

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
)

// Resource defines a named TCP forwarding target.
type Resource struct {
	Name string
	Host string
	Port int
}

func (r Resource) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

const (
	maxClients       = 1000            // max concurrent tunnel clients
	authTimeout      = 30 * time.Second // unauthenticated clients get reaped after this
	clientCleanupInt = 10 * time.Second
)

// Manager handles dns2tcp tunnel protocol sessions.
type Manager struct {
	mu      sync.RWMutex
	clients map[uint16]*Client

	store    session.Store
	logger   *slog.Logger
	key      string
	stopOnce sync.Once
	stop     chan struct{}
}

// NewManager creates a new tunnel manager.
func NewManager(store session.Store, key string, logger *slog.Logger) *Manager {
	m := &Manager{
		clients: make(map[uint16]*Client),
		store:   store,
		key:     key,
		logger:  logger.With("component", "tunnel"),
		stop:    make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// HandleQuery processes an incoming dns2tcp protocol query and returns a response packet.
func (m *Manager) HandleQuery(ctx context.Context, q *protocol.ParsedQuery) (*protocol.Packet, error) {
	if q.Packet == nil {
		return nil, fmt.Errorf("tunnel: nil packet in query")
	}

	switch q.Command {
	case protocol.CmdAuth:
		return m.handleAuth(q.Packet, q.Subdomain)
	case protocol.CmdResource:
		return m.handleResource(ctx, q.Packet, q.Subdomain)
	case protocol.CmdConnect:
		return m.handleConnect(ctx, q.Packet, q.Subdomain)
	case "":
		// Data or NOP query.
		return m.handleData(q.Packet)
	default:
		return nil, fmt.Errorf("tunnel: unknown command %q", q.Command)
	}
}

func (m *Manager) handleAuth(pkt *protocol.Packet, subdomain string) (*protocol.Packet, error) {
	if pkt.SessionID == 0 {
		/* step 1: client requests challenge */
		m.mu.RLock()
		count := len(m.clients)
		m.mu.RUnlock()
		if count >= maxClients {
			return &protocol.Packet{
				SessionID: 0,
				Type:      protocol.TypeErr,
				Payload:   []byte("server full"),
			}, nil
		}

		sessionID, err := m.generateSessionID()
		if err != nil {
			return nil, err
		}

		challenge, err := protocol.GenerateChallenge()
		if err != nil {
			return nil, err
		}

		client := NewClient(sessionID, m.logger)
		client.Challenge = challenge
		client.Subdomain = subdomain

		m.mu.Lock()
		m.clients[sessionID] = client
		m.mu.Unlock()

		m.logger.Info("auth challenge sent", "session_id", sessionID, "subdomain", subdomain)

		return &protocol.Packet{
			SessionID: sessionID,
			Type:      protocol.TypeOK,
			Payload:   []byte(challenge),
		}, nil
	}

	// Step 2: Client sends HMAC response.
	m.mu.RLock()
	client, ok := m.clients[pkt.SessionID]
	m.mu.RUnlock()

	if !ok {
		return &protocol.Packet{
			SessionID: pkt.SessionID,
			Type:      protocol.TypeErr,
			Payload:   []byte("unknown session"),
		}, nil
	}

	// If no key configured, accept any auth.
	if m.key != "" {
		clientHMAC := string(pkt.Payload)
		if !protocol.VerifyHMAC(m.key, client.Challenge, clientHMAC) {
			m.logger.Warn("auth failed", "session_id", pkt.SessionID)
			m.removeClient(pkt.SessionID)
			return &protocol.Packet{
				SessionID: pkt.SessionID,
				Type:      protocol.TypeErr,
				Payload:   []byte("auth failed"),
			}, nil
		}
	}

	client.SetAuthed()
	m.logger.Info("auth success", "session_id", pkt.SessionID)

	return &protocol.Packet{
		SessionID: pkt.SessionID,
		Type:      protocol.TypeOK,
	}, nil
}

func (m *Manager) handleResource(ctx context.Context, pkt *protocol.Packet, subdomain string) (*protocol.Packet, error) {
	client := m.getClient(pkt.SessionID)
	if client == nil {
		return m.errPacket(pkt.SessionID, "not authenticated"), nil
	}
	/* public resolvers can reorder: =resource may arrive before auth step 2 */
	if !client.WaitAuthed(500 * time.Millisecond) {
		return m.errPacket(pkt.SessionID, "not authenticated"), nil
	}

	resourceList := m.buildResourceList(ctx, subdomain)

	return &protocol.Packet{
		SessionID: pkt.SessionID,
		Type:      protocol.TypeOK,
		Payload:   []byte(resourceList),
	}, nil
}

func (m *Manager) handleConnect(ctx context.Context, pkt *protocol.Packet, subdomain string) (*protocol.Packet, error) {
	client := m.getClient(pkt.SessionID)
	if client == nil {
		return m.errPacket(pkt.SessionID, "not authenticated"), nil
	}
	/* public resolvers can reorder: =connect may arrive before auth step 2 */
	if !client.WaitAuthed(500 * time.Millisecond) {
		return m.errPacket(pkt.SessionID, "not authenticated"), nil
	}

	resourceName := string(pkt.Payload)
	client.Resource = resourceName

	target := m.resolveResource(ctx, subdomain)
	if target == "" {
		m.logger.Warn("resource not found", "resource", resourceName, "subdomain", subdomain, "session_id", pkt.SessionID)
		return m.errPacket(pkt.SessionID, "resource not found"), nil
	}

	if target == "socks5" {
		if err := client.ConnectSOCKS5(); err != nil {
			m.logger.Error("socks5 setup failed", "error", err)
			return m.errPacket(pkt.SessionID, "connection failed"), nil
		}
	} else {
		if err := client.ConnectTCP(target); err != nil {
			m.logger.Error("tcp connect failed", "target", target, "error", err)
			return m.errPacket(pkt.SessionID, "connection failed"), nil
		}
	}

	m.logger.Info("tunnel connected", "session_id", pkt.SessionID, "resource", resourceName, "target", target)

	return &protocol.Packet{
		SessionID: pkt.SessionID,
		Type:      protocol.TypeOK,
	}, nil
}

func (m *Manager) handleData(pkt *protocol.Packet) (*protocol.Packet, error) {
	client := m.getClient(pkt.SessionID)
	if client == nil {
		return m.errPacket(pkt.SessionID, "unknown session"), nil
	}

	if pkt.IsDesauth() {
		m.logger.Info("client disconnect", "session_id", pkt.SessionID)
		client.Close()
		m.removeClient(pkt.SessionID)
		return &protocol.Packet{
			SessionID: pkt.SessionID,
			Type:      protocol.TypeOK,
		}, nil
	}

	if pkt.IsData() && len(pkt.Payload) > 0 {
		if err := client.HandleData(pkt.Seq, pkt.Payload); err != nil {
			m.logger.Debug("data forward failed", "error", err, "session_id", pkt.SessionID)
		}
	} else {
		client.MarkNOPSeen(pkt.Seq)
	}

	return client.DrainPending(pkt.Seq, MaxPayloadSize), nil
}

/* resolveResource looks up the REST API session by subdomain.
 * Returns the TCP target address for ModeTCP, "socks5" marker for ModeSOCKS5,
 * or "" if the session is not found or not a connectable mode. */
func (m *Manager) resolveResource(ctx context.Context, subdomain string) string {
	sess, ok := m.store.Get(ctx, subdomain)
	if !ok {
		return ""
	}
	switch sess.Mode {
	case session.ModeTCP:
		return sess.Target()
	case session.ModeSOCKS5:
		return "socks5"
	default:
		return ""
	}
}

/* buildResourceList returns the resource descriptor for this subdomain's session.
 * Format matches dns2tcp: "name:target". Shown when client runs without -r flag. */
func (m *Manager) buildResourceList(ctx context.Context, subdomain string) string {
	sess, ok := m.store.Get(ctx, subdomain)
	if !ok {
		return ""
	}
	switch sess.Mode {
	case session.ModeTCP:
		return fmt.Sprintf("tunnel:%s", sess.Target())
	case session.ModeSOCKS5:
		return "tunnel:socks5"
	default:
		return ""
	}
}

func (m *Manager) getClient(id uint16) *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[id]
}

func (m *Manager) removeClient(id uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[id]; ok {
		c.Close()
		delete(m.clients, id)
	}
}

func (m *Manager) errPacket(sessionID uint16, msg string) *protocol.Packet {
	return &protocol.Packet{
		SessionID: sessionID,
		Type:      protocol.TypeErr,
		Payload:   []byte(msg),
	}
}

func (m *Manager) generateSessionID() (uint16, error) {
	for i := 0; i < 100; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(0xFFFF))
		if err != nil {
			return 0, fmt.Errorf("tunnel: generating session id: %w", err)
		}
		id := uint16(n.Int64()) + 1 // avoid zero

		m.mu.RLock()
		_, exists := m.clients[id]
		m.mu.RUnlock()

		if !exists {
			return id, nil
		}
	}
	return 0, fmt.Errorf("tunnel: failed to generate unique session id after 100 attempts")
}

/*
 * cleanupLoop: reap unauthenticated clients that didn't complete auth
 * within authTimeout. Prevents memory exhaustion from DNS auth spam.
 */
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(clientCleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.reapStaleClients()
		case <-m.stop:
			return
		}
	}
}

func (m *Manager) reapStaleClients() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, client := range m.clients {
		if !client.IsAuthed && now.Sub(client.CreatedAt) > authTimeout {
			client.Close()
			delete(m.clients, id)
			m.logger.Debug("reaped stale client", "session_id", id)
		}
	}
}

func (m *Manager) Shutdown() {
	m.stopOnce.Do(func() { close(m.stop) })

	m.mu.Lock()
	defer m.mu.Unlock()

	for id, client := range m.clients {
		client.Close()
		delete(m.clients, id)
	}
	m.logger.Info("all tunnel clients closed")
}
