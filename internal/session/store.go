package session

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Store defines the interface for session persistence.
type Store interface {
	Put(ctx context.Context, s *Session) error
	Get(ctx context.Context, subdomain string) (*Session, bool)
	Delete(ctx context.Context, subdomain string) bool
	ListByOwner(ctx context.Context, ownerIP string) []*Session
	ExtendTTL(ctx context.Context, subdomain string, d time.Duration) (*Session, bool)
	Count() int
}

// MemoryStore is a thread-safe in-memory implementation of Store.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by subdomain
	logger   *slog.Logger
}

// Compile-time interface check.
var _ Store = (*MemoryStore)(nil)

// NewMemoryStore creates a new in-memory session store.
func NewMemoryStore(logger *slog.Logger) *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*Session),
		logger:   logger,
	}
}

func (m *MemoryStore) Put(_ context.Context, s *Session) error {
	if s == nil {
		return fmt.Errorf("session: cannot store nil session")
	}
	if s.Subdomain == "" {
		return fmt.Errorf("session: subdomain must not be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s.isActive = true
	m.sessions[s.Subdomain] = s
	m.logger.Info("session stored",
		"subdomain", s.Subdomain,
		"mode", s.Mode.String(),
		"owner", s.OwnerIP,
	)
	return nil
}

func (m *MemoryStore) Get(_ context.Context, subdomain string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[subdomain]
	if !ok {
		return nil, false
	}
	if s.IsExpired() {
		return nil, false
	}
	return s, true
}

func (m *MemoryStore) Delete(_ context.Context, subdomain string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[subdomain]
	if !ok {
		return false
	}
	s.isActive = false
	delete(m.sessions, subdomain)
	m.logger.Info("session deleted", "subdomain", subdomain)
	return true
}

func (m *MemoryStore) ListByOwner(_ context.Context, ownerIP string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Session
	for _, s := range m.sessions {
		if s.OwnerIP == ownerIP && !s.IsExpired() {
			result = append(result, s)
		}
	}
	return result
}

// ExtendTTL atomically extends a session's expiry. Returns the updated session.
func (m *MemoryStore) ExtendTTL(_ context.Context, subdomain string, d time.Duration) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[subdomain]
	if !ok || s.IsExpired() {
		return nil, false
	}
	s.ExpiresAt = time.Now().Add(d)
	m.logger.Info("session extended", "subdomain", subdomain, "expires_at", s.ExpiresAt.Format(time.RFC3339))
	return s, true
}

func (m *MemoryStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// StartCleanup runs a background goroutine that removes expired sessions.
// It stops when the context is cancelled. The caller must wait for the returned
// channel to close before considering cleanup fully stopped.
func (m *MemoryStore) StartCleanup(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				m.logger.Info("session cleanup stopped")
				return
			case <-ticker.C:
				m.cleanup()
			}
		}
	}()

	return done
}

func (m *MemoryStore) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expired []string
	for sub, s := range m.sessions {
		if s.IsExpired() {
			expired = append(expired, sub)
		}
	}

	for _, sub := range expired {
		delete(m.sessions, sub)
	}

	if len(expired) > 0 {
		m.logger.Info("expired sessions cleaned", "count", len(expired))
	}
}
