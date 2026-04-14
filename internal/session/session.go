package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Mode represents the type of tunnel.
type Mode int

const (
	ModeUnknown Mode = iota
	ModeTCP
	ModeNS
	ModeRTCP
	ModeSOCKS5
)

// String returns the human-readable name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeTCP:
		return "tcp"
	case ModeNS:
		return "ns"
	case ModeRTCP:
		return "rtcp"
	case ModeSOCKS5:
		return "socks5"
	default:
		return "unknown"
	}
}

// ParseMode converts a string to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "tcp":
		return ModeTCP, nil
	case "ns":
		return ModeNS, nil
	case "rtcp":
		return ModeRTCP, nil
	case "socks5":
		return ModeSOCKS5, nil
	default:
		return ModeUnknown, fmt.Errorf("session: unknown mode %q", s)
	}
}

// Session represents an active tunnel session.
type Session struct {
	ID         string    `json:"id"`
	Subdomain  string    `json:"subdomain"`
	Token      string    `json:"token"`
	Mode       Mode      `json:"mode"`
	TargetIP   string    `json:"target_ip,omitempty"`
	TargetPort int       `json:"target_port,omitempty"`
	RTCPPort   int       `json:"rtcp_port,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	OwnerIP    string    `json:"owner_ip"`
	isActive   bool
}

// IsExpired returns true if the session has passed its expiry time.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns true if the session is active and not expired.
func (s *Session) IsActive() bool {
	return s.isActive && !s.IsExpired()
}

// Target returns the target as "ip:port" string.
func (s *Session) Target() string {
	if s.TargetIP == "" || s.TargetPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", s.TargetIP, s.TargetPort)
}

// subdomainCharset is lowercase alphanumeric, excluding ambiguous chars (0, o, 1, l).
const subdomainCharset = "abcdefghjkmnpqrstuvwxyz23456789"

// GenerateSubdomain creates a cryptographically random 6-character alphanumeric subdomain.
// Guarantees at least one letter and one digit for readability.
func GenerateSubdomain() (string, error) {
	const length = 6
	for attempts := 0; attempts < 10; attempts++ {
		b := make([]byte, length)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("session: generating subdomain: %w", err)
		}

		result := make([]byte, length)
		hasLetter := false
		hasDigit := false
		for i := range result {
			result[i] = subdomainCharset[b[i]%byte(len(subdomainCharset))]
			if result[i] >= 'a' && result[i] <= 'z' {
				hasLetter = true
			}
			if result[i] >= '2' && result[i] <= '9' {
				hasDigit = true
			}
		}

		if hasLetter && hasDigit {
			return string(result), nil
		}
	}

	// Fallback: force mix by placing a letter at pos 0 and digit at pos 1.
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generating subdomain: %w", err)
	}
	letters := "abcdefghjkmnpqrstuvwxyz"
	digits := "23456789"
	b[0] = letters[b[0]%byte(len(letters))]
	b[1] = digits[b[1]%byte(len(digits))]
	for i := 2; i < 6; i++ {
		b[i] = subdomainCharset[b[i]%byte(len(subdomainCharset))]
	}
	return string(b), nil
}

// GenerateID creates a cryptographically random 16-character hex session ID.
func GenerateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateToken creates a cryptographically random 32-character hex token.
func GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generating token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
