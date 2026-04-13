package protocol

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// dns2tcp uses standard base64 without padding.
var encoding = base64.StdEncoding.WithPadding(base64.NoPadding)

/* Command prefixes used in dns2tcp protocol.
 * These appear as labels in the DNS query name: <data>.=<command>.<subdomain>.<zone> */
const (
	CmdAuth     = "auth"
	CmdResource = "resource"
	CmdConnect  = "connect"
)

// ParsedQuery represents a decoded dns2tcp DNS query.
type ParsedQuery struct {
	Command   string  // "auth", "resource", "connect", or "" for data queries
	Subdomain string  // the session subdomain (e.g. "m6kfjz")
	Packet    *Packet // decoded protocol packet
	Raw       string  // raw query name for debugging
}

// DecodeQuery parses a dns2tcp DNS query name into its components.
//
// dns2tcpc is configured with domain = "<subdomain>.<zone>" (e.g. "m6kfjz.tun.numex.sh").
// It sends queries in the format:
//
//	<base64-data>.=<command>.<subdomain>.<zone>
//
// For data queries (no command):
//
//	<base64-data>.<subdomain>.<zone>
//
// This function strips the zone, identifies the subdomain (last label),
// finds the command (label with "=" prefix), and decodes the base64 data.
func DecodeQuery(qname, zone string) (*ParsedQuery, error) {
	// Trim trailing dot but preserve original case for base64 data.
	qname = strings.TrimSuffix(qname, ".")
	zone = strings.TrimSuffix(zone, ".")

	// Case-insensitive zone matching (DNS is case-insensitive for domain names).
	qnameLower := strings.ToLower(qname)
	zoneLower := strings.ToLower(zone)

	if !strings.HasSuffix(qnameLower, "."+zoneLower) && qnameLower != zoneLower {
		return nil, fmt.Errorf("protocol: query %q not in zone %q", qname, zone)
	}

	// Zone apex query (e.g. "tun.numex.sh" with no subdomain prefix).
	if qnameLower == zoneLower {
		return nil, fmt.Errorf("protocol: zone apex query %q, no tunnel data", qname)
	}

	// Strip the zone from the ORIGINAL case query to preserve base64 data.
	// Zone length is the same regardless of case.
	prefix := qname[:len(qname)-len(zone)-1]
	if prefix == "" {
		return nil, fmt.Errorf("protocol: empty prefix in query %q", qname)
	}

	result := &ParsedQuery{Raw: qname}

	// Split into labels.
	labels := strings.Split(prefix, ".")
	if len(labels) == 0 {
		return nil, fmt.Errorf("protocol: no labels in query prefix %q", prefix)
	}

	// The last label is the session subdomain (case-insensitive, lowercase it).
	result.Subdomain = strings.ToLower(labels[len(labels)-1])
	labels = labels[:len(labels)-1]

	// If only the subdomain was present (direct subdomain query, no data).
	if len(labels) == 0 {
		return result, nil
	}

	// Scan remaining labels for the command (prefixed with "=").
	// Command is case-insensitive, data labels preserve original case for base64.
	var dataLabels []string
	for _, label := range labels {
		if strings.HasPrefix(label, "=") || strings.HasPrefix(label, "=") {
			result.Command = strings.ToLower(strings.TrimPrefix(label, "="))
		} else {
			dataLabels = append(dataLabels, label)
		}
	}

	/*
	 * Strip Go-relay seq uniqueness prefix if present: exactly 4 lowercase hex chars.
	 * Valid dns2tcp base64 data labels are always >=10 chars (7-byte minimum packet),
	 * so a 4-char label is unambiguously our prefix. C client (dns2tcpc) sends no prefix.
	 */
	if len(dataLabels) > 0 && len(dataLabels[0]) == 4 && isHexString(dataLabels[0]) {
		dataLabels = dataLabels[1:]
	}

	// Reassemble base64 data: join labels (dots are just DNS label separators).
	encoded := strings.Join(dataLabels, "")

	if encoded == "" {
		return result, nil
	}

	// Base64 decode.
	raw, err := encoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("protocol: base64 decode: %w", err)
	}

	// Parse the packet.
	pkt, err := Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("protocol: unmarshal packet: %w", err)
	}

	result.Packet = pkt
	return result, nil
}

// EncodeResponse builds a base64-encoded response payload from a packet.
func EncodeResponse(p *Packet) string {
	return encoding.EncodeToString(p.Marshal())
}

/*
 * EncodeTXTResponse builds a TXT record value.
 * dns2tcp TXT responses prepend a single-char index ('A' + answerIndex)
 * followed by the base64-encoded packet data.
 */
func EncodeTXTResponse(p *Packet, answerIndex int) string {
	indexChar := byte('A') + byte(answerIndex)
	encoded := encoding.EncodeToString(p.Marshal())
	return string(indexChar) + encoded
}

/*
 * EncodeQuery builds a dns2tcp QNAME for sending queries to the server.
 * domain is the full tunnel domain including subdomain (e.g. "m6kfjz.tun.numex.sh").
 * command is "auth", "resource", "connect", or "" for data queries.
 *
 * Output format: <base64-labels>.[=<command>.]<domain>.
 * Base64 data is split into 63-byte DNS labels when needed.
 */
func EncodeQuery(pkt *Packet, command, domain string) string {
	/*
	 * Prepend 4-hex seq label for QNAME uniqueness after DNS case normalization.
	 * Caching resolvers (e.g. Cloudflare) lowercase QNAMEs before serving from cache.
	 * base64 uses A-Z (values 0-25) and a-z (values 26-51), so seq=N and seq=N+26
	 * produce identical lowercased QNAMEs. The hex prefix distinguishes them:
	 * "0001.8sEAAAABBA..." != "001b.8sEAAAAbBA..." even after lowercasing.
	 */
	seqLabel := fmt.Sprintf("%04x", pkt.Seq)
	encoded := encoding.EncodeToString(pkt.Marshal())

	// Split base64 into DNS-safe labels (max 63 chars per label).
	var parts []string
	parts = append(parts, seqLabel)
	for len(encoded) > 63 {
		parts = append(parts, encoded[:63])
		encoded = encoded[63:]
	}
	if len(encoded) > 0 {
		parts = append(parts, encoded)
	}

	if command != "" {
		parts = append(parts, "="+command)
	}

	return strings.Join(parts, ".") + "." + strings.TrimSuffix(domain, ".") + "."
}

/*
 * DecodeTXTResponse decodes a dns2tcp TXT response into a Packet.
 * The txt slice comes from miekg/dns TXT.Txt (character-strings, 63-byte chunks).
 * First byte is an index char ('A' + answerIndex), rest is base64-encoded packet.
 */
func DecodeTXTResponse(txt []string) (*Packet, error) {
	if len(txt) == 0 {
		return nil, fmt.Errorf("protocol: empty TXT response")
	}
	data := strings.Join(txt, "")
	if len(data) < 2 {
		return nil, fmt.Errorf("protocol: TXT response too short (%d bytes)", len(data))
	}
	raw, err := encoding.DecodeString(data[1:])
	if err != nil {
		return nil, fmt.Errorf("protocol: base64 decode response: %w", err)
	}
	return Unmarshal(raw)
}

/*
 * MaxQueryPayload returns the maximum raw payload bytes (excluding the 7-byte
 * header) that fit in a single dns2tcp data query for the given domain.
 * Accounts for DNS wire format overhead (label length bytes, root null).
 */
func MaxQueryPayload(domain string) int {
	// DNS QNAME wire limit: 255 bytes including all length prefixes and root null.
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	overhead := 0
	for _, l := range labels {
		overhead += 1 + len(l) // length prefix + label data
	}
	overhead++ // root null byte

	available := 255 - overhead
	if available <= 5 {
		return 0
	}
	available -= 5 // Go relay seq prefix label: 1 length byte + 4 hex chars = 5 wire bytes.

	// Each base64 label costs 1 wire byte (length prefix) + up to 63 data bytes.
	var b64 int
	for available >= 2 {
		chunk := available
		if chunk > 64 {
			chunk = 64
		}
		b64 += chunk - 1
		available -= chunk
	}

	// base64 no-padding -> raw byte count
	raw := b64 / 4 * 3
	switch b64 % 4 {
	case 2:
		raw++
	case 3:
		raw += 2
	}

	if raw <= HeaderSize {
		return 0
	}
	return raw - HeaderSize
}

// EncodeTXTChunks builds TXT record string chunks compatible with dns2tcp's
// wire format. The original dns2tcp C server uses dns_encode() to split TXT
// data into DNS label format (max 63 bytes per label). The C client's
// dns_simple_decode() expects this format. miekg/dns encodes each string in
// the Txt slice as a separate character-string with a length prefix, matching
// the label format the client expects.
func EncodeTXTChunks(p *Packet, answerIndex int) []string {
	data := EncodeTXTResponse(p, answerIndex)

	const maxLabel = 63
	if len(data) <= maxLabel {
		return []string{data}
	}

	var chunks []string
	for len(data) > maxLabel {
		chunks = append(chunks, data[:maxLabel])
		data = data[maxLabel:]
	}
	if len(data) > 0 {
		chunks = append(chunks, data)
	}
	return chunks
}

/* isHexString reports whether s consists entirely of lowercase hex digits [0-9a-f].
 * Used to detect the Go-relay seq uniqueness prefix in DecodeQuery. */
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
