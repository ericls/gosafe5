package gosafe5

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// REF: https://developers.google.com/safe-browsing/reference/URLs.and.Hashing

// ErrInvalidURL identifies unsupported or malformed URLs and zero CanonicalURLs.
var ErrInvalidURL = errors.New("gosafe5: invalid URL")

// CanonicalURL holds canonical components used by Safe Browsing. It deliberately
// omits scheme, credentials, and port, which do not participate in hashing.
// Its zero value is invalid. Values are immutable and safe for concurrent use.
type CanonicalURL struct {
	host, path, query string
	hasQuery          bool
}

// Host returns the normalized host (IPv6 literals retain brackets).
func (u CanonicalURL) Host() string { return u.host }

// Path returns the normalized, escaped path.
func (u CanonicalURL) Path() string { return u.path }

// Query returns the escaped query and whether a query delimiter was present.
func (u CanonicalURL) Query() (string, bool) { return u.query, u.hasQuery }

// Canonicalize accepts an absolute HTTP or HTTPS URL and performs Safe Browsing
// normalization. Valid percent escapes are decoded repeatedly; literal percent
// signs are escaped again. Query contents are not path-normalized or form-decoded.
func Canonicalize(raw string) (CanonicalURL, error) {
	bad := func(reason string) (CanonicalURL, error) {
		return CanonicalURL{}, fmt.Errorf("%w: %s", ErrInvalidURL, reason)
	}
	raw = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(raw)
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || (!strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https")) {
		return bad("expected absolute HTTP(S) URL")
	}
	rest = unescapeRepeated(rest)
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	host := authority
	port := ""
	hasPort := false
	if strings.HasPrefix(host, "[") {
		close := strings.IndexByte(host, ']')
		if close < 0 {
			return bad("unclosed IPv6 literal")
		}
		if close+1 < len(host) {
			if host[close+1] != ':' {
				return bad("invalid IPv6 authority")
			}
			port, hasPort = host[close+2:], true
		}
		host = host[:close+1]
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host, port, hasPort = host[:i], host[i+1:], true
	}
	if hasPort {
		if port == "" {
			return bad("empty port")
		}
		for _, b := range []byte(port) {
			if b < '0' || b > '9' {
				return bad("invalid port")
			}
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return bad("invalid port")
		}
	}
	var err error
	host, err = canonicalHost(host)
	if err != nil {
		return CanonicalURL{}, err
	}
	path, query, hasQuery := strings.Cut(tail, "?")
	if path == "" {
		path = "/"
	}
	return CanonicalURL{host: escapeCanonical(host), path: escapeCanonical(cleanURLPath(path)),
		query: escapeCanonical(query), hasQuery: hasQuery}, nil
}

func canonicalHost(host string) (string, error) {
	bad := func() (string, error) { return "", fmt.Errorf("%w: invalid host", ErrInvalidURL) }
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ip, err := netip.ParseAddr(host[1 : len(host)-1])
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return bad()
		}
		ip = ip.Unmap()
		if ip.Is6() {
			b := ip.As16()
			if b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
				b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 {
				ip = netip.AddrFrom4([4]byte(b[12:]))
			}
		}
		if ip.Is4() {
			return ip.String(), nil
		}
		return "[" + ip.String() + "]", nil
	}
	if strings.ContainsAny(host, ":[]\\") {
		return bad()
	}
	// IDNA also normalizes Unicode dot variants before collapsing labels.
	if strings.IndexFunc(host, func(r rune) bool { return r >= 128 }) >= 0 {
		var err error
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return bad()
		}
	}
	host = strings.ToLower(strings.Join(strings.FieldsFunc(host, func(r rune) bool { return r == '.' }), "."))
	if host == "" {
		return bad()
	}
	if ip, ok := legacyIPv4(host); ok {
		return ip, nil
	}
	return host, nil
}

// legacyIPv4 implements inet_aton-style decimal, octal, hexadecimal, and
// shortened IPv4 forms. A non-address is left to ordinary hostname handling.
func legacyIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return "", false
	}
	var addr uint64
	for i, part := range parts {
		base := 10
		digits := part
		if strings.HasPrefix(part, "0x") {
			base, digits = 16, part[2:]
		} else if len(part) > 1 && part[0] == '0' {
			base, digits = 8, part[1:]
		}
		if digits == "" || strings.HasPrefix(digits, "+") || strings.HasPrefix(digits, "-") {
			return "", false
		}
		value, err := strconv.ParseUint(digits, base, 32)
		if err != nil {
			return "", false
		}
		bits := 8
		if i == len(parts)-1 {
			bits = 8 * (5 - len(parts))
		}
		if value >= uint64(1)<<uint(bits) {
			return "", false
		}
		addr = addr<<uint(bits) | value
	}
	return netip.AddrFrom4([4]byte{byte(addr >> 24), byte(addr >> 16), byte(addr >> 8), byte(addr)}).String(), true
}

func cleanURLPath(path string) string {
	parts := strings.Split(path, "/")
	stack := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, part)
		}
	}
	result := "/" + strings.Join(stack, "/")
	if result != "/" && (strings.HasSuffix(path, "/") || strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..")) {
		result += "/"
	}
	return result
}

func unescapeRepeated(s string) string {
	for {
		changed := false
		var out strings.Builder
		out.Grow(len(s))
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && i+2 < len(s) {
				hi, ok1 := unhex(s[i+1])
				lo, ok2 := unhex(s[i+2])
				if ok1 && ok2 {
					out.WriteByte(hi<<4 | lo)
					i += 2
					changed = true
					continue
				}
			}
			out.WriteByte(s[i])
		}
		if !changed {
			return s
		}
		s = out.String()
	}
}

func unhex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func escapeCanonical(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 32 || c >= 127 || c == '#' || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Expressions returns unique host-suffix/path-prefix combinations in stable
// order: exact host first, then decreasing suffix specificity; exact path with
// query, exact path, then directory prefixes starting at root. At most 30 are
// returned. PSL private domains are included. Hosts without a registrable domain
// and IP literals produce only an exact-host candidate.
func (u CanonicalURL) Expressions() ([]string, error) {
	if u.host == "" || u.path == "" {
		return nil, ErrInvalidURL
	}
	hosts := []string{u.host}
	if _, err := netip.ParseAddr(strings.Trim(u.host, "[]")); err != nil {
		if domain, err := publicsuffix.EffectiveTLDPlusOne(u.host); err == nil {
			labels := strings.Split(u.host, ".")
			baseLabels := strings.Count(domain, ".") + 1
			start := len(labels) - baseLabels - 3
			if start < 1 {
				start = 1
			}
			for i := start; i <= len(labels)-baseLabels; i++ {
				hosts = append(hosts, strings.Join(labels[i:], "."))
			}
		}
	}
	paths := make([]string, 0, 6)
	seen := make(map[string]bool)
	add := func(path string) {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}
	if u.hasQuery {
		add(u.path + "?" + u.query)
	}
	add(u.path)
	count := 0
	for i := 0; i < len(u.path) && count < 4; i++ {
		if u.path[i] == '/' {
			add(u.path[:i+1])
			count++
		}
	}
	result := make([]string, 0, len(hosts)*len(paths))
	for _, host := range hosts {
		for _, path := range paths {
			result = append(result, host+path)
		}
	}
	return result, nil
}

// URLHashes canonicalizes raw and hashes its expressions in Expressions order.
func URLHashes(raw string) ([]Hash, error) {
	u, err := Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	expressions, err := u.Expressions()
	if err != nil {
		return nil, err
	}
	hashes := make([]Hash, len(expressions))
	for i, expression := range expressions {
		hashes[i] = Hash(sha256.Sum256([]byte(expression)))
	}
	return hashes, nil
}
