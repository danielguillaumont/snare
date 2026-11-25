// Package token mints and verifies Snare tripwire tokens.
//
// v2 (current, docs/M3a-fix-antifingerprint.md):
//
//	token = prefix + encode(id || mac)
//	id    = 10 random bytes
//	mac   = first 10 bytes of HMAC-SHA256(key, "snare/v2|" || id)
//
// The encoding is lowercase base32 (32 chars, default) or lowercase hex (40 chars). The prefix
// is empty by default, so a token looks like any other random secret: only the server key can
// tell it apart. Every form is one DNS label, URL-safe and case-insensitive.
//
// v1 tokens ("snr" + base32(id) + base32(mac), 35 chars, domain "snare/v1|") still verify, so
// tripwires planted before v2 keep working. New tokens are always v2.
//
// Listeners verify the MAC before any database work, so scanner noise and forged tokens cost
// almost nothing. Find caps MAC attempts per input to keep junk traffic cheap.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	idBytes  = 10
	macBytes = 10
	// MinKeyBytes is the minimum server key size.
	MinKeyBytes = 32
	// MaxPrefix is the longest allowed per-install prefix.
	MaxPrefix = 12
	// maxAttempts caps MAC checks per Find call.
	maxAttempts = 256

	v1Prefix = "snr"
	v1Length = len(v1Prefix) + 32
	v1Domain = "snare/v1|"
	v2Domain = "snare/v2|"
	b32Len   = 32 // base32 of 20 bytes
	hexLen   = 40 // hex of 20 bytes
)

// Encoding of the token body.
type Encoding string

const (
	B32 Encoding = "b32"
	Hex Encoding = "hex"
)

var (
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

	v1Candidate = regexp.MustCompile(`snr[a-z2-7]{32}`)
	b32Run      = regexp.MustCompile(`[a-z2-7]{32,}`)
	hexRun      = regexp.MustCompile(`[0-9a-f]{40,}`)
	prefixRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,11}$`)

	// Reserved prefixes. Real providers' key formats: honey values must never imitate a real
	// vendor's keys (CLAUDE.md). And "snr", the v1 prefix: it's the public fingerprint v2 removes.
	providerPrefixes = []string{
		"snr", "sk-", "sk_", "pk_", "rk_", "akia", "asia", "aws", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
		"github", "glpat", "xox", "aiza", "ya29", "sg.", "shp", "npm_", "pypi", "hf_", "dop_",
		"eyj", "sq0", "sl.", "ntn_", "lin_", "pat",
	}

	ErrMalformed = errors.New("token: malformed")
	ErrBadMAC    = errors.New("token: bad signature")
	ErrShortKey  = fmt.Errorf("token: key must be at least %d bytes", MinKeyBytes)
	ErrPrefix    = fmt.Errorf("token: prefix must be 1-%d chars of [a-z0-9-], start with a letter or digit, and not resemble a real provider's key prefix", MaxPrefix)
	ErrEncoding  = errors.New("token: encoding must be b32 or hex")
)

// ValidatePrefix reports whether p may be used as a per-install token prefix.
func ValidatePrefix(p string) error {
	if p == "" {
		return nil
	}
	if !prefixRE.MatchString(p) {
		return ErrPrefix
	}
	for _, bad := range providerPrefixes {
		if strings.HasPrefix(p, bad) || strings.HasPrefix(bad, p) {
			return ErrPrefix
		}
	}
	return nil
}

// Signer mints and verifies tokens with one server key.
type Signer struct {
	key      []byte
	prefix   string
	encoding Encoding
}

// NewSigner returns a signer that mints v2 tokens: no prefix, base32.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < MinKeyBytes {
		return nil, ErrShortKey
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k, encoding: B32}, nil
}

// WithFormat returns a copy of s that mints tokens with the given prefix and encoding.
// Verification accepts every format regardless, so changing it never breaks old tripwires.
func (s *Signer) WithFormat(prefix string, encoding Encoding) (*Signer, error) {
	prefix = strings.ToLower(prefix)
	if err := ValidatePrefix(prefix); err != nil {
		return nil, err
	}
	if encoding == "" {
		encoding = B32
	}
	if encoding != B32 && encoding != Hex {
		return nil, ErrEncoding
	}
	c := *s
	c.prefix, c.encoding = prefix, encoding
	return &c, nil
}

func (s *Signer) mac(domain string, id []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(domain))
	m.Write(id)
	return m.Sum(nil)[:macBytes]
}

func idString(raw []byte) string { return strings.ToLower(b32.EncodeToString(raw)) }

// Mint returns a new v2 token and its ID (base32 of the random id; the DB key).
func (s *Signer) Mint() (tok string, id string, err error) {
	raw := make([]byte, idBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	body := append(append([]byte{}, raw...), s.mac(v2Domain, raw)...)
	var enc string
	if s.encoding == Hex {
		enc = hex.EncodeToString(body)
	} else {
		enc = strings.ToLower(b32.EncodeToString(body))
	}
	return s.prefix + enc, idString(raw), nil
}

// verifyBody checks a bare v2 body (no prefix).
func (s *Signer) verifyBody(body string) (string, error) {
	var raw []byte
	var err error
	switch len(body) {
	case b32Len:
		raw, err = b32.DecodeString(strings.ToUpper(body))
	case hexLen:
		raw, err = hex.DecodeString(body)
	default:
		return "", ErrMalformed
	}
	if err != nil || len(raw) != idBytes+macBytes {
		return "", ErrMalformed
	}
	id, got := raw[:idBytes], raw[idBytes:]
	if !hmac.Equal(got, s.mac(v2Domain, id)) {
		return "", ErrBadMAC
	}
	return idString(id), nil
}

func (s *Signer) verifyV1(tok string) (string, error) {
	if len(tok) != v1Length || !strings.HasPrefix(tok, v1Prefix) {
		return "", ErrMalformed
	}
	id, err := b32.DecodeString(strings.ToUpper(tok[3:19]))
	if err != nil || len(id) != idBytes {
		return "", ErrMalformed
	}
	got, err := b32.DecodeString(strings.ToUpper(tok[19:]))
	if err != nil || len(got) != macBytes {
		return "", ErrMalformed
	}
	if !hmac.Equal(got, s.mac(v1Domain, id)) {
		return "", ErrBadMAC
	}
	return idString(id), nil
}

// Verify checks a whole token (v2 with or without this signer's prefix, or v1) and returns
// its ID. MAC comparison is constant-time.
func (s *Signer) Verify(tok string) (string, error) {
	tok = strings.ToLower(tok)
	id, v1err := s.verifyV1(tok)
	if v1err == nil {
		return id, nil
	}
	body := tok
	if s.prefix != "" {
		body = strings.TrimPrefix(tok, s.prefix)
	}
	id, err := s.verifyBody(body)
	if err == ErrMalformed && v1err != ErrMalformed {
		return "", v1err // v1-shaped: report its real failure (bad MAC)
	}
	return id, err
}

// Find returns the ID of the first valid token embedded anywhere in text (host, path, query
// name), whatever its prefix. Forged candidates are skipped, so they can't mask a real token.
func (s *Signer) Find(text string) (id string, ok bool) {
	text = strings.ToLower(text)
	attempts := 0
	try := func(f func() (string, error)) bool {
		attempts++
		if v, err := f(); err == nil {
			id = v
			return true
		}
		return false
	}
	for _, c := range v1Candidate.FindAllString(text, 8) {
		if attempts >= maxAttempts {
			return "", false
		}
		if try(func() (string, error) { return s.verifyV1(c) }) {
			return id, true
		}
	}
	for _, scan := range []struct {
		re *regexp.Regexp
		n  int
	}{{b32Run, b32Len}, {hexRun, hexLen}} {
		for _, run := range scan.re.FindAllString(text, 16) {
			for off := 0; off+scan.n <= len(run); off++ {
				if attempts >= maxAttempts {
					return "", false
				}
				w := run[off : off+scan.n]
				if try(func() (string, error) { return s.verifyBody(w) }) {
					return id, true
				}
			}
		}
	}
	return "", false
}
