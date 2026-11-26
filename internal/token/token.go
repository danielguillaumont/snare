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
// almost nothing. Find caps MAC computations per input to keep junk traffic cheap.
//
// Key rotation (docs/M4c-reliability.md §5): a signer mints with its current key and also
// verifies with up to MaxPreviousKeys retired ones, so rotating the key doesn't silence every
// planted tripwire. Each key costs one MAC per candidate, out of the same per-input budget.
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
	// maxAttempts caps MAC computations per Find call, across all keys.
	maxAttempts = 256
	// MaxPreviousKeys bounds how many retired keys still verify.
	MaxPreviousKeys = 3

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

	prefixRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,11}$`)

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
	ErrPrevious  = fmt.Errorf("token: at most %d previous keys, each at least %d bytes and different from the current key", MaxPreviousKeys, MinKeyBytes)
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

// Signer mints tokens with its current key and verifies with that key and any previous ones.
type Signer struct {
	key      []byte
	previous [][]byte
	prefix   string
	encoding Encoding
}

// Match is a verified token found in untrusted input.
type Match struct {
	ID string
	// PreviousKey is true when the token verified under a retired key: the tripwire works,
	// but should be replanted before that key is dropped.
	PreviousKey bool
}

// WithPrevious returns a copy of s that also verifies tokens minted under the given retired
// keys. New tokens still use the current key.
func (s *Signer) WithPrevious(keys ...[]byte) (*Signer, error) {
	if len(keys) > MaxPreviousKeys {
		return nil, ErrPrevious
	}
	c := *s
	c.previous = nil
	for _, k := range keys {
		if len(k) < MinKeyBytes || hmac.Equal(k, s.key) {
			return nil, ErrPrevious
		}
		c.previous = append(c.previous, append([]byte(nil), k...))
	}
	return &c, nil
}

// keys returns the current key first, then the previous ones.
func (s *Signer) keys() [][]byte { return append([][]byte{s.key}, s.previous...) }

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

func (s *Signer) mac(domain string, id []byte) []byte { return macWith(s.key, domain, id) }

func macWith(key []byte, domain string, id []byte) []byte {
	m := hmac.New(sha256.New, key)
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

// verifyBody checks a bare v2 body (no prefix) under the current key only.
func (s *Signer) verifyBody(body string) (string, error) {
	m, _, err := s.verifyBodyKeys(body, 1)
	return m.ID, err
}

// verifyBodyKeys checks a bare v2 body under up to maxKeys keys, current first, and returns
// how many MACs it computed.
func (s *Signer) verifyBodyKeys(body string, maxKeys int) (Match, int, error) {
	var raw []byte
	var err error
	switch len(body) {
	case b32Len:
		raw, err = b32.DecodeString(strings.ToUpper(body))
	case hexLen:
		raw, err = hex.DecodeString(body)
	default:
		return Match{}, 0, ErrMalformed
	}
	if err != nil || len(raw) != idBytes+macBytes {
		return Match{}, 0, ErrMalformed
	}
	return s.check(v2Domain, raw[:idBytes], raw[idBytes:], maxKeys)
}

func (s *Signer) verifyV1(tok string) (string, error) {
	m, _, err := s.verifyV1Keys(tok, 1)
	return m.ID, err
}

func (s *Signer) verifyV1Keys(tok string, maxKeys int) (Match, int, error) {
	if len(tok) != v1Length || !strings.HasPrefix(tok, v1Prefix) {
		return Match{}, 0, ErrMalformed
	}
	id, err := b32.DecodeString(strings.ToUpper(tok[3:19]))
	if err != nil || len(id) != idBytes {
		return Match{}, 0, ErrMalformed
	}
	got, err := b32.DecodeString(strings.ToUpper(tok[19:]))
	if err != nil || len(got) != macBytes {
		return Match{}, 0, ErrMalformed
	}
	return s.check(v1Domain, id, got, maxKeys)
}

// check compares got against the MAC under each key in turn (current first), at most maxKeys
// of them, constant-time per comparison. It returns the MACs computed.
func (s *Signer) check(domain string, id, got []byte, maxKeys int) (Match, int, error) {
	n := 0
	for i, k := range s.keys() {
		if i >= maxKeys {
			break
		}
		n++
		if hmac.Equal(got, macWith(k, domain, id)) {
			return Match{ID: idString(id), PreviousKey: i > 0}, n, nil
		}
	}
	return Match{}, n, ErrBadMAC
}

// Verify checks a whole token (v2 with or without this signer's prefix, or v1) under every
// key and returns its ID. MAC comparison is constant-time.
func (s *Signer) Verify(tok string) (string, error) {
	tok = strings.ToLower(tok)
	all := len(s.previous) + 1
	m, _, v1err := s.verifyV1Keys(tok, all)
	if v1err == nil {
		return m.ID, nil
	}
	body := tok
	if s.prefix != "" {
		body = strings.TrimPrefix(tok, s.prefix)
	}
	m, _, err := s.verifyBodyKeys(body, all)
	if err == ErrMalformed && v1err != ErrMalformed {
		return "", v1err // v1-shaped: report its real failure (bad MAC)
	}
	return m.ID, err
}

// Find returns the ID of the first valid token embedded anywhere in text (host, path, query
// name), whatever its prefix. Forged candidates are skipped, so they can't mask a real token.
func (s *Signer) Find(text string) (id string, ok bool) {
	m, ok, _ := s.find(text)
	return m.ID, ok
}

// Match is Find, also reporting whether a previous key verified the token.
func (s *Signer) Match(text string) (Match, bool) {
	m, ok, _ := s.find(text)
	return m, ok
}

// find is Match plus the number of MAC computations spent, so tests can hold the cap. Each
// candidate costs one MAC per key. When the budget can't cover every key for a candidate,
// it is checked against as many as fit, current key first.
func (s *Signer) find(text string) (m Match, ok bool, attempts int) {
	text = strings.ToLower(text)
	nkeys := len(s.previous) + 1
	try := func(f func(maxKeys int) (Match, int, error)) bool {
		budget := maxAttempts - attempts
		if budget > nkeys {
			budget = nkeys
		}
		got, n, err := f(budget)
		attempts += n
		if err == nil {
			m = got
			return true
		}
		return false
	}
	for _, c := range v1Candidates(text, 8) {
		if attempts >= maxAttempts {
			return Match{}, false, attempts
		}
		if try(func(k int) (Match, int, error) { return s.verifyV1Keys(c, k) }) {
			return m, true, attempts
		}
	}
	for _, scan := range []struct {
		class *[256]bool
		n     int
	}{{&b32Class, b32Len}, {&hexClass, hexLen}} {
		for _, run := range runs(text, scan.class, scan.n, 16) {
			for off := 0; off+scan.n <= len(run); off++ {
				if attempts >= maxAttempts {
					return Match{}, false, attempts
				}
				w := run[off : off+scan.n]
				if try(func(k int) (Match, int, error) { return s.verifyBodyKeys(w, k) }) {
					return m, true, attempts
				}
			}
		}
	}
	return Match{}, false, attempts
}
