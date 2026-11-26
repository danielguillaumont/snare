package token

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fingerprints let a component recognize Snare tokens without the signing key and without a
// list of tokens (docs/M6-gateway.md §3). The Snare gateway sits on the agent's machine,
// where a hijacked agent can read its config, so it holds only salted hashes of token
// bodies. A hash of 80 bits of MAC material can't be turned back into a token.
//
//	fingerprint = hex(SHA-256("snare/fp/v1|" + salt + "|" + body))[:32]
//
// body is a v2 token without its prefix (base32 or hex) or a whole v1 token, lowercase.

// MaxWindows caps the candidate windows hashed per Find call.
const MaxWindows = 4096

const fpDomain = "snare/fp/v1|"

// Fingerprint returns the fingerprint of one token body under salt.
func Fingerprint(salt, body string) string {
	h := sha256.Sum256([]byte(fpDomain + salt + "|" + strings.ToLower(body)))
	return hex.EncodeToString(h[:16])
}

// FingerprintSet is a set of fingerprints.
type FingerprintSet map[string]struct{}

func (f FingerprintSet) Add(fp string) { f[fp] = struct{}{} }

// Bodies returns every body a token with this id can appear as: v2 base32 and hex under the
// current and each previous key, and the v1 form under each key. Prefixes are not part of a
// body, so tokens minted with any prefix are covered.
func (s *Signer) Bodies(id string) ([]string, error) {
	raw, err := b32.DecodeString(strings.ToUpper(id))
	if err != nil || len(raw) != idBytes {
		return nil, fmt.Errorf("token: malformed id %q", id)
	}
	var out []string
	for _, k := range s.keys() {
		body := append(append([]byte{}, raw...), macWith(k, v2Domain, raw)...)
		out = append(out, strings.ToLower(b32.EncodeToString(body)), hex.EncodeToString(body),
			v1Prefix+idString(raw)+strings.ToLower(b32.EncodeToString(macWith(k, v1Domain, raw))))
	}
	return out, nil
}

// Matcher finds tokens whose fingerprint is in a set. It keeps fingerprints as raw 16-byte
// keys and hashes each window into a reused buffer, so a scan allocates almost nothing.
type Matcher struct {
	prefix []byte
	set    map[[16]byte]struct{}
}

// NewMatcher builds a matcher; entries that aren't 32 hex characters are ignored.
func NewMatcher(salt string, set FingerprintSet) *Matcher {
	m := &Matcher{prefix: []byte(fpDomain + salt + "|"), set: make(map[[16]byte]struct{}, len(set))}
	for fp := range set {
		var k [16]byte
		if b, err := hex.DecodeString(fp); err == nil && len(b) == 16 {
			copy(k[:], b)
			m.set[k] = struct{}{}
		}
	}
	return m
}

// Find returns the first token body in text whose fingerprint is in the set. It looks at the
// same candidate windows as Signer.Match, at most MaxWindows of them.
func (m *Matcher) Find(text string) (body string, ok bool) {
	body, ok, _ = m.find(text)
	return body, ok
}

func (m *Matcher) find(text string) (string, bool, int) {
	if len(m.set) == 0 {
		return "", false, 0
	}
	text = strings.ToLower(text)
	n := 0
	buf := make([]byte, len(m.prefix), len(m.prefix)+hexLen)
	copy(buf, m.prefix)
	try := func(w string) bool {
		n++
		sum := sha256.Sum256(append(buf[:len(m.prefix)], w...))
		_, hit := m.set[[16]byte(sum[:16])]
		return hit
	}
	for _, c := range v1Candidates(text, 64) {
		if n >= MaxWindows {
			return "", false, n
		}
		if try(c) {
			return c, true, n
		}
	}
	for _, scan := range []struct {
		class *[256]bool
		n     int
	}{{&b32Class, b32Len}, {&hexClass, hexLen}} {
		for _, run := range runs(text, scan.class, scan.n, 256) {
			for off := 0; off+scan.n <= len(run); off++ {
				if n >= MaxWindows {
					return "", false, n
				}
				if w := run[off : off+scan.n]; try(w) {
					return w, true, n
				}
			}
		}
	}
	return "", false, n
}
