// Package token mints and verifies Snare tripwire tokens.
//
// A token is "snr" + base32(id) + base32(mac), all lowercase:
//
//	id  = 10 random bytes
//	mac = first 10 bytes of HMAC-SHA256(key, "snare/v1|" || id)
//
// That is 35 characters: one DNS label, URL-safe, case-insensitive. Listeners verify the
// MAC before any database work, so scanner noise and forged tokens cost almost nothing.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	Prefix   = "snr"
	idBytes  = 10
	macBytes = 10
	// Length of an encoded token.
	Length = len(Prefix) + 16 + 16
	domain = "snare/v1|"
	// MinKeyBytes is the minimum server key size.
	MinKeyBytes = 32
)

var (
	enc = base32.StdEncoding.WithPadding(base32.NoPadding)
	// Candidate matches anywhere in a string (path, host, query name). Verify confirms them.
	candidate = regexp.MustCompile(`(?i)snr[a-z2-7]{32}`)

	ErrMalformed = errors.New("token: malformed")
	ErrBadMAC    = errors.New("token: bad signature")
	ErrShortKey  = fmt.Errorf("token: key must be at least %d bytes", MinKeyBytes)
)

// Signer mints and verifies tokens with one server key.
type Signer struct{ key []byte }

func NewSigner(key []byte) (*Signer, error) {
	if len(key) < MinKeyBytes {
		return nil, ErrShortKey
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k}, nil
}

func (s *Signer) mac(id []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(domain))
	m.Write(id)
	return m.Sum(nil)[:macBytes]
}

// Mint returns a new token and its ID (the hex-free base32 id part, used as the DB key).
func (s *Signer) Mint() (tok string, id string, err error) {
	raw := make([]byte, idBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	idEnc := strings.ToLower(enc.EncodeToString(raw))
	macEnc := strings.ToLower(enc.EncodeToString(s.mac(raw)))
	return Prefix + idEnc + macEnc, idEnc, nil
}

// Verify checks a token and returns its ID. Comparison is constant-time.
func (s *Signer) Verify(tok string) (string, error) {
	tok = strings.ToLower(tok)
	if len(tok) != Length || !strings.HasPrefix(tok, Prefix) {
		return "", ErrMalformed
	}
	idEnc := tok[len(Prefix) : len(Prefix)+16]
	macEnc := tok[len(Prefix)+16:]
	id, err := enc.DecodeString(strings.ToUpper(idEnc))
	if err != nil || len(id) != idBytes {
		return "", ErrMalformed
	}
	got, err := enc.DecodeString(strings.ToUpper(macEnc))
	if err != nil || len(got) != macBytes {
		return "", ErrMalformed
	}
	if !hmac.Equal(got, s.mac(id)) {
		return "", ErrBadMAC
	}
	return idEnc, nil
}

// Find returns the ID of the first valid token embedded in s, if any.
// Invalid candidates (wrong MAC) are skipped, so a forged token can't mask a real one.
func (s *Signer) Find(text string) (id string, ok bool) {
	for _, c := range candidate.FindAllString(text, 8) {
		if id, err := s.Verify(c); err == nil {
			return id, true
		}
	}
	return "", false
}
