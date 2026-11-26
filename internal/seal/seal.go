// Package seal encrypts small secrets at rest (sink credentials) with AES-256-GCM.
//
// The associated data binds a ciphertext to where it is stored (tenant id and sink id), so a
// row copied into another tenant's record, by a bug or by someone with write access to the
// database, fails to open instead of leaking one tenant's SIEM credentials into another's
// alerts.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const version byte = 1

var ErrOpen = errors.New("seal: cannot open (wrong key, tampered, or bound to another record)")

type Sealer struct{ aead cipher.AEAD }

// New takes a 32-byte key (SNARE_SEAL_KEY).
func New(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("seal: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func ad(tenantID, recordID string) []byte {
	return []byte(fmt.Sprintf("snare-seal-v1|%d:%s|%d:%s", len(tenantID), tenantID, len(recordID), recordID))
}

// Seal returns version || nonce || ciphertext.
func (s *Sealer) Seal(plaintext []byte, tenantID, recordID string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{version}, nonce...)
	return s.aead.Seal(out, nonce, plaintext, ad(tenantID, recordID)), nil
}

func (s *Sealer) Open(sealed []byte, tenantID, recordID string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < 1+n+s.aead.Overhead() || sealed[0] != version {
		return nil, ErrOpen
	}
	pt, err := s.aead.Open(nil, sealed[1:1+n], sealed[1+n:], ad(tenantID, recordID))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
