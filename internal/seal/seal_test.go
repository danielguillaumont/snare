package seal

import (
	"bytes"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestRoundTripAndBinding(t *testing.T) {
	s, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal([]byte(`{"token":"hec-secret"}`), "tn_a", "sk_1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("hec-secret")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	pt, err := s.Open(ct, "tn_a", "sk_1")
	if err != nil || string(pt) != `{"token":"hec-secret"}` {
		t.Fatalf("open: %q %v", pt, err)
	}
	// Bound to tenant and record: a copied row does not open.
	for _, c := range [][2]string{{"tn_b", "sk_1"}, {"tn_a", "sk_2"}, {"tn_", "ask_1"}} {
		if _, err := s.Open(ct, c[0], c[1]); !errors.Is(err, ErrOpen) {
			t.Fatalf("opened under %v", c)
		}
	}
	// Wrong key, tampering, truncation.
	s2, _ := New(key(2))
	if _, err := s2.Open(ct, "tn_a", "sk_1"); !errors.Is(err, ErrOpen) {
		t.Fatal("opened with wrong key")
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	if _, err := s.Open(bad, "tn_a", "sk_1"); !errors.Is(err, ErrOpen) {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := s.Open(ct[:10], "tn_a", "sk_1"); !errors.Is(err, ErrOpen) {
		t.Fatal("truncated ciphertext opened")
	}
	// Nonces are random: sealing twice differs.
	ct2, _ := s.Seal([]byte(`{"token":"hec-secret"}`), "tn_a", "sk_1")
	if bytes.Equal(ct, ct2) {
		t.Fatal("deterministic ciphertext")
	}
}

func TestKeyLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
}
