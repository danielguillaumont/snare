package token

import (
	"bytes"
	"strings"
	"testing"
)

func signer(t *testing.T, b byte) *Signer {
	t.Helper()
	s, err := NewSigner(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMintVerifyRoundTrip(t *testing.T) {
	s := signer(t, 1)
	tok, id, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != Length || len(tok) > 63 {
		t.Fatalf("length %d", len(tok))
	}
	if tok != strings.ToLower(tok) {
		t.Fatal("token must be lowercase for DNS")
	}
	got, err := s.Verify(tok)
	if err != nil || got != id {
		t.Fatalf("verify: %v %q != %q", err, got, id)
	}
	// DNS may hand us any case.
	if _, err := s.Verify(strings.ToUpper(tok)); err != nil {
		t.Fatalf("uppercase verify: %v", err)
	}
}

func TestTamperAndWrongKeyRejected(t *testing.T) {
	s := signer(t, 1)
	tok, _, _ := s.Mint()
	flip := []byte(tok)
	if flip[10] == 'a' {
		flip[10] = 'b'
	} else {
		flip[10] = 'a'
	}
	if _, err := s.Verify(string(flip)); err != ErrBadMAC {
		t.Fatalf("tampered id: got %v", err)
	}
	if _, err := signer(t, 2).Verify(tok); err != ErrBadMAC {
		t.Fatalf("wrong key: got %v", err)
	}
}

func TestMalformed(t *testing.T) {
	s := signer(t, 1)
	for _, in := range []string{"", "snr", "abc" + strings.Repeat("a", 32), "snr" + strings.Repeat("1", 32), "snr" + strings.Repeat("a", 33)} {
		if _, err := s.Verify(in); err != ErrMalformed {
			t.Errorf("%q: got %v", in, err)
		}
	}
}

func TestShortKey(t *testing.T) {
	if _, err := NewSigner(make([]byte, 16)); err != ErrShortKey {
		t.Fatal("expected ErrShortKey")
	}
}

func TestFindSkipsForgedCandidates(t *testing.T) {
	s := signer(t, 1)
	real, id, _ := s.Mint()
	forged, _, _ := signer(t, 9).Mint()
	text := "GET /t/" + forged + "/x?next=" + strings.ToUpper(real)
	got, ok := s.Find(text)
	if !ok || got != id {
		t.Fatalf("Find = %q %v, want %q", got, ok, id)
	}
	if _, ok := s.Find("nothing here " + forged); ok {
		t.Fatal("forged token must not match")
	}
}

func TestMintIsUnique(t *testing.T) {
	s := signer(t, 1)
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		tok, _, _ := s.Mint()
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

func FuzzVerifyNeverPanics(f *testing.F) {
	s, _ := NewSigner(bytes.Repeat([]byte{1}, 32))
	tok, _, _ := s.Mint()
	f.Add(tok)
	f.Add("snr" + strings.Repeat("7", 32))
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = s.Verify(in)
		_, _ = s.Find(in)
	})
}
