package token

import (
	"bytes"
	"crypto/rand"
	"regexp"
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

func format(t *testing.T, s *Signer, prefix string, enc Encoding) *Signer {
	t.Helper()
	f, err := s.WithFormat(prefix, enc)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// mintV1 builds a pre-v2 token, as planted before M3a-fix.
func mintV1(s *Signer) (string, string) {
	raw := make([]byte, idBytes)
	_, _ = rand.Read(raw)
	return v1Prefix + idString(raw) + strings.ToLower(b32.EncodeToString(s.mac(v1Domain, raw))), idString(raw)
}

func TestFormats(t *testing.T) {
	base := signer(t, 1)
	cases := []struct {
		s     *Signer
		shape *regexp.Regexp
	}{
		{base, regexp.MustCompile(`^[a-z2-7]{32}$`)},
		{format(t, base, "", Hex), regexp.MustCompile(`^[0-9a-f]{40}$`)},
		{format(t, base, "nw-", B32), regexp.MustCompile(`^nw-[a-z2-7]{32}$`)},
		{format(t, base, "acme", Hex), regexp.MustCompile(`^acme[0-9a-f]{40}$`)},
	}
	for _, c := range cases {
		tok, id, err := c.s.Mint()
		if err != nil {
			t.Fatal(err)
		}
		if !c.shape.MatchString(tok) || len(tok) > 63 {
			t.Errorf("token %q has the wrong shape", tok)
		}
		got, err := c.s.Verify(tok)
		if err != nil || got != id {
			t.Errorf("verify %q: %v %q != %q", tok, err, got, id)
		}
		if _, err := c.s.Verify(strings.ToUpper(tok)); err != nil {
			t.Errorf("uppercase verify %q: %v", tok, err)
		}
		// Changing the install's format later must not break planted tokens.
		if got, ok := base.Find("GET /t/" + tok + "/x"); !ok || got != id {
			t.Errorf("base signer can't Find %q", tok)
		}
	}
}

func TestDefaultHasNoFixedPrefix(t *testing.T) {
	s := signer(t, 1)
	first := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, _, _ := s.Mint()
		first[tok[:3]] = true
	}
	if len(first) < 150 {
		t.Fatalf("only %d distinct 3-char starts in 200 tokens: looks like a fixed prefix", len(first))
	}
}

func TestV1StillVerifies(t *testing.T) {
	s := signer(t, 1)
	tok, id := mintV1(s)
	if got, err := s.Verify(tok); err != nil || got != id {
		t.Fatalf("v1 verify: %v", err)
	}
	if got, ok := s.Find(tok + ".cb.example.com."); !ok || got != id {
		t.Fatal("v1 Find")
	}
	if _, err := signer(t, 2).Verify(tok); err != ErrBadMAC {
		t.Fatalf("v1 wrong key: %v", err)
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
	for _, in := range []string{"", "snr", strings.Repeat("a", 31), strings.Repeat("1", 32), strings.Repeat("g", 40), strings.Repeat("a", 33)} {
		if _, err := s.Verify(in); err != ErrMalformed {
			t.Errorf("%q: got %v", in, err)
		}
	}
}

func TestPrefixValidation(t *testing.T) {
	s := signer(t, 1)
	for _, bad := range []string{"sk-", "sk_live_", "AKIA", "ghp_", "xoxb-", "aiza", "-x", "has space", "UPPER_", "snr", strings.Repeat("a", 13), "a_b"} {
		if _, err := s.WithFormat(bad, B32); err == nil {
			t.Errorf("prefix %q accepted", bad)
		}
	}
	for _, ok := range []string{"", "nw-", "acme", "int-7"} {
		if _, err := s.WithFormat(ok, B32); err != nil {
			t.Errorf("prefix %q rejected: %v", ok, err)
		}
	}
	if _, err := s.WithFormat("", "b64"); err != ErrEncoding {
		t.Errorf("bad encoding: %v", err)
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

func TestFindEmbeddedInLongerRun(t *testing.T) {
	s := format(t, signer(t, 1), "nwk", B32)
	tok, id, _ := s.Mint()
	// Prefix glued to the body, inside a hostname label: the window scan finds it.
	if got, ok := signer(t, 1).Find(tok + ".cb.example.com"); !ok || got != id {
		t.Fatal("prefixed token not found by window scan")
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
	v1, _ := mintV1(s)
	f.Add(tok)
	f.Add(v1)
	f.Add("snr" + strings.Repeat("7", 32))
	f.Add(strings.Repeat("ab", 30))
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = s.Verify(in)
		_, _ = s.Find(in)
	})
}

func TestRotationKeepsOldTokensWorking(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
	old, _ := NewSigner(oldKey)
	oldTok, oldID, _ := old.Mint()

	cur, _ := NewSigner(newKey)
	rotated, err := cur.WithPrevious(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	newTok, newID, _ := rotated.Mint()
	if _, err := old.Verify(newTok); err == nil {
		t.Fatal("new tokens must be minted under the new key")
	}
	if m, ok := rotated.Match("GET /v1/" + oldTok); !ok || m.ID != oldID || !m.PreviousKey {
		t.Fatalf("old token after rotation: %+v %v", m, ok)
	}
	if m, ok := rotated.Match("GET /v1/" + newTok); !ok || m.ID != newID || m.PreviousKey {
		t.Fatalf("new token: %+v %v", m, ok)
	}
	if id, err := rotated.Verify(oldTok); err != nil || id != oldID {
		t.Fatalf("Verify old token: %v", err)
	}
	// A token under a key that is no longer configured is rejected.
	if _, ok := cur.Match(oldTok); ok {
		t.Fatal("old token verified without its key configured")
	}
	// v1 tokens rotate too.
	v1, _ := mintV1(old)
	if m, ok := rotated.Match(v1); !ok || !m.PreviousKey {
		t.Fatalf("v1 token after rotation: %+v %v", m, ok)
	}
}

func TestWithPreviousValidation(t *testing.T) {
	cur, _ := NewSigner(bytes.Repeat([]byte{1}, 32))
	k := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	for name, keys := range map[string][][]byte{
		"too many":        {k(2), k(3), k(4), k(5)},
		"short":           {[]byte("short")},
		"same as current": {k(1)},
	} {
		if _, err := cur.WithPrevious(keys...); err != ErrPrevious {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := cur.WithPrevious(k(2), k(3), k(4)); err != nil {
		t.Fatal(err)
	}
}

// With four keys, junk input still costs at most maxAttempts MACs.
func TestAttemptCapHoldsAcrossKeys(t *testing.T) {
	cur, _ := NewSigner(bytes.Repeat([]byte{1}, 32))
	s, _ := cur.WithPrevious(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32))
	junk := strings.Repeat("abcdefghijklmnopqrstuvwxyz234567", 64)
	_, ok, attempts := s.find(junk)
	if ok || attempts > maxAttempts || attempts < maxAttempts-4 {
		t.Fatalf("ok=%v attempts=%d cap=%d", ok, attempts, maxAttempts)
	}
	_, _, one := cur.find(junk)
	if one > maxAttempts {
		t.Fatalf("single key: %d", one)
	}
}
