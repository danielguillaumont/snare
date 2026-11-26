package token

import (
	"bytes"
	"strings"
	"testing"
)

// The scanner runs on attacker-controlled text (hosts, paths, query names, credential
// headers). Invariants: it never panics, never spends more than maxAttempts MAC checks, only
// ever reports an id that really verifies, and always finds a real token that sits between
// separators, in any letter case.
func FuzzFind(f *testing.F) {
	s, err := NewSigner(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		f.Fatal(err)
	}
	tok, id, _ := s.Mint()
	hexSigner, _ := s.WithFormat("", Hex)
	hexTok, hexID, _ := hexSigner.Mint()

	for _, seed := range []struct{ pre, suf string }{
		{"", ""},
		{"https://cb.example/v1/", "?x=1"},
		{strings.Repeat("a", 500), strings.Repeat("7", 500)},
		{strings.Repeat("abcdefghijklmnopqrstuvwxyz234567 ", 40), ""},
		{"snr", ".cb.example."},
		{"Bearer ", ""},
		{"\x00\xff", "☃"},
		{strings.Repeat("0123456789abcdef", 30), "-"},
	} {
		f.Add(seed.pre, seed.suf, false)
		f.Add(seed.pre, seed.suf, true)
	}

	f.Fuzz(func(t *testing.T, pre, suf string, upper bool) {
		for _, c := range []struct {
			sg     *Signer
			tok    string
			wantID string
		}{{s, tok, id}, {hexSigner, hexTok, hexID}} {
			text := pre + c.tok + suf
			if upper {
				text = strings.ToUpper(text)
			}
			got, ok, attempts := c.sg.find(text)
			if attempts > maxAttempts {
				t.Fatalf("%d MAC checks, cap is %d", attempts, maxAttempts)
			}
			if ok {
				if got != c.wantID && !containsValidToken(c.sg, text, got) {
					t.Fatalf("reported id %q that no token in the input carries", got)
				}
			}
			// Between separators (no token alphabet characters touching it), the planted
			// token must be found.
			sepPre, sepSuf := onlySeparators(pre), onlySeparators(suf)
			clean := sepPre + c.tok + sepSuf
			if upper {
				clean = strings.ToUpper(clean)
			}
			if got, ok := c.sg.Find(clean); !ok || got != c.wantID {
				t.Fatalf("planted token not found in %q", clean)
			}
		}

		// Pure noise never yields a hit: forging an 80-bit MAC by fuzzing is not plausible,
		// so any hit here would mean the verifier accepts something it shouldn't.
		if got, ok := s.Find(pre + suf); ok && !containsValidToken(s, pre+suf, got) {
			t.Fatalf("noise produced id %q", got)
		}
	})
}

// onlySeparators keeps runes that can't extend a base32 or hex run.
func onlySeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return -1
		}
		return r
	}, s)
}

// containsValidToken reports whether some substring of text verifies to id. Used only to
// explain a hit the fuzzer didn't plant (it can splice the planted token into its inputs).
func containsValidToken(s *Signer, text, id string) bool {
	low := strings.ToLower(text)
	for _, n := range []int{b32Len, hexLen, len("snr") + b32Len} {
		for i := 0; i+n <= len(low); i++ {
			if got, err := s.Verify(low[i : i+n]); err == nil && got == id {
				return true
			}
		}
	}
	return false
}
