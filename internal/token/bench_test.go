package token

import (
	"bytes"
	"strings"
	"testing"
)

// Benchmarks for docs/results-bench.md (M4d §3). Run:
//
//	go test ./internal/token -run '^$' -bench . -benchmem -count 5

func benchSigner(b *testing.B, keys int) *Signer {
	b.Helper()
	s, err := NewSigner(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		b.Fatal(err)
	}
	var prev [][]byte
	for i := 0; i < keys-1; i++ {
		prev = append(prev, bytes.Repeat([]byte{byte(2 + i)}, 32))
	}
	if s, err = s.WithPrevious(prev...); err != nil {
		b.Fatal(err)
	}
	return s
}

func BenchmarkMatch(b *testing.B) {
	for _, keys := range []int{1, 4} {
		s := benchSigner(b, keys)
		tok, _, _ := s.Mint()
		// A token minted under the oldest key: the worst case for a valid match.
		old := benchSigner(b, 1)
		if keys > 1 {
			old, _ = NewSigner(bytes.Repeat([]byte{byte(keys)}, 32))
		}
		oldTok, _, _ := old.Mint()
		junk := strings.Repeat("a", len(tok)) // same shape, wrong MAC
		cases := []struct{ name, text string }{
			{"valid", "GET /v1/" + tok + " HTTP/1.1"},
			{"valid-oldest-key", "GET /v1/" + oldTok + " HTTP/1.1"},
			{"junk-same-shape", "GET /v1/" + junk + " HTTP/1.1"},
			// No token-shaped run at all: what most scanner traffic looks like.
			{"8KiB-no-candidate", strings.Repeat("GET /wp-login.php?x=1 HTTP/1.1\r\nHost: x\r\n", 200)},
			// One long base32 run: every offset is a candidate, so the 256-MAC cap is what bounds it.
			{"adversarial-long-run", strings.Repeat("abcdefghijklmnopqrstuvwxyz234567", 64)},
		}
		for _, c := range cases {
			b.Run(c.name+"/keys="+string(rune('0'+keys)), func(b *testing.B) {
				b.SetBytes(int64(len(c.text)))
				for i := 0; i < b.N; i++ {
					s.Match(c.text)
				}
			})
		}
	}
}
