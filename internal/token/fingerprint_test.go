package token

import (
	"bytes"
	"strings"
	"testing"
)

func fpSigner(t *testing.T, b byte) *Signer {
	t.Helper()
	s, err := NewSigner(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBodiesCoverMintedTokens(t *testing.T) {
	old := fpSigner(t, 1)
	s, _ := fpSigner(t, 2).WithPrevious(bytes.Repeat([]byte{1}, 32))
	hexS, _ := s.WithFormat("acme", Hex)

	for _, c := range []struct {
		name string
		mint *Signer
	}{{"b32 current key", s}, {"hex with prefix", hexS}, {"b32 previous key", old}} {
		tok, id, err := c.mint.Mint()
		if err != nil {
			t.Fatal(err)
		}
		bodies, err := s.Bodies(id)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, b := range bodies {
			found = found || strings.HasSuffix(tok, b)
		}
		if !found {
			t.Errorf("%s: no body of %s matches token %s (bodies %v)", c.name, id, tok, bodies)
		}
	}
	if _, err := s.Bodies("not-an-id"); err == nil {
		t.Error("malformed id accepted")
	}
}

func TestFingerprintScan(t *testing.T) {
	s := fpSigner(t, 3)
	hexS, _ := s.WithFormat("", Hex)
	b32tok, b32id, _ := s.Mint()
	hextok, hexid, _ := hexS.Mint()
	_, otherid, _ := s.Mint()
	const salt = "c2FsdA"
	fps := FingerprintSet{}
	for _, id := range []string{b32id, hexid} {
		bodies, _ := s.Bodies(id)
		for _, b := range bodies {
			fps.Add(Fingerprint(salt, b))
		}
	}
	m := NewMatcher(salt, fps)

	for _, c := range []struct {
		name, text, want string
	}{
		{"bare b32", b32tok, b32tok},
		{"in JSON", `{"to":"x@example.com","body":"key=` + b32tok + `; thanks"}`, b32tok},
		{"uppercased", strings.ToUpper(`{"k":"` + b32tok + `"}`), b32tok},
		{"hex in URL", `{"url":"https://h.example/` + hextok + `?a=1"}`, hextok},
		{"glued to more base32", `"zzzz` + b32tok + `zz"`, b32tok},
		{"absent", `{"q":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0123456789abcdef0123456789abcdef01234567"}`, ""},
	} {
		got, ok := m.Find(c.text)
		if c.want == "" {
			if ok {
				t.Errorf("%s: false match %q", c.name, got)
			}
			continue
		}
		if !ok || !strings.EqualFold(got, c.want) && !strings.HasSuffix(strings.ToLower(c.want), got) {
			t.Errorf("%s: got %q ok=%v, want %q", c.name, got, ok, c.want)
		}
	}

	// A token whose fingerprint isn't in the set is not reported, even though it is valid.
	otherBodies, _ := s.Bodies(otherid)
	if _, ok := m.Find("x " + otherBodies[0] + " y"); ok {
		t.Error("matched a token outside the fingerprint set")
	}
	// A different salt yields different fingerprints: sets don't link across installs.
	if Fingerprint("a", "b") == Fingerprint("c", "b") {
		t.Error("salt does not change the fingerprint")
	}
}

func TestFingerprintScanIsBounded(t *testing.T) {
	s := fpSigner(t, 4)
	tok, id, _ := s.Mint()
	bodies, _ := s.Bodies(id)
	fps := FingerprintSet{}
	for _, b := range bodies {
		fps.Add(Fingerprint("s", b))
	}
	m := NewMatcher("s", fps)
	// One very long base32 run produces more windows than the cap; a token after it is not
	// guaranteed to be found, but the scan must stop at the cap.
	junk := strings.Repeat("a", 100_000)
	_, _, n := m.find(junk + " " + tok)
	if n > MaxWindows {
		t.Fatalf("scanned %d windows, cap is %d", n, MaxWindows)
	}
	if _, ok := m.Find("short " + tok); !ok {
		t.Fatal("token not found in short input")
	}
}
