package token

import (
	"bytes"
	"testing"
)

// A derived token is stable for one key and name, differs across keys and names, and
// verifies like a minted one (docs/M11-heartbeat.md §1).
func TestDerive(t *testing.T) {
	a, _ := NewSigner(bytes.Repeat([]byte{1}, 32))
	b, _ := NewSigner(bytes.Repeat([]byte{2}, 32))
	t1, id1 := a.Derive("heartbeat:default")
	t2, id2 := a.Derive("heartbeat:default")
	if t1 != t2 || id1 != id2 {
		t.Fatal("not stable")
	}
	if t3, _ := a.Derive("heartbeat:other"); t3 == t1 {
		t.Fatal("same token for different names")
	}
	if t4, id4 := b.Derive("heartbeat:default"); t4 == t1 || id4 == id1 {
		t.Fatal("same token under different keys")
	}
	if id, err := a.Verify(t1); err != nil || id != id1 {
		t.Fatalf("verify: %q %v", id, err)
	}
	if _, err := b.Verify(t1); err == nil {
		t.Fatal("verified under the wrong key")
	}
	if m, ok := a.Match("GET /v1/" + t1 + " ua=x"); !ok || m.ID != id1 {
		t.Fatalf("match: %+v %v", m, ok)
	}
	minted, _, _ := a.Mint()
	if len(minted) != len(t1) {
		t.Fatalf("derived token has a different shape: %d vs %d", len(t1), len(minted))
	}
}
