package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
)

// TestLoad measures one instance end to end on loopback (docs/M4d-operations.md §3). It is
// skipped unless SNARE_LOADTEST=1, and prints a table row per scenario:
//
//	SNARE_LOADTEST=1 go test ./internal/server -run TestLoad -v -count 1
//
// Each request carries a distinct X-Forwarded-For address (TrustProxy on), as a distributed
// sender would, so the per-IP rate limiter doesn't hide the cost of the work behind it.
func TestLoad(t *testing.T) {
	if os.Getenv("SNARE_LOADTEST") != "1" {
		t.Skip("set SNARE_LOADTEST=1 to run")
	}
	conc := envInt("SNARE_LOADTEST_CONC", 32)
	adminKey := "test-admin-key-0123456789abcdef"
	s, err := Start(Config{Key: bytes.Repeat([]byte{31}, 32), AdminKey: []byte(adminKey),
		SealKey: bytes.Repeat([]byte{32}, 32), HTTPAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		PublicURL: "http://cb.test", DBPath: filepath.Join(t.TempDir(), "snare.db"), TrustProxy: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: conc * 2}, Timeout: 30 * time.Second}
	base := "http://" + s.HTTPAddr

	var ipSeq atomic.Uint32
	nextIP := func() string {
		n := ipSeq.Add(1)
		return fmt.Sprintf("10.%d.%d.%d", byte(n>>16), byte(n>>8), byte(n))
	}
	run := func(name string, reqs []string, header func(i int) (string, string)) {
		lat := make([]time.Duration, len(reqs))
		var next atomic.Int64
		var failed atomic.Int64
		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(next.Add(1)) - 1
					if i >= len(reqs) {
						return
					}
					req, _ := http.NewRequest("GET", base+reqs[i], nil)
					req.Header.Set("X-Forwarded-For", nextIP())
					req.Header.Set("User-Agent", "snare-loadtest")
					if header != nil {
						k, v := header(i)
						req.Header.Set(k, v)
					}
					t0 := time.Now()
					resp, err := client.Do(req)
					lat[i] = time.Since(t0)
					if err != nil || resp.StatusCode != 200 {
						failed.Add(1)
						if resp != nil {
							resp.Body.Close()
						}
						continue
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()
		}
		wg.Wait()
		el := time.Since(start)
		slices.Sort(lat)
		pct := func(p float64) time.Duration { return lat[int(p*float64(len(lat)-1))] }
		t.Logf("| %s | %d | %d | %.0f | %v | %v | %v | %d |", name, len(reqs), conc,
			float64(len(reqs))/el.Seconds(), pct(0.50).Round(10*time.Microsecond),
			pct(0.99).Round(10*time.Microsecond), lat[len(lat)-1].Round(100*time.Microsecond), failed.Load())
	}
	t.Logf("| Scenario | Requests | Concurrency | Req/s | p50 | p99 | max | Failed |")
	t.Logf("|---|---|---|---|---|---|---|---|")

	// Junk: what the public port mostly sees. Scanners, and forged token-shaped paths that
	// each cost MAC checks.
	nJunk := envInt("SNARE_LOADTEST_JUNK", 20000)
	scan := make([]string, nJunk)
	forged := make([]string, nJunk)
	for i := range scan {
		scan[i] = "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=" + strconv.Itoa(i)
		forged[i] = "/v1/" + strings.Repeat("a", 24) + b32Suffix(i)
	}
	run("junk: scanner paths", scan, nil)
	run("junk: forged token-shaped paths", forged, nil)

	// Touches: each one is a new event, written and queued for delivery in one transaction.
	nTouch := envInt("SNARE_LOADTEST_TOUCH", 3000)
	toks := make([]string, nTouch)
	for i := range toks {
		var m admin.MintResponse
		adminCall(t, "POST", "http://"+s.AdminAddr+"/api/tokens", adminKey, admin.MintRequest{Kind: "canary_url", Label: "load " + strconv.Itoa(i)}, &m)
		toks[i] = "/v1/" + m.Token
	}
	run("touches: valid tokens, stored and queued", toks, nil)
	// Same tokens again from new sources: dedup doesn't apply (new source IP), so these are
	// stored and queued too, and correlation has history to scan.
	run("touches: repeat tokens, new sources", toks, nil)

}

// b32Suffix makes 8 base32 characters from i, so each forged path is a distinct 32-character
// body that passes the shape check and fails the MAC.
func b32Suffix(i int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz234567"
	var b [8]byte
	for k := range b {
		b[k] = alpha[i&31]
		i >>= 5
	}
	return string(b[:])
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}
