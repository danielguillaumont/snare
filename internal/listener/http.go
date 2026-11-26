// Package listener receives tripwire callbacks over HTTP and DNS.
package listener

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/danielguillaumont/snare/internal/token"
)

// Recorder is the part of the alert pipeline listeners need.
type Recorder interface {
	Hit(ctx context.Context, m token.Match, channel, sourceIP, detail string) error
}

// HTTP answers every request blandly and records any that carry a valid token in the
// host, path or query. Request bodies are drained (bounded) and never stored: a callback
// may carry stolen data.
type HTTP struct {
	Signer     *token.Signer
	Recorder   Recorder
	Log        *slog.Logger
	TrustProxy bool // take the client IP from X-Forwarded-For (set only behind your own proxy)

	PerIPRate  rate.Limit // requests/second per source IP (default 5)
	PerIPBurst int        // default 20

	mu       sync.Mutex
	limiters map[string]*ipLimiter
}

type ipLimiter struct {
	lim  *rate.Limiter
	seen time.Time
}

const maxBody = 64 << 10

func (h *HTTP) allow(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.limiters == nil {
		h.limiters = map[string]*ipLimiter{}
	}
	r, b := h.PerIPRate, h.PerIPBurst
	if r == 0 {
		r = 5
	}
	if b == 0 {
		b = 20
	}
	now := time.Now()
	l, ok := h.limiters[ip]
	if !ok {
		if len(h.limiters) > 50_000 { // evict idle entries under a flood
			for k, v := range h.limiters {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(h.limiters, k)
				}
			}
		}
		l = &ipLimiter{lim: rate.NewLimiter(r, b)}
		h.limiters[ip] = l
	}
	l.seen = now
	return l.lim.Allow()
}

func (h *HTTP) clientIP(r *http.Request) string {
	if h.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// The last entry was appended by our own proxy; earlier ones are client-controlled.
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxBody))

	if !h.allow(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	detail := r.Method + " " + r.URL.Path + " ua=" + r.UserAgent()
	urlM, urlHit := h.Signer.Match(r.Host + " " + r.URL.Path + "?" + r.URL.RawQuery)
	if urlHit {
		if err := h.Recorder.Hit(r.Context(), urlM, "http", ip, detail); err != nil {
			h.Log.Error("record http hit", "err", err)
		}
	}
	// A stolen honey API key arrives in a credential header, usually sent to the honey base
	// URL. Record it as its own hit so the alert says which value was used. Only the fact
	// that a token arrived in a header is stored, never the header itself.
	creds := r.Header.Get("Authorization") + " " + r.Header.Get("X-Api-Key") + " " + r.Header.Get("Api-Key")
	if m, ok := h.Signer.Match(creds); ok && (!urlHit || m.ID != urlM.ID) {
		if err := h.Recorder.Hit(r.Context(), m, "http", ip, detail+" via=credential-header"); err != nil {
			h.Log.Error("record http hit", "err", err)
		}
	}
	// Same bland answer for hits, misses and forgeries: the toucher learns nothing.
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}
