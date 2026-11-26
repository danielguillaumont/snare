// Package listener receives tripwire callbacks over HTTP and DNS.
package listener

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

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

	limiters limiterTable
}

const maxBody = 64 << 10

func (h *HTTP) allow(ip string) bool {
	r, b := h.PerIPRate, h.PerIPBurst
	if r == 0 {
		r = 5
	}
	if b == 0 {
		b = 20
	}
	return h.limiters.get(limitKey(ip), r, b).Allow()
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
	detail := r.Method + " " + r.URL.Path + " ua=" + r.UserAgent() + callbackContext(r)
	q := r.URL.Query()
	arrived := arrival(q.Get("layer"), q.Get("session"))
	urlM, urlHit := h.Signer.Match(r.Host + " " + r.URL.Path + "?" + r.URL.RawQuery)
	if urlHit {
		if err := h.Recorder.Hit(WithContext(r.Context(), arrived), urlM, "http", ip, detail); err != nil {
			h.Log.Error("record http hit", "err", err)
		}
	}
	// A stolen honey API key arrives in a credential header, usually sent to the honey base
	// URL. Record it as its own hit so the alert says which value was used. Only the fact
	// that a token arrived in a header is stored, never the header itself.
	creds := r.Header.Get("Authorization") + " " + r.Header.Get("X-Api-Key") + " " + r.Header.Get("Api-Key")
	if m, ok := h.Signer.Match(creds); ok && (!urlHit || m.ID != urlM.ID) {
		used := arrived
		used.Via = "use"
		if err := h.Recorder.Hit(WithContext(r.Context(), used), m, "http", ip, detail+" via=credential-header"); err != nil {
			h.Log.Error("record http hit", "err", err)
		}
	}
	// Same bland answer for hits, misses and forgeries: the toucher learns nothing.
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

// contextKeys are the query parameters a Snare component may attach to its own callbacks
// (docs/M6-gateway.md §4): which layer fired, which tool, which agent session. Nothing
// else from the query is stored.
var contextKeys = []string{"layer", "tool", "session"}

// callbackContext renders the allowlisted query parameters as " key=value" pairs, first
// value only, and only values of 1-64 characters from [A-Za-z0-9._-].
func callbackContext(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	q := r.URL.Query()
	var b strings.Builder
	for _, k := range contextKeys {
		if v := q.Get(k); contextValue(v) {
			b.WriteString(" " + k + "=" + v)
		}
	}
	return b.String()
}

func contextValue(v string) bool {
	if len(v) == 0 || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
