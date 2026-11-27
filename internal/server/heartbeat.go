package server

// The server's heartbeat probe (docs/M11-heartbeat.md): it touches its own heartbeat token
// through its public URL and its DNS name, as an attacker's touch would arrive.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

// MinHeartbeat is the shortest SNARE_HEARTBEAT accepted.
const MinHeartbeat = time.Minute

type prober struct {
	url, host string
	client    *http.Client
	resolver  *net.Resolver
	stop      chan struct{}
	wg        sync.WaitGroup
}

// beatPolicy says which channels this server expects to beat, and when they are stale.
func beatPolicy(cfg Config) store.BeatPolicy {
	p := store.BeatPolicy{StaleAfter: cfg.HeartbeatStale}
	if cfg.Heartbeat > 0 {
		if p.StaleAfter == 0 {
			p.StaleAfter = 3 * cfg.Heartbeat
		}
		if cfg.PublicURL != "" {
			p.Expected = append(p.Expected, store.BeatHTTP)
		}
		if cfg.Zone != "" && cfg.DNSAddr != "" {
			p.Expected = append(p.Expected, store.BeatDNS)
		}
	}
	return p
}

// registerBeatMetrics exposes, per channel, the age of the newest heartbeat across tenants
// and whether it is stale (never seen counts as stale for an expected channel).
func registerBeatMetrics(reg *metrics.Registry, st *store.Store, p store.BeatPolicy, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	status := func() []store.BeatState {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		latest, _ := st.LatestHeartbeats(ctx)
		var hs []store.Heartbeat
		for ch, at := range latest {
			hs = append(hs, store.Heartbeat{Channel: ch, LastAt: at})
		}
		return p.Status(hs, now())
	}
	reg.GaugeVecFunc("snare_heartbeat_age_seconds", "Seconds since the newest heartbeat on the channel, across tenants (docs/M11-heartbeat.md).",
		"channel", func() map[string]float64 {
			out := map[string]float64{}
			for _, b := range status() {
				if b.State != store.BeatNever {
					out[b.Channel] = float64(b.AgeSeconds)
				}
			}
			return out
		})
	reg.GaugeVecFunc("snare_heartbeat_stale", "1 when the channel's newest heartbeat is older than the stale limit, or an expected channel has never beaten.",
		"channel", func() map[string]float64 {
			out := map[string]float64{}
			for _, b := range status() {
				out[b.Channel] = 0
				if b.State != store.BeatOK {
					out[b.Channel] = 1
				}
			}
			return out
		})
}

// startHeartbeat registers the server's derived heartbeat token and probes now and on every
// interval.
func (s *Server) startHeartbeat(signer *token.Signer) error {
	if s.cfg.PublicURL == "" {
		return errors.New("SNARE_HEARTBEAT needs SNARE_PUBLIC_URL: the probe goes through the public URL")
	}
	tok, id := signer.Derive("heartbeat:" + store.DefaultTenant)
	err := s.st.Tenant(store.DefaultTenant).CreateToken(context.Background(),
		store.Token{ID: id, Kind: store.KindHeartbeat, Label: "server heartbeat"})
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return err
	}
	p := &prober{
		url:    strings.TrimRight(s.cfg.PublicURL, "/") + admin.NormalizeURLPath(s.cfg.URLPath) + tok,
		client: &http.Client{Timeout: 10 * time.Second},
		stop:   make(chan struct{}),
	}
	if s.cfg.Zone != "" && s.DNSAddr != "" {
		p.host = tok + "." + strings.TrimSuffix(s.cfg.Zone, ".")
		p.resolver = net.DefaultResolver
		if s.cfg.resolver != nil {
			p.resolver = s.cfg.resolver(s)
		}
	}
	s.probe = p
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(s.cfg.Heartbeat)
		defer t.Stop()
		for {
			s.beat()
			select {
			case <-p.stop:
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// beat runs one probe of each channel. Failures are logged; the stale metric is the alarm.
func (s *Server) beat() {
	p := s.probe
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", p.url, nil)
	req.Header.Set("User-Agent", "snare-heartbeat/1")
	if resp, err := p.client.Do(req); err != nil {
		s.log.Warn("heartbeat: http probe failed", "err", err)
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
	}
	if p.host != "" {
		if _, err := p.resolver.LookupHost(ctx, p.host); err != nil {
			s.log.Warn("heartbeat: dns probe failed", "err", err)
		}
	}
}

func (p *prober) close() {
	close(p.stop)
	p.wg.Wait()
}

// heartbeatFromEnv parses SNARE_HEARTBEAT (empty: off; at least MinHeartbeat) and
// SNARE_HEARTBEAT_STALE (empty: the default; otherwise positive).
func heartbeatFromEnv(every, stale string) (time.Duration, time.Duration, error) {
	var e, st time.Duration
	var err error
	if every != "" {
		if e, err = time.ParseDuration(every); err != nil || e < MinHeartbeat {
			return 0, 0, errors.New("SNARE_HEARTBEAT must be a duration of at least 1m, e.g. 15m")
		}
	}
	if stale != "" {
		if st, err = time.ParseDuration(stale); err != nil || st <= 0 {
			return 0, 0, errors.New("SNARE_HEARTBEAT_STALE must be a positive duration, e.g. 45m")
		}
	}
	return e, st, nil
}
