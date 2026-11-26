package server

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/store"
)

// maxRetentionDays bounds SNARE_EVENT_RETENTION so the cutoff arithmetic can't overflow.
const maxRetentionDays = 36500

// retentionFromEnv parses SNARE_EVENT_RETENTION: whole days, "" or "0" for forever.
func retentionFromEnv(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	days, err := strconv.Atoi(v)
	if err != nil || days < 0 || days > maxRetentionDays {
		return 0, fmt.Errorf("SNARE_EVENT_RETENTION must be a whole number of days from 0 (keep forever) to %d, got %q", maxRetentionDays, v)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// retention runs the hourly event purge (docs/M4f-distribution.md §2).
type retention struct {
	st     *store.Store
	period time.Duration
	every  time.Duration
	log    *slog.Logger
	purged *metrics.Counter

	stop chan struct{}
	wg   sync.WaitGroup
}

func newRetention(st *store.Store, period time.Duration, reg *metrics.Registry, log *slog.Logger) *retention {
	r := &retention{st: st, period: period, every: time.Hour, log: log, stop: make(chan struct{})}
	r.purged = reg.Counter("snare_events_purged_total", "Closed or muted events deleted by SNARE_EVENT_RETENTION.")
	reg.GaugeFunc("snare_events_open_expired",
		"Open events older than the retention period. Retention never deletes them; triage does.",
		func() float64 {
			if period <= 0 {
				return 0
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			n, _ := st.OpenExpired(ctx, time.Now().Add(-period))
			return float64(n)
		})
	return r
}

func (r *retention) start() {
	if r.period <= 0 {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.every)
		defer t.Stop()
		for {
			r.run(time.Now())
			select {
			case <-r.stop:
				return
			case <-t.C:
			}
		}
	}()
}

func (r *retention) run(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, err := r.st.PurgeEvents(ctx, now.Add(-r.period))
	if n > 0 {
		r.purged.Add(float64(n))
		r.log.Info("event retention purged events", "events", n, "retention_days", int(r.period/(24*time.Hour)))
	}
	if err != nil {
		r.log.Error("event retention", "err", err)
	}
}

func (r *retention) close() {
	close(r.stop)
	r.wg.Wait()
}
