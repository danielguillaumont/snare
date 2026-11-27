package alert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/listener"
	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

// Target is one destination. Ref is stable across restarts: "op:<name>" for operator sinks,
// the sink id for a tenant's own.
type Target struct {
	Ref  string
	Sink Sink
}

// Resolver returns a tenant's own sinks.
type Resolver interface {
	Sinks(ctx context.Context, tenantID string) []Target
}

// Metrics are the alert pipeline's counters. Any field may be nil.
type Metrics struct {
	Hits       *metrics.Counter // channel
	Suppressed *metrics.Counter
	Shed       *metrics.Counter
	Muted      *metrics.Counter
	Heartbeats *metrics.Counter // channel (M11)
	Warnings   *metrics.Counter // M16
	Deliveries *metrics.Counter // sink, result
	Latency    *metrics.Histogram
}

// NewMetrics registers the pipeline's metrics, including outbox gauges read at scrape time.
func NewMetrics(r *metrics.Registry, st *store.Store) *Metrics {
	m := &Metrics{
		Hits:       r.Counter("snare_hits_total", "Verified tripwire hits, before dedup.", "channel"),
		Suppressed: r.Counter("snare_alerts_suppressed_total", "Hits stored without an alert because an identical one was sent within the dedup window."),
		Shed:       r.Counter("snare_alerts_shed_total", "Hits stored without an alert because the delivery outbox was full."),
		Muted:      r.Counter("snare_hits_muted_total", "Hits on disabled tripwires: stored, never alerted."),
		Heartbeats: r.Counter("snare_heartbeats_total", "Heartbeat touches received (docs/M11-heartbeat.md), by listener channel. Never alerted.", "channel"),
		Warnings:   r.Counter("snare_warnings_total", "Exposure warnings (docs/M16-early-warning.md): a honey value reached an agent. Stored, never alerted on their own."),
		Deliveries: r.Counter("snare_deliveries_total", "Delivery attempts by sink type and result (ok, retry, dead).", "sink", "result"),
		Latency: r.Histogram("snare_delivery_latency_seconds", "Time from touch to successful delivery.",
			[]float64{0.05, 0.25, 1, 5, 30, 120, 600, 3600, 14400}),
	}
	ob := st.Outbox()
	stats := func() store.OutboxStats {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, _ := ob.Stats(ctx, time.Now())
		return s
	}
	r.GaugeFunc("snare_deliveries_pending", "Deliveries waiting for a first attempt or a retry.", func() float64 { return float64(stats().Pending) })
	r.GaugeFunc("snare_deliveries_dead", "Deliveries that exhausted their retries. Each is an alert nobody received.", func() float64 { return float64(stats().Dead) })
	r.GaugeFunc("snare_oldest_pending_delivery_seconds", "Age of the oldest pending delivery.", func() float64 { return stats().OldestPending.Seconds() })
	return m
}

// Outbox delivers queued alerts. Each (event, destination) row has its own retry schedule,
// and at most PerSink attempts to one destination run at once, so a dead SIEM can hold only
// a few workers and delays nobody else. Delivery is at least once; receivers dedupe on
// finding_info.uid.
type Outbox struct {
	Store    *store.Store
	Operator []Target // every alert goes to these
	Resolver Resolver // optional: per-tenant sinks
	Log      *slog.Logger
	Metrics  *Metrics

	Workers     int           // default 8
	PerSink     int           // default 2
	MaxAttempts int           // default 20
	Backoff     time.Duration // first retry delay, default 2s; doubles each attempt
	MaxBackoff  time.Duration // default 15m
	Timeout     time.Duration // per attempt, default 10s
	Poll        time.Duration // idle rescan, default 1s
	Retention   time.Duration // delivered rows, default 7 days
	Correlation time.Duration // window for multi-tripwire correlation, default 1h
	NoJitter    bool          // tests
	Now         func() time.Time

	once     sync.Once
	started  bool
	ob       *store.Outbox
	wake     chan struct{}
	stop     chan struct{}
	loopDone chan struct{}
	sem      chan struct{}
	wg       sync.WaitGroup

	mu       sync.Mutex
	inflight map[int64]bool
	perSink  map[string]int
	idle     *sync.Cond
}

func (o *Outbox) init() {
	o.once.Do(func() {
		def := func(d *time.Duration, v time.Duration) {
			if *d <= 0 {
				*d = v
			}
		}
		if o.Workers <= 0 {
			o.Workers = 8
		}
		if o.PerSink <= 0 {
			o.PerSink = 2
		}
		if o.MaxAttempts <= 0 {
			o.MaxAttempts = 20
		}
		def(&o.Backoff, 2*time.Second)
		def(&o.MaxBackoff, 15*time.Minute)
		def(&o.Timeout, 10*time.Second)
		def(&o.Poll, time.Second)
		def(&o.Retention, 7*24*time.Hour)
		def(&o.Correlation, DefaultCorrelationWindow)
		if o.Now == nil {
			o.Now = time.Now
		}
		if o.Log == nil {
			o.Log = slog.Default()
		}
		if o.Metrics == nil {
			o.Metrics = &Metrics{}
		}
		o.ob = o.Store.Outbox()
		o.wake = make(chan struct{}, 1)
		o.stop = make(chan struct{})
		o.loopDone = make(chan struct{})
		o.sem = make(chan struct{}, o.Workers)
		o.inflight = map[int64]bool{}
		o.perSink = map[string]int{}
		o.idle = sync.NewCond(&o.mu)
	})
}

// Start runs the delivery loop until Close.
func (o *Outbox) Start() {
	o.init()
	o.mu.Lock()
	if o.started {
		o.mu.Unlock()
		return
	}
	o.started = true
	o.mu.Unlock()
	go o.loop()
}

// Notify wakes the loop now instead of at the next poll. It never blocks.
func (o *Outbox) Notify() {
	o.init()
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// Close stops the loop and waits for attempts in flight. Pending rows stay in the store and
// are picked up on the next start.
func (o *Outbox) Close() {
	o.init()
	select {
	case <-o.stop:
		return
	default:
	}
	close(o.stop)
	o.mu.Lock()
	started := o.started
	o.mu.Unlock()
	if started {
		<-o.loopDone
	}
	o.wg.Wait()
}

func (o *Outbox) loop() {
	defer close(o.loopDone)
	t := time.NewTicker(o.Poll)
	defer t.Stop()
	lastPurge := time.Time{}
	for {
		if _, err := o.pass(context.Background()); err != nil {
			o.Log.Error("outbox pass", "err", err)
		}
		if now := o.Now(); now.Sub(lastPurge) > time.Hour {
			lastPurge = now
			if n, err := o.ob.Purge(context.Background(), now.Add(-o.Retention)); err != nil {
				o.Log.Error("outbox purge", "err", err)
			} else if n > 0 {
				o.Log.Info("outbox purged delivered rows", "rows", n)
			}
		}
		select {
		case <-o.stop:
			return
		case <-o.wake:
		case <-t.C:
		}
	}
}

// pass expands due markers and starts every due delivery a worker is free for. It returns
// how many attempts it started; it does not wait for them.
func (o *Outbox) pass(ctx context.Context) (int, error) {
	now := o.Now()
	due, err := o.ob.Due(ctx, now, 500)
	if err != nil {
		return 0, err
	}
	expanded := false
	for _, d := range due {
		if !d.IsMarker() {
			break // markers come first
		}
		refs := make([]string, 0, len(o.Operator)+2)
		for _, t := range o.Operator {
			refs = append(refs, t.Ref)
		}
		if o.Resolver != nil && d.TenantID != "" {
			for _, t := range o.Resolver.Sinks(ctx, d.TenantID) {
				refs = append(refs, t.Ref)
			}
		}
		if err := o.ob.Expand(ctx, d, refs, now); err != nil {
			return 0, fmt.Errorf("expand delivery %d: %w", d.ID, err)
		}
		expanded = true
	}
	if expanded {
		if due, err = o.ob.Due(ctx, now, 500); err != nil {
			return 0, err
		}
	}
	started := 0
	for _, d := range due {
		if d.IsMarker() {
			continue
		}
		o.mu.Lock()
		busy := o.inflight[d.ID] || o.perSink[d.SinkRef] >= o.PerSink
		o.mu.Unlock()
		if busy {
			continue
		}
		select {
		case o.sem <- struct{}{}:
		default:
			return started, nil // every worker is busy
		}
		o.mu.Lock()
		o.inflight[d.ID] = true
		o.perSink[d.SinkRef]++
		o.mu.Unlock()
		o.wg.Add(1)
		started++
		go func(d store.Delivery) {
			defer func() {
				<-o.sem
				o.mu.Lock()
				delete(o.inflight, d.ID)
				o.perSink[d.SinkRef]--
				if o.perSink[d.SinkRef] == 0 {
					delete(o.perSink, d.SinkRef)
				}
				o.idle.Broadcast()
				o.mu.Unlock()
				o.wg.Done()
				o.Notify() // a freed worker or sink slot may unblock other due rows
			}()
			o.attempt(d)
		}(d)
	}
	return started, nil
}

func (o *Outbox) target(ctx context.Context, d store.Delivery) (Target, bool) {
	for _, t := range o.Operator {
		if t.Ref == d.SinkRef {
			return t, true
		}
	}
	if o.Resolver != nil && d.TenantID != "" {
		for _, t := range o.Resolver.Sinks(ctx, d.TenantID) {
			if t.Ref == d.SinkRef {
				return t, true
			}
		}
	}
	return Target{}, false
}

func (o *Outbox) attempt(d store.Delivery) {
	ctx := context.Background()
	n := d.Attempts + 1
	fail := func(sinkType string, err error, permanent bool) {
		now := o.Now()
		dead := permanent || n >= o.MaxAttempts
		next := now.Add(o.delay(n))
		result := "retry"
		if dead {
			result = "dead"
			o.Log.Error("alert delivery dead; it will not be retried automatically", "delivery", d.ID, "sink", d.SinkRef,
				"tenant", d.TenantID, "event", d.EventID, "attempts", n, "err", err)
		} else {
			o.Log.Warn("alert delivery failed; will retry", "delivery", d.ID, "sink", d.SinkRef, "attempt", n,
				"next_in", next.Sub(now).Round(time.Millisecond), "err", err)
		}
		o.Metrics.Deliveries.Inc(sinkType, result)
		if err := o.ob.MarkFailed(ctx, d.ID, n, next, err.Error(), dead, now); err != nil {
			o.Log.Error("outbox mark failed", "delivery", d.ID, "err", err)
		}
	}

	t, ok := o.target(ctx, d)
	if !ok {
		fail("unknown", errors.New("sink no longer configured (removed, or its config no longer opens)"), true)
		return
	}
	tok, ev, found, err := o.ob.AlertData(ctx, d.EventID)
	if errors.Is(err, store.ErrNotFound) {
		fail(t.Sink.Name(), errors.New("event no longer exists"), true)
		return
	}
	if err != nil {
		fail(t.Sink.Name(), fmt.Errorf("load event: %w", err), false)
		return
	}
	if !found {
		// Valid signature means we minted it; the record may be from another instance or
		// deleted. No tenant owns it, so it reaches operator sinks only.
		tok = store.Token{ID: ev.TokenID, Kind: "unknown", Label: "(unregistered token)"}
	}
	a, err := Build(ctx, o.Store, tok, ev, o.Correlation)
	if err != nil {
		fail(t.Sink.Name(), err, false)
		return
	}
	actx, cancel := context.WithTimeout(ctx, o.Timeout)
	err = t.Sink.Send(actx, a)
	cancel()
	if err != nil {
		fail(t.Sink.Name(), err, false)
		return
	}
	now := o.Now()
	o.Metrics.Deliveries.Inc(t.Sink.Name(), "ok")
	o.Metrics.Latency.Observe(now.Sub(ev.At).Seconds())
	if err := o.ob.MarkDelivered(ctx, d.ID, n, now); err != nil {
		o.Log.Error("outbox mark delivered", "delivery", d.ID, "err", err)
	}
}

// DefaultCorrelationWindow is how far back Build looks for other tripwires touched by the
// same source.
const DefaultCorrelationWindow = time.Hour

// Build makes the alert for one stored event, correlated with the source's earlier touches.
// Live delivery and export both use it, so a backfilled finding matches the one delivered.
func Build(ctx context.Context, st *store.Store, tok store.Token, ev store.Event, window time.Duration) (Alert, error) {
	a := New(tok, ev)
	c, err := st.Outbox().Related(ctx, ev, window, 10)
	if err != nil {
		return Alert{}, fmt.Errorf("correlate: %w", err)
	}
	a.Correlate(c, ev.Stage, window)
	return a, nil
}

// delay is the wait after failed attempt n: Backoff·2^(n-1), capped, with ±20% jitter.
func (o *Outbox) delay(n int) time.Duration {
	d := o.Backoff
	for i := 1; i < n && d < o.MaxBackoff; i++ {
		d *= 2
	}
	if d > o.MaxBackoff {
		d = o.MaxBackoff
	}
	if !o.NoJitter {
		d = time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
	}
	return d
}

// Drain processes the outbox until nothing is in flight and no pending row is due within
// horizon, or ctx ends. Rows scheduled further out are left alone. Used by tests and by tools
// that run the pipeline synchronously.
func (o *Outbox) Drain(ctx context.Context, horizon time.Duration) error {
	o.init()
	for {
		if _, err := o.pass(ctx); err != nil {
			return err
		}
		o.mu.Lock()
		for len(o.inflight) > 0 {
			o.idle.Wait()
		}
		o.mu.Unlock()
		due, err := o.ob.Due(ctx, o.Now().Add(horizon), 1)
		if err != nil {
			return err
		}
		if len(due) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// Pipeline records hits and queues alerts.
type Pipeline struct {
	Store   *store.Store
	Outbox  *Outbox
	Dedup   *Dedup
	Log     *slog.Logger
	Metrics *Metrics
	Now     func() time.Time
}

// Hit is called by listeners after a token's signature has been verified. Every hit is
// stored; an alert is queued unless an identical one went out within the dedup window.
func (p *Pipeline) Hit(ctx context.Context, tm token.Match, channel, sourceIP, detail string) error {
	tokenID := tm.ID
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	m := p.Metrics
	if m == nil {
		m = &Metrics{}
	}
	at := now().UTC()
	// Token ids are globally unique, so the key needs no tenant.
	alert := p.Dedup.Allow(tokenID+"|"+channel+"|"+sourceIP, at)
	lc := listener.ContextFrom(ctx)
	var inputs []store.Input
	for _, in := range lc.Inputs {
		inputs = append(inputs, store.Input{Tool: in.Tool, Fingerprint: in.Fingerprint, Length: in.Length,
			AgeSeconds: in.AgeSeconds, Source: in.Source})
	}
	tok, ev, _, queued, err := p.Store.RecordHit(ctx, store.Event{
		TokenID: tokenID, Channel: channel, SourceIP: sourceIP, Detail: truncate(detail, 512), At: at,
		PreviousKey: tm.PreviousKey, Via: lc.Via, Session: lc.Session, Containment: lc.Containment, Inputs: inputs,
	}, alert)
	if err != nil {
		return fmt.Errorf("record event: %w", err)
	}
	if tok.Kind == store.KindHeartbeat { // recorded as a heartbeat, never an alert (M11)
		m.Heartbeats.Inc(channel)
		return nil
	}
	m.Hits.Inc(channel)
	switch {
	case ev.Warning:
		m.Warnings.Inc()
	case ev.Muted:
		m.Muted.Inc()
	case !alert:
		m.Suppressed.Inc()
	case !queued:
		m.Shed.Inc()
		p.Log.Error("delivery outbox full; event stored but no alert queued", "token", tokenID, "channel", channel)
	default:
		if p.Outbox != nil {
			p.Outbox.Notify()
		}
	}
	return nil
}
