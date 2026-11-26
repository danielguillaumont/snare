package alert

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/store"
)

// fastOutbox is an outbox with test-speed retries. Sink i gets ref "op:<name><i>".
func fastOutbox(st *store.Store, sinks ...Sink) *Outbox {
	var ts []Target
	for i, s := range sinks {
		ts = append(ts, Target{Ref: fmt.Sprintf("op:%s%d", s.Name(), i), Sink: s})
	}
	return &Outbox{Store: st, Operator: ts, Log: quiet, Backoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond,
		Timeout: time.Second, NoJitter: true}
}

func drain(t *testing.T, o *Outbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := o.Drain(ctx, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func memStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestPipelineStoresEveryEventButDedupsAlerts(t *testing.T) {
	ctx := context.Background()
	st := memStore(t)
	_ = st.Tenant(store.DefaultTenant).CreateToken(ctx, store.Token{ID: "tid", Kind: "honey_credential", Label: "repo .env in payments-api"})
	sink := &memSink{}
	ob := fastOutbox(st, sink)
	m := NewMetrics(metrics.New(), st)
	ob.Metrics = m
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet, Metrics: m}

	for i := 0; i < 5; i++ { // resolver retry storm
		if err := p.Hit(ctx, "tid", "dns", "198.51.100.4", "tid.cb.example. A"); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.Hit(ctx, "tid", "http", "198.51.100.4", "GET /t/x")
	drain(t, ob)

	evs, _ := st.Tenant(store.DefaultTenant).ListEvents(ctx, "tid", 100)
	if len(evs) != 6 {
		t.Fatalf("stored %d events, want 6", len(evs))
	}
	got := sink.alerts()
	if len(got) != 2 {
		t.Fatalf("sent %d alerts, want 2 (one per channel)", len(got))
	}
	a := got[0]
	if a.ClassUID != 2004 || a.Unmapped.Label != "repo .env in payments-api" || a.SrcEndpoint.IP != "198.51.100.4" {
		t.Fatalf("alert content: %+v", a)
	}
	if m.Hits.Value("dns") != 5 || m.Hits.Value("http") != 1 || m.Suppressed.Value() != 4 || m.Deliveries.Value("mem", "ok") != 2 {
		t.Fatalf("metrics: dns=%v http=%v suppressed=%v ok=%v",
			m.Hits.Value("dns"), m.Hits.Value("http"), m.Suppressed.Value(), m.Deliveries.Value("mem", "ok"))
	}
}

func TestUnregisteredTokenStillAlerts(t *testing.T) {
	st := memStore(t)
	sink := &memSink{}
	ob := fastOutbox(st, sink)
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	_ = p.Hit(context.Background(), "ghost", "http", "192.0.2.1", "")
	drain(t, ob)
	if got := sink.alerts(); len(got) != 1 || got[0].Unmapped.Kind != "unknown" {
		t.Fatalf("got %+v", got)
	}
}

// The old in-memory dispatcher gave up after 3 attempts (under a second). A sink that is
// down for longer must still get the alert once it recovers.
func TestOutboxRetriesUntilSinkRecovers(t *testing.T) {
	st := memStore(t)
	sink := &memSink{fail: 7}
	ob := fastOutbox(st, sink)
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	_ = p.Hit(context.Background(), "x", "http", "192.0.2.1", "")
	drain(t, ob)
	if len(sink.alerts()) != 1 {
		t.Fatalf("not delivered after recovery (%d attempts)", atomic.LoadInt32(&sink.n))
	}
	ds, _ := st.Operator().ListDeliveries(context.Background(), "", 10)
	if len(ds) != 1 || ds[0].State != store.DeliveryDelivered || ds[0].Attempts != 8 {
		t.Fatalf("delivery row %+v", ds)
	}
}

func TestOutboxDeadAfterMaxAttemptsThenManualRetry(t *testing.T) {
	ctx := context.Background()
	st := memStore(t)
	sink := &memSink{fail: 3}
	ob := fastOutbox(st, sink)
	ob.MaxAttempts = 3
	reg := metrics.New()
	ob.Metrics = NewMetrics(reg, st)
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	_ = p.Hit(ctx, "x", "http", "192.0.2.1", "")
	drain(t, ob)
	dead, _ := st.Operator().ListDeliveries(ctx, store.DeliveryDead, 10)
	if len(dead) != 1 || dead[0].Attempts != 3 || dead[0].LastError != "transient" || len(sink.alerts()) != 0 {
		t.Fatalf("want one dead row after 3 attempts: %+v", dead)
	}
	if ob.Metrics.Deliveries.Value("mem", "retry") != 2 || ob.Metrics.Deliveries.Value("mem", "dead") != 1 {
		t.Fatal("retry/dead counters")
	}
	var b strings.Builder
	reg.Write(&b)
	if !strings.Contains(b.String(), "snare_deliveries_dead 1\n") {
		t.Fatalf("dead gauge:\n%s", b.String())
	}
	if err := st.Operator().RetryDelivery(ctx, dead[0].ID); err != nil {
		t.Fatal(err)
	}
	drain(t, ob)
	if len(sink.alerts()) != 1 {
		t.Fatal("manual retry did not deliver")
	}
}

// Alerts queued before a restart are delivered after it.
func TestOutboxSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "snare.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Tenant(store.DefaultTenant).CreateToken(ctx, store.Token{ID: "t1", Kind: "canary_url", Label: "wiki link"})
	down := sinkFunc(func(context.Context, Alert) error { return errors.New("connection refused") })
	ob := fastOutbox(st, down)
	ob.Backoff, ob.MaxBackoff = time.Hour, time.Hour // the first failure pushes the retry far out
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	_ = p.Hit(ctx, "t1", "http", "192.0.2.1", "GET")
	drain(t, ob)
	ob.Close()
	st.Close()

	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	up := &memSink{}
	ob2 := &Outbox{Store: st2, Operator: []Target{{Ref: "op:func0", Sink: up}}, Log: quiet,
		Now: func() time.Time { return time.Now().Add(2 * time.Hour) }}
	ob2.Start()
	defer ob2.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(up.alerts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := up.alerts(); len(got) != 1 || got[0].Unmapped.Label != "wiki link" {
		t.Fatalf("after restart: %+v", got)
	}
}

// A sink that hangs holds at most PerSink workers; alerts to another destination keep
// flowing.
func TestDeadSinkDoesNotDelayOthers(t *testing.T) {
	ctx := context.Background()
	st := memStore(t)
	release := make(chan struct{})
	hung := sinkFunc(func(ctx context.Context, _ Alert) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return errors.New("still down")
		}
	})
	fast := &memSink{}
	ob := &Outbox{Store: st, Log: quiet, Workers: 4, PerSink: 2, Timeout: 5 * time.Second, Backoff: time.Hour,
		Operator: []Target{{Ref: "op:hung", Sink: hung}, {Ref: "op:fast", Sink: fast}}}
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	for i := 0; i < 20; i++ {
		_ = p.Hit(ctx, fmt.Sprintf("tok%d", i), "http", "192.0.2.1", "")
	}
	if _, err := ob.pass(ctx); err != nil { // fan out and start what fits
		t.Fatal(err)
	}
	ob.mu.Lock()
	held := ob.perSink["op:hung"]
	ob.mu.Unlock()
	if held != 2 {
		t.Fatalf("hung sink holds %d workers, want the cap of 2", held)
	}

	start := time.Now()
	ob.Start()
	defer func() { close(release); ob.Close() }()
	for len(fast.alerts()) < 20 && time.Since(start) < 3*time.Second {
		time.Sleep(2 * time.Millisecond)
	}
	if n := len(fast.alerts()); n != 20 {
		t.Fatalf("healthy sink got %d of 20 alerts while the other hung", n)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("healthy sink delayed %v", took)
	}
}

func TestHitNeverBlocksOnDelivery(t *testing.T) {
	st := memStore(t)
	block := make(chan struct{})
	slow := sinkFunc(func(context.Context, Alert) error { <-block; return nil })
	ob := fastOutbox(st, slow)
	ob.Workers = 1
	ob.Start()
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			_ = p.Hit(context.Background(), fmt.Sprintf("t%d", i), "http", "192.0.2.1", "")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Hit blocked on a slow sink")
	}
	close(block)
	ob.Close()
}

// A row whose destination is no longer configured fails once, permanently.
func TestRemovedSinkGoesDeadNotRetried(t *testing.T) {
	ctx := context.Background()
	st := memStore(t)
	ob := fastOutbox(st, &memSink{})
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	_ = p.Hit(ctx, "y", "http", "192.0.2.1", "")
	if err := st.Outbox().Expand(ctx, mustMarker(t, st), []string{"op:gone"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	drain(t, ob)
	dead, _ := st.Operator().ListDeliveries(ctx, store.DeliveryDead, 10)
	if len(dead) != 1 || dead[0].SinkRef != "op:gone" || dead[0].Attempts != 1 {
		t.Fatalf("%+v", dead)
	}
}

func mustMarker(t *testing.T, st *store.Store) store.Delivery {
	t.Helper()
	due, _ := st.Outbox().Due(context.Background(), time.Now().Add(time.Minute), 10)
	for _, d := range due {
		if d.IsMarker() {
			return d
		}
	}
	t.Fatal("no marker")
	return store.Delivery{}
}

// The schedule in docs/M4c-reliability.md: 2 s doubling to 15 min, 20 attempts, about 2.8 h
// of retrying in total, ±20% jitter.
func TestBackoffScheduleMatchesDoc(t *testing.T) {
	o := &Outbox{NoJitter: true, Backoff: 2 * time.Second, MaxBackoff: 15 * time.Minute, MaxAttempts: 20}
	if o.delay(1) != 2*time.Second || o.delay(2) != 4*time.Second || o.delay(10) != 15*time.Minute || o.delay(50) != 15*time.Minute {
		t.Fatalf("delays %v %v %v %v", o.delay(1), o.delay(2), o.delay(10), o.delay(50))
	}
	var total time.Duration
	for n := 1; n < o.MaxAttempts; n++ {
		total += o.delay(n)
	}
	if total < 2*time.Hour+40*time.Minute || total > 2*time.Hour+55*time.Minute {
		t.Fatalf("total retry span %v; the doc says about 2.8 h", total)
	}
	o.NoJitter = false
	for i := 0; i < 200; i++ {
		if d := o.delay(3); d < 6400*time.Millisecond || d > 9600*time.Millisecond {
			t.Fatalf("jitter outside ±20%%: %v", d)
		}
	}
}
