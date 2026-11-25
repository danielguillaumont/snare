// Package alert turns tripwire hits into stored events and delivered alerts.
//
// Flow: listener -> Pipeline.Hit -> store event -> dedup -> Dispatcher queue -> sinks.
// Hit never blocks on delivery: a slow or dead webhook can't slow the listeners down.
package alert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// Alert follows the shape of OCSF Detection Finding (class_uid 2004) so SIEMs can ingest
// it without reshaping. Snare-specific fields live under Unmapped.
type Alert struct {
	ClassUID    int         `json:"class_uid"`
	ClassName   string      `json:"class_name"`
	CategoryUID int         `json:"category_uid"`
	ActivityID  int         `json:"activity_id"`
	SeverityID  int         `json:"severity_id"`
	Severity    string      `json:"severity"`
	Time        int64       `json:"time"` // epoch ms
	Message     string      `json:"message"`
	FindingInfo FindingInfo `json:"finding_info"`
	SrcEndpoint Endpoint    `json:"src_endpoint"`
	Metadata    Metadata    `json:"metadata"`
	Unmapped    Unmapped    `json:"unmapped"`
}

type FindingInfo struct {
	UID           string   `json:"uid"`
	Title         string   `json:"title"`
	Types         []string `json:"types"`
	FirstSeenTime int64    `json:"first_seen_time"`
}

type Endpoint struct {
	IP string `json:"ip"`
}

type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
}

type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type Unmapped struct {
	TokenID string `json:"token_id"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Memo    string `json:"memo,omitempty"`
	Channel string `json:"channel"`
	Detail  string `json:"detail"`
	EventID int64  `json:"event_id"`
}

// New builds an alert for one event on one token.
func New(tok store.Token, ev store.Event) Alert {
	ms := ev.At.UnixMilli()
	return Alert{
		ClassUID:    2004,
		ClassName:   "Detection Finding",
		CategoryUID: 2,
		ActivityID:  1, // Create
		SeverityID:  4, // High: legitimate work never touches a tripwire
		Severity:    "High",
		Time:        ms,
		Message:     fmt.Sprintf("Snare tripwire touched via %s: %s", ev.Channel, tok.Label),
		FindingInfo: FindingInfo{
			UID:           fmt.Sprintf("snare-%s-%d", tok.ID, ev.ID),
			Title:         "Tripwire touched: " + tok.Label,
			Types:         []string{"tripwire/" + tok.Kind},
			FirstSeenTime: ms,
		},
		SrcEndpoint: Endpoint{IP: ev.SourceIP},
		Metadata:    Metadata{Version: "1.3.0", Product: Product{Name: "Snare", VendorName: "Snare"}},
		Unmapped: Unmapped{
			TokenID: tok.ID, Kind: tok.Kind, Label: tok.Label, Memo: tok.Memo,
			Channel: ev.Channel, Detail: ev.Detail, EventID: ev.ID,
		},
	}
}

// Sink delivers alerts somewhere.
type Sink interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Dedup suppresses repeat alerts for the same token, channel and source within a window.
// DNS resolvers retry and fan out, so one touch can produce many queries.
type Dedup struct {
	window time.Duration
	mu     sync.Mutex
	last   map[string]time.Time
}

func NewDedup(window time.Duration) *Dedup {
	return &Dedup{window: window, last: map[string]time.Time{}}
}

// Allow reports whether an alert for key at time now should be sent.
func (d *Dedup) Allow(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[key]; ok && now.Sub(t) < d.window {
		return false
	}
	d.last[key] = now
	if len(d.last) > 10_000 { // bound memory under a flood
		for k, t := range d.last {
			if now.Sub(t) >= d.window {
				delete(d.last, k)
			}
		}
	}
	return true
}

// Dispatcher delivers alerts to sinks from a bounded queue with retries.
type Dispatcher struct {
	sinks    []Sink
	queue    chan Alert
	attempts int
	backoff  time.Duration
	log      *slog.Logger
	wg       sync.WaitGroup
}

type DispatcherOpts struct {
	QueueSize int
	Workers   int
	Attempts  int
	Backoff   time.Duration // first retry delay; doubles each attempt
}

func NewDispatcher(log *slog.Logger, opts DispatcherOpts, sinks ...Sink) *Dispatcher {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 1024
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.Attempts <= 0 {
		opts.Attempts = 3
	}
	if opts.Backoff <= 0 {
		opts.Backoff = 250 * time.Millisecond
	}
	d := &Dispatcher{sinks: sinks, queue: make(chan Alert, opts.QueueSize), attempts: opts.Attempts, backoff: opts.Backoff, log: log}
	for i := 0; i < opts.Workers; i++ {
		d.wg.Add(1)
		go d.work()
	}
	return d
}

// Enqueue never blocks. It returns false if the queue is full (the event is still stored).
func (d *Dispatcher) Enqueue(a Alert) bool {
	select {
	case d.queue <- a:
		return true
	default:
		d.log.Warn("alert queue full; alert dropped (event stored)", "finding", a.FindingInfo.UID)
		return false
	}
}

// Close stops accepting alerts and waits for queued ones to be delivered or fail.
func (d *Dispatcher) Close() {
	close(d.queue)
	d.wg.Wait()
}

func (d *Dispatcher) work() {
	defer d.wg.Done()
	for a := range d.queue {
		for _, s := range d.sinks {
			d.deliver(s, a)
		}
	}
}

func (d *Dispatcher) deliver(s Sink, a Alert) {
	delay := d.backoff
	var err error
	for i := 1; i <= d.attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = s.Send(ctx, a)
		cancel()
		if err == nil {
			return
		}
		if i < d.attempts {
			time.Sleep(delay)
			delay *= 2
		}
	}
	d.log.Error("alert delivery failed", "sink", s.Name(), "finding", a.FindingInfo.UID, "err", err)
}

// Pipeline records hits and dispatches alerts.
type Pipeline struct {
	Store      *store.Store
	Dispatcher *Dispatcher
	Dedup      *Dedup
	Log        *slog.Logger
	Now        func() time.Time
}

// Hit is called by listeners after a token's signature has been verified.
func (p *Pipeline) Hit(ctx context.Context, tokenID, channel, sourceIP, detail string) error {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	ev := store.Event{TokenID: tokenID, Channel: channel, SourceIP: sourceIP, Detail: truncate(detail, 512), At: now().UTC()}
	id, err := p.Store.AddEvent(ctx, ev)
	if err != nil {
		return fmt.Errorf("record event: %w", err)
	}
	ev.ID = id

	tok, err := p.Store.GetToken(ctx, tokenID)
	if errors.Is(err, store.ErrNotFound) {
		// Valid signature means we minted it; the record may be from another instance or deleted.
		tok = store.Token{ID: tokenID, Kind: "unknown", Label: "(unregistered token)"}
	} else if err != nil {
		return fmt.Errorf("load token: %w", err)
	}

	if !p.Dedup.Allow(tokenID+"|"+channel+"|"+sourceIP, ev.At) {
		return nil
	}
	p.Dispatcher.Enqueue(New(tok, ev))
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
