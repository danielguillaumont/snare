// Package alert turns tripwire hits into stored events and delivered alerts.
//
// Flow: listener -> Pipeline.Hit -> dedup -> store event + outbox marker (one transaction) ->
// Outbox worker -> sinks. Hit never blocks on delivery: a slow or dead webhook can't slow the
// listeners down, and a restart or a SIEM outage can't lose an alert (docs/M4c-reliability.md).
package alert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// Alert is an OCSF 1.3 Detection Finding (class_uid 2004), so SIEMs can ingest it without
// reshaping. ocsf_test.go checks every required attribute and enumeration we emit. Snare's own
// fields live under Unmapped.
type Alert struct {
	ActivityID   int          `json:"activity_id"`
	ActivityName string       `json:"activity_name"`
	CategoryUID  int          `json:"category_uid"`
	CategoryName string       `json:"category_name"`
	ClassUID     int          `json:"class_uid"`
	ClassName    string       `json:"class_name"`
	TypeUID      int          `json:"type_uid"`
	TypeName     string       `json:"type_name"`
	SeverityID   int          `json:"severity_id"`
	Severity     string       `json:"severity"`
	StatusID     int          `json:"status_id"`
	Status       string       `json:"status"`
	Time         int64        `json:"time"` // epoch ms
	Message      string       `json:"message"`
	FindingInfo  FindingInfo  `json:"finding_info"`
	SrcEndpoint  Endpoint     `json:"src_endpoint"`
	Observables  []Observable `json:"observables"`
	Metadata     Metadata     `json:"metadata"`
	Unmapped     Unmapped     `json:"unmapped"`
}

type FindingInfo struct {
	UID           string   `json:"uid"`
	Title         string   `json:"title"`
	Desc          string   `json:"desc,omitempty"`
	Types         []string `json:"types"`
	FirstSeenTime int64    `json:"first_seen_time"`
	Analytic      Analytic `json:"analytic"`
}

// Analytic names the detection logic: a deterministic rule ("this token was used").
type Analytic struct {
	Name   string `json:"name"`
	TypeID int    `json:"type_id"` // 1 = Rule
	Type   string `json:"type"`
}

type Endpoint struct {
	IP string `json:"ip"`
}

type Observable struct {
	Name   string `json:"name"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

type Metadata struct {
	Version   string  `json:"version"` // OCSF schema version
	Product   Product `json:"product"`
	TenantUID string  `json:"tenant_uid,omitempty"`
	UID       string  `json:"uid"`
}

type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
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

// ProductVersion is reported in metadata.product.version.
var ProductVersion = "0.5.0"

// New builds an alert for one event on one token.
func New(tok store.Token, ev store.Event) Alert {
	ms := ev.At.UnixMilli()
	uid := fmt.Sprintf("snare-%s-%d", tok.ID, ev.ID)
	return Alert{
		ActivityID: 1, ActivityName: "Create",
		CategoryUID: 2, CategoryName: "Findings",
		ClassUID: 2004, ClassName: "Detection Finding",
		TypeUID: 200401, TypeName: "Detection Finding: Create",
		SeverityID: 4, Severity: "High", // legitimate work never touches a tripwire
		StatusID: 1, Status: "New",
		Time:    ms,
		Message: fmt.Sprintf("Snare tripwire touched via %s: %s", ev.Channel, tok.Label),
		FindingInfo: FindingInfo{
			UID:   uid,
			Title: "Tripwire touched: " + tok.Label,
			Desc: "A planted Snare tripwire was used. No legitimate workflow uses it, so treat the " +
				"source as compromised or misdirected until shown otherwise.",
			Types:         []string{"tripwire/" + tok.Kind},
			FirstSeenTime: ms,
			Analytic:      Analytic{Name: "snare-tripwire-" + tok.Kind, TypeID: 1, Type: "Rule"},
		},
		SrcEndpoint: Endpoint{IP: ev.SourceIP},
		Observables: []Observable{
			{Name: "src_endpoint.ip", TypeID: 2, Type: "IP Address", Value: ev.SourceIP},
			{Name: "unmapped.token_id", TypeID: 99, Type: "Other", Value: tok.ID},
		},
		Metadata: Metadata{
			Version:   "1.3.0",
			Product:   Product{Name: "Snare", VendorName: "Snare", Version: ProductVersion},
			TenantUID: ev.TenantID,
			UID:       uid,
		},
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
