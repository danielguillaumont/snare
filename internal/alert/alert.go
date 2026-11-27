// Package alert turns tripwire hits into stored events and delivered alerts.
//
// Flow: listener -> Pipeline.Hit -> dedup -> store event + outbox marker (one transaction) ->
// Outbox worker -> sinks. Hit never blocks on delivery: a slow or dead webhook can't slow the
// listeners down, and a restart or a SIEM outage can't lose an alert (docs/M4c-reliability.md).
package alert

import (
	"context"
	"fmt"
	"strconv"
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
	StatusDetail string       `json:"status_detail,omitempty"` // Snare's triage status, or "muted"
	Time         int64        `json:"time"`                    // epoch ms
	Message      string       `json:"message"`
	FindingInfo  FindingInfo  `json:"finding_info"`
	SrcEndpoint  Endpoint     `json:"src_endpoint"`
	Observables  []Observable `json:"observables"`
	Metadata     Metadata     `json:"metadata"`
	Unmapped     Unmapped     `json:"unmapped"`
}

type FindingInfo struct {
	UID           string         `json:"uid"`
	Title         string         `json:"title"`
	Desc          string         `json:"desc,omitempty"`
	Types         []string       `json:"types"`
	FirstSeenTime int64          `json:"first_seen_time"`
	Analytic      Analytic       `json:"analytic"`
	RelatedEvents []RelatedEvent `json:"related_events,omitempty"`
}

// RelatedEvent is OCSF's related_event object: another finding this one is linked to.
type RelatedEvent struct {
	UID           string `json:"uid"`
	TypeUID       int    `json:"type_uid"`
	TypeName      string `json:"type_name"`
	Title         string `json:"title"`
	FirstSeenTime int64  `json:"first_seen_time"`
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
	// Distinct tripwires this source touched in this tenant within CorrelationWindow,
	// including this one (docs/M4c-reliability.md §3). 1 means an isolated touch.
	CorrelatedTripwires int    `json:"correlated_tripwires"`
	CorrelationWindow   string `json:"correlation_window,omitempty"`
	// The token verified under a retired signing key: replant this tripwire before that key
	// is removed from SNARE_KEY_PREVIOUS.
	VerifiedByPreviousKey bool `json:"verified_by_previous_key,omitempty"`
	// Layer and stage of this touch, and its incident (docs/M7-incidents.md). Empty or zero
	// for events recorded before M7.
	Layer      string `json:"layer,omitempty"`
	Stage      string `json:"stage,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	IncidentID int64  `json:"incident_id,omitempty"`
	// Distinct stages and touch count over the correlated touches, as for
	// CorrelatedTripwires. Stages are in kill-chain order.
	CorrelatedStages  []string `json:"correlated_stages,omitempty"`
	CorrelatedTouches int      `json:"correlated_touches,omitempty"`
	// Why the alert is Critical, in words; empty when it is not.
	CriticalBecause string `json:"critical_because,omitempty"`
	// Containment the gateway took (docs/M8-containment.md): "blocked" or "frozen".
	Containment string `json:"containment,omitempty"`
	// What the agent received through the gateway before this touch, oldest first
	// (docs/M9-provenance.md). Fingerprints and lengths, never content.
	Inputs []store.Input `json:"inputs,omitempty"`
	// Warning: an exposure warning (docs/M16-early-warning.md), severity Low, never sent
	// to sinks on its own.
	Warning bool `json:"warning,omitempty"`
}

// ProductVersion is reported in metadata.product.version.
var ProductVersion = "0.9.0"

// New builds an alert for one event on one token.
func New(tok store.Token, ev store.Event) Alert {
	ms := ev.At.UnixMilli()
	uid := findingUID(tok.ID, ev.ID)
	a := Alert{
		ActivityID: 1, ActivityName: "Create",
		CategoryUID: 2, CategoryName: "Findings",
		ClassUID: 2004, ClassName: "Detection Finding",
		TypeUID: 200401, TypeName: "Detection Finding: Create",
		SeverityID: 4, Severity: "High", // legitimate work never touches a tripwire
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
			CorrelatedTripwires: 1, VerifiedByPreviousKey: ev.PreviousKey,
			Layer: ev.Layer, Stage: ev.Stage, SessionID: ev.Session, IncidentID: ev.IncidentID,
			Containment: ev.Containment, Inputs: ev.Inputs, Warning: ev.Warning,
		},
	}
	if ev.Warning { // docs/M16-early-warning.md §2, docs/M17-tool-integrity.md §2
		a.SeverityID, a.Severity = 2, "Low"
		if tok.Kind == store.KindIntegrity {
			a.Message = "Snare warning: a real tool's definition changed"
			a.FindingInfo.Title = "Tool definition changed: " + tok.Label
			a.FindingInfo.Desc = "A gateway saw a real tool's description or input schema differ from the " +
				"definition it pinned. A changed definition can carry instructions the agent will follow. " +
				"Server upgrades change definitions too, so this is a lead, not an alert; a tripwire touch " +
				"in the same session becomes Critical. Accept a reviewed change with snare gateway pins -accept."
		} else {
			a.Message = "Snare warning: a honey value reached an agent through a tool result"
			a.FindingInfo.Title = "Honey value reached the agent: " + tok.Label
			a.FindingInfo.Desc = "A gateway saw a planted honey value in a real tool's result, so the agent " +
				"has read it. Nothing has used it yet. Legitimate work can read config files, so this is " +
				"a lead, not an alert; a tripwire touch in the same session becomes Critical."
		}
	}
	if s := LastInput(ev.Inputs); s != "" {
		a.FindingInfo.Desc += " " + s
	}
	switch ev.Containment {
	case store.ContainBlocked:
		a.FindingInfo.Desc += " The gateway blocked this call, so the value was not sent, and froze the session " +
			"until an admin releases it (snare gateway release)."
	case store.ContainFrozen:
		a.FindingInfo.Desc += " The gateway froze the session: its tool calls fail until an admin releases it " +
			"(snare gateway release)."
	}
	a.setStatus(ev)
	return a
}

// setStatus maps Snare's triage state onto OCSF status_id (docs/M4e-lifecycle.md §2). A
// touch of a disabled tripwire is Suppressed, whatever its triage.
func (a *Alert) setStatus(ev store.Event) {
	a.StatusDetail = ev.Status
	switch {
	case ev.Muted:
		a.StatusID, a.Status, a.StatusDetail = 3, "Suppressed", "muted"
	case ev.Status == store.StatusAcknowledged:
		a.StatusID, a.Status = 2, "In Progress"
	case ev.Status == store.StatusResolved, ev.Status == store.StatusFalsePositive:
		a.StatusID, a.Status = 4, "Resolved"
	default:
		a.StatusID, a.Status, a.StatusDetail = 1, "New", ""
	}
}

func findingUID(tokenID string, eventID int64) string {
	return fmt.Sprintf("snare-%s-%d", tokenID, eventID)
}

// Correlate records the other tripwires touched by the same incident or source shortly
// before, and sets severity (store.Correlation.Critical). One touch can be an accident; an agent working
// through several traps, or moving from one stage to the next, is not. It never lowers
// severity or suppresses an alert.
func (a *Alert) Correlate(c store.Correlation, stage string, window time.Duration) {
	a.Unmapped.CorrelationWindow = window.String()
	distinct := max(c.Tripwires, 1)
	a.Unmapped.CorrelatedTripwires = distinct
	a.Unmapped.CorrelatedStages = c.Stages
	a.Unmapped.CorrelatedTouches = c.Touches
	a.FindingInfo.RelatedEvents = nil
	for _, r := range c.Related {
		a.FindingInfo.RelatedEvents = append(a.FindingInfo.RelatedEvents, RelatedEvent{
			UID: findingUID(r.TokenID, r.EventID), TypeUID: 200401, TypeName: "Detection Finding: Create",
			Title: "Tripwire touched: " + r.Label, FirstSeenTime: r.At.UnixMilli(),
		})
	}
	critical, why := c.Critical(stage)
	if !critical || a.Unmapped.Warning {
		return
	}
	a.SeverityID, a.Severity = 5, "Critical"
	a.Unmapped.CriticalBecause = why
	a.Message = fmt.Sprintf("%s (%s)", a.Message, why)
	switch {
	case distinct >= 2:
		a.FindingInfo.Desc += fmt.Sprintf(" The same source touched %d different tripwires within %s, "+
			"which is how an agent working through planted traps looks.", distinct, window)
	default:
		a.FindingInfo.Desc += " Critical because " + why + "."
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

// LastInput describes the last input before a touch in one sentence, or "" if there are
// none (docs/M9-provenance.md §2).
func LastInput(ins []store.Input) string {
	if len(ins) == 0 {
		return ""
	}
	in := ins[len(ins)-1]
	from := ""
	if in.Source != "" {
		from = " from " + in.Source
	}
	return fmt.Sprintf("Last input before this touch: %s returned %s characters%s (fingerprint %s) %s earlier; "+
		"snare provenance find -hash %s names the file.", in.Tool, thousands(in.Length), from, in.Fingerprint,
		ago(in.AgeSeconds), in.Fingerprint)
}

func ago(s int) string {
	switch {
	case s < 120:
		return fmt.Sprintf("%d s", s)
	case s < 7200:
		return fmt.Sprintf("%d min", s/60)
	}
	return fmt.Sprintf("%d h", s/3600)
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
