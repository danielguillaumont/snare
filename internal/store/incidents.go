package store

// Layers, stages and incidents (docs/M7-incidents.md).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Layers: where in the agent's path a tripwire sits.
const (
	LayerIngest  = "ingest"
	LayerContext = "context" // system prompt and memory (M10)
	LayerTool    = "tool"
	LayerData    = "data"
	LayerEgress  = "egress"
	LayerUse     = "use"
)

// Stages: what a touch proves about the agent, in kill-chain order.
const (
	StageSteered      = "steered"
	StageRecon        = "recon"
	StageCollection   = "collection"
	StageExfiltration = "exfiltration"
	StageUse          = "use"
)

// Stages lists the stages in kill-chain order.
var Stages = []string{StageSteered, StageRecon, StageCollection, StageExfiltration, StageUse}

// StageRank is a stage's position in kill-chain order, or -1 for an unknown or empty stage.
func StageRank(stage string) int { return slices.Index(Stages, stage) }

// Classify decides a touch's layer and stage (§1). via is how the token arrived: "egress"
// (the gateway found it in a real tool's arguments) or "use" (it was presented as a
// credential). Both override the kind. Any other via is ignored, so a caller can't promote
// a touch by naming a layer.
func Classify(kind, via string) (layer, stage string) {
	switch via {
	case LayerEgress:
		return LayerEgress, StageExfiltration
	case LayerUse:
		return LayerUse, StageUse
	}
	switch kind {
	case "canary_instruction":
		return LayerIngest, StageSteered
	case "prompt_canary", "memory_canary": // docs/M10-context-canaries.md §1
		return LayerContext, StageSteered
	case "decoy_tool":
		return LayerTool, StageRecon
	}
	return LayerData, StageCollection
}

// IncidentGap is how long an incident stays open after its last touch (§2).
const IncidentGap = time.Hour

// maxSession bounds a stored session id. The listener allows 64 characters.
const maxSession = 64

func incidentKey(e Event) string {
	if e.Session != "" {
		return "s:" + e.Session
	}
	return "ip:" + e.SourceIP
}

// joinIncident returns the incident a new touch joins, or 0 when it starts one. It runs
// inside RecordHit's transaction; the store has one connection, so writes are serial and
// two touches can't both start an incident for the same key.
func joinIncident(ctx context.Context, tx *sql.Tx, e Event, key string) (int64, error) {
	var id, at int64
	err := tx.QueryRowContext(ctx,
		`SELECT incident_id, at FROM events WHERE tenant_id = ? AND incident_key = ? AND incident_id != 0
		 ORDER BY id DESC LIMIT 1`, e.TenantID, key).Scan(&id, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if e.At.Sub(time.UnixMilli(at)) > IncidentGap {
		return 0, nil
	}
	return id, nil
}

// Correlation describes the touches correlated with one touch (see Outbox.Related), counting
// those recorded up to and including it. Later events never count, so a retried delivery
// gets the same answer.
type Correlation struct {
	// Related: the latest touch of each other tripwire, newest first, at most the limit.
	Related []RelatedTouch
	// Tripwires: distinct tripwires, including the touch's own.
	Tripwires int
	// Stages: distinct stages, in kill-chain order, including the touch's own.
	Stages []string
	// Touches: touches so far, including this one.
	Touches int
}

// Critical reports whether a touch at stage is Critical given its correlation, and why
// (docs/M7-incidents.md §3): two or more distinct tripwires, two or more distinct stages,
// or a touch that is itself exfiltration or use. Otherwise it is High. Alerts and the
// dashboard both use it, so they agree.
func (c Correlation) Critical(stage string) (bool, string) {
	switch {
	case c.Tripwires >= 2:
		return true, fmt.Sprintf("the same source touched %d tripwires", c.Tripwires)
	case stage == StageUse:
		return true, "a stolen tripwire value was used as a credential"
	case stage == StageExfiltration:
		return true, "a tripwire value left through a real tool"
	case len(c.Stages) >= 2:
		return true, "the attack moved through " + strings.Join(c.Stages, ", ")
	}
	return false, ""
}

// Incident summarises one incident for listing.
type Incident struct {
	ID        int64     `json:"id"`
	Session   string    `json:"session,omitempty"`
	SourceIP  string    `json:"source_ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Touches   int       `json:"touches"`
	Tripwires int       `json:"tripwires"`
	Stages    []string  `json:"stages"`
	Open      int       `json:"open"` // touches still to triage
}

// sortStages orders distinct stages by kill-chain rank and drops empty ones.
func sortStages(set map[string]bool) []string {
	out := []string{}
	for _, s := range Stages {
		if set[s] {
			out = append(out, s)
		}
	}
	return out
}

const incidentSelect = `SELECT incident_id, MAX(session_id), MIN(source_ip), MIN(at), MAX(at), COUNT(*),
	COUNT(DISTINCT token_id), COALESCE(GROUP_CONCAT(DISTINCT stage), ''), COALESCE(SUM(status = 'open'), 0)
	FROM events`

func scanIncidents(rows *sql.Rows) ([]Incident, error) {
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var first, last int64
		var stages string
		if err := rows.Scan(&in.ID, &in.Session, &in.SourceIP, &first, &last, &in.Touches, &in.Tripwires, &stages, &in.Open); err != nil {
			return nil, err
		}
		in.FirstSeen, in.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		set := map[string]bool{}
		for _, s := range strings.Split(stages, ",") {
			set[s] = true
		}
		in.Stages = sortStages(set)
		out = append(out, in)
	}
	return out, rows.Err()
}

// ListIncidents returns the tenant's incidents, most recently active first. Events recorded
// before M7 belong to no incident and are not listed.
func (v *tenantView) ListIncidents(ctx context.Context, limit int) ([]Incident, error) {
	rows, err := v.db.QueryContext(ctx, incidentSelect+` WHERE tenant_id = ? AND incident_id != 0
		GROUP BY incident_id ORDER BY MAX(at) DESC, incident_id DESC LIMIT ?`, v.tid, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	return scanIncidents(rows)
}

// GetIncident returns one incident and its touches, oldest first.
func (v *tenantView) GetIncident(ctx context.Context, id int64) (Incident, []Event, error) {
	rows, err := v.db.QueryContext(ctx, incidentSelect+` WHERE tenant_id = ? AND incident_id = ? AND incident_id != 0
		GROUP BY incident_id`, v.tid, id)
	if err != nil {
		return Incident{}, nil, err
	}
	ins, err := scanIncidents(rows)
	if err != nil {
		return Incident{}, nil, err
	}
	if len(ins) == 0 {
		return Incident{}, nil, ErrNotFound
	}
	rows, err = v.db.QueryContext(ctx,
		`SELECT `+eventCols+` FROM events WHERE tenant_id = ? AND incident_id = ? ORDER BY at, id LIMIT 1000`, v.tid, id)
	if err != nil {
		return Incident{}, nil, err
	}
	evs, err := scanEvents(rows)
	return ins[0], evs, err
}
