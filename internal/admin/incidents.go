package admin

// Incidents (docs/M7-incidents.md §4).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielguillaumont/snare/internal/store"
)

// IncidentTouch is one touch in an incident's timeline.
type IncidentTouch struct {
	store.Event
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// IncidentDetail is the body of GET /api/incidents/{id}: the incident and its touches,
// oldest first.
type IncidentDetail struct {
	store.Incident
	Timeline []IncidentTouch `json:"timeline"`
}

func (a *API) listIncidents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ins, err := a.view(r).ListIncidents(r.Context(), limit)
	if err != nil {
		a.fail(w, "list incidents", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(ins))
}

func (a *API) getIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	d, err := Incident(r, a.view(r), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.fail(w, "get incident", err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ReleaseRequest is the body of POST /api/sessions/{id}/release.
type ReleaseRequest struct {
	Note string `json:"note"`
}

// ReleaseResponse says how many contained touches the released session had.
type ReleaseResponse struct {
	ContainedTouches int `json:"contained_touches"`
}

// releaseSession records an audited release of a contained gateway session (M8 §4).
func (a *API) releaseSession(w http.ResponseWriter, r *http.Request) {
	var req ReleaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body: {\"note\": \"why it is safe to release\"}"})
		return
	}
	n, err := a.view(r).ReleaseSession(r.Context(), r.PathValue("id"), strings.TrimSpace(req.Note))
	switch {
	case errors.Is(err, store.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("a note is required, at most %d bytes", store.MaxTriageNote)})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case err != nil:
		a.fail(w, "release session", err)
	default:
		writeJSON(w, http.StatusOK, ReleaseResponse{ContainedTouches: n})
	}
}

// Incident assembles an incident's timeline with each touch's tripwire kind and label. The
// dashboard uses it too.
func Incident(r *http.Request, v store.TenantStore, id int64) (IncidentDetail, error) {
	in, evs, err := v.GetIncident(r.Context(), id)
	if err != nil {
		return IncidentDetail{}, err
	}
	toks, err := v.ListTokens(r.Context())
	if err != nil {
		return IncidentDetail{}, fmt.Errorf("tokens: %w", err)
	}
	byID := map[string]store.Token{}
	for _, t := range toks {
		byID[t.ID] = t
	}
	d := IncidentDetail{Incident: in, Timeline: make([]IncidentTouch, 0, len(evs))}
	for _, e := range evs {
		t, ok := byID[e.TokenID]
		if !ok {
			t = store.Token{Kind: "unknown", Label: "(deleted tripwire)"}
		}
		d.Timeline = append(d.Timeline, IncidentTouch{Event: e, Kind: t.Kind, Label: t.Label})
	}
	return d, nil
}
