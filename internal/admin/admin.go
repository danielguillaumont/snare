// Package admin serves the authenticated management API: mint tokens, list tokens and events.
// It listens on its own address (default localhost), separate from the public listeners.
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

var Kinds = map[string]bool{
	"decoy_tool": true, "honey_credential": true, "canary_doc": true,
	"canary_url": true, "canary_instruction": true, "other": true,
}

type API struct {
	Key       []byte
	Signer    *token.Signer
	Store     *store.Store
	PublicURL string // e.g. https://cb.example.com
	Zone      string // e.g. cb.example.com.
	Log       *slog.Logger
}

type MintRequest struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Memo  string `json:"memo,omitempty"`
}

type MintResponse struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	URL      string `json:"url,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.Handle("POST /api/tokens", a.auth(http.HandlerFunc(a.mint)))
	mux.Handle("GET /api/tokens", a.auth(http.HandlerFunc(a.listTokens)))
	mux.Handle("GET /api/events", a.auth(http.HandlerFunc(a.listEvents)))
	return mux
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), a.Key) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) mint(w http.ResponseWriter, r *http.Request) {
	var req MintRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if !Kinds[req.Kind] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown kind"})
		return
	}
	if req.Label == "" || len(req.Label) > 200 || len(req.Memo) > 2000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label required (max 200 chars); memo max 2000"})
		return
	}
	tok, id, err := a.Signer.Mint()
	if err != nil {
		a.fail(w, "mint", err)
		return
	}
	if err := a.Store.CreateToken(r.Context(), store.Token{ID: id, Kind: req.Kind, Label: req.Label, Memo: req.Memo}); err != nil {
		a.fail(w, "store token", err)
		return
	}
	resp := MintResponse{ID: id, Token: tok}
	if a.PublicURL != "" {
		resp.URL = strings.TrimRight(a.PublicURL, "/") + "/t/" + tok
	}
	if a.Zone != "" {
		resp.Hostname = tok + "." + strings.TrimSuffix(a.Zone, ".")
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.Store.ListTokens(r.Context())
	if err != nil {
		a.fail(w, "list tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(toks))
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	evs, err := a.Store.ListEvents(r.Context(), r.URL.Query().Get("token"), limit)
	if err != nil {
		a.fail(w, "list events", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(evs))
}

func (a *API) fail(w http.ResponseWriter, what string, err error) {
	a.Log.Error(what, "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
