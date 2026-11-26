package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// Client calls the admin API.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:8081
	Key     string // operator key or a tenant API key
	Tenant  string // with the operator key: act on this tenant (X-Snare-Tenant)
	HTTP    *http.Client
}

func (c *Client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	if c.Tenant != "" {
		req.Header.Set(TenantHeader, c.Tenant)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Mint creates a token. It satisfies plant.Minter.
func (c *Client) Mint(kind, label, memo string) (MintResponse, error) {
	var r MintResponse
	err := c.do("POST", "/api/tokens", MintRequest{Kind: kind, Label: label, Memo: memo}, &r)
	return r, err
}

func (c *Client) Events(tokenID string, limit int) ([]store.Event, error) {
	return c.EventsFiltered(store.EventFilter{TokenID: tokenID}, limit)
}

func (c *Client) EventsFiltered(f store.EventFilter, limit int) ([]store.Event, error) {
	var evs []store.Event
	err := c.do("GET", fmt.Sprintf("/api/events?token=%s&status=%s&limit=%d",
		url.QueryEscape(f.TokenID), url.QueryEscape(f.Status), limit), nil, &evs)
	return evs, err
}

// Triage sets an event's triage status and note.
func (c *Client) Triage(eventID int64, status, note string) error {
	return c.do("POST", fmt.Sprintf("/api/events/%d/triage", eventID), TriageRequest{Status: status, Note: note}, nil)
}

func (c *Client) Tokens() ([]store.Token, error) {
	var ts []store.Token
	err := c.do("GET", "/api/tokens", nil, &ts)
	return ts, err
}

// SetTokenDisabled mutes (disabled) or unmutes a tripwire.
func (c *Client) SetTokenDisabled(tokenID string, disabled bool) error {
	action := "enable"
	if disabled {
		action = "disable"
	}
	return c.do("POST", "/api/tokens/"+url.PathEscape(tokenID)+"/"+action, nil, nil)
}

// IssuedKey is a new tenant API key; Key is shown once and not stored in plaintext.
type IssuedKey struct {
	store.APIKey
	Key string `json:"key"`
}

func (c *Client) CreateTenant(name string) (store.Tenant, error) {
	var t store.Tenant
	err := c.do("POST", "/api/operator/tenants", map[string]string{"name": name}, &t)
	return t, err
}

func (c *Client) ListTenants() ([]store.Tenant, error) {
	var ts []store.Tenant
	err := c.do("GET", "/api/operator/tenants", nil, &ts)
	return ts, err
}

func (c *Client) IssueKey(tenantID, role string) (IssuedKey, error) {
	var k IssuedKey
	err := c.do("POST", "/api/operator/tenants/"+url.PathEscape(tenantID)+"/keys", map[string]string{"role": role}, &k)
	return k, err
}

func (c *Client) RevokeKey(keyID string) error {
	return c.do("DELETE", "/api/operator/keys/"+url.PathEscape(keyID), nil, nil)
}

// Audit lists audit records, newest first: the caller's tenant for a tenant key, or (with
// the operator key) one tenant or, with tenantID "", everything.
func (c *Client) Audit(tenantID string, limit int, operator bool) ([]store.AuditEntry, error) {
	var es []store.AuditEntry
	path := fmt.Sprintf("/api/audit?limit=%d", limit)
	if operator {
		path = fmt.Sprintf("/api/operator/audit?tenant=%s&limit=%d", url.QueryEscape(tenantID), limit)
	}
	err := c.do("GET", path, nil, &es)
	return es, err
}

// Deliveries lists alert deliveries, newest first: the caller's tenant, or every tenant for
// the operator. state "" means any.
func (c *Client) Deliveries(state string, limit int, operator bool) ([]store.Delivery, error) {
	var ds []store.Delivery
	base := "/api/deliveries"
	if operator {
		base = "/api/operator/deliveries"
	}
	err := c.do("GET", fmt.Sprintf("%s?state=%s&limit=%d", base, url.QueryEscape(state), limit), nil, &ds)
	return ds, err
}

// RetryDelivery requeues a dead delivery.
func (c *Client) RetryDelivery(id int64, operator bool) error {
	base := "/api/deliveries/"
	if operator {
		base = "/api/operator/deliveries/"
	}
	return c.do("POST", fmt.Sprintf("%s%d/retry", base, id), nil, nil)
}

func (c *Client) VerifyAudit() (AuditVerification, error) {
	var v AuditVerification
	err := c.do("GET", "/api/operator/audit/verify", nil, &v)
	return v, err
}

func (c *Client) SetTenantDisabled(tenantID string, disabled bool) error {
	action := "enable"
	if disabled {
		action = "disable"
	}
	return c.do("POST", "/api/operator/tenants/"+url.PathEscape(tenantID)+"/"+action, nil, nil)
}
