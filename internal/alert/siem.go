package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// postJSON sends body and treats any non-2xx as an error, keeping a short excerpt of the
// response for the log. Sink secrets travel in headers only, never in URLs or errors.
func postJSON(ctx context.Context, c *http.Client, u string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Snare/"+ProductVersion)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(excerpt)))
	}
	return nil
}

func clientOr(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// --------------------------------------------------------------------------- Splunk

// SplunkHECSink sends to a Splunk HTTP Event Collector.
// https://docs.splunk.com/Documentation/Splunk/latest/Data/HECRESTendpoints
type SplunkHECSink struct {
	URL        string // base, e.g. https://splunk.example.com:8088
	Token      string
	Index      string // optional
	SourceType string // default snare:ocsf:detection_finding
	Client     *http.Client
}

func (SplunkHECSink) Name() string { return "splunk_hec" }

func (s SplunkHECSink) Send(ctx context.Context, a Alert) error {
	st := s.SourceType
	if st == "" {
		st = "snare:ocsf:detection_finding"
	}
	ev := map[string]any{
		"time":       float64(a.Time) / 1000, // HEC wants epoch seconds
		"source":     "snare",
		"sourcetype": st,
		"event":      a,
	}
	if s.Index != "" {
		ev["index"] = s.Index
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return postJSON(ctx, clientOr(s.Client), strings.TrimRight(s.URL, "/")+"/services/collector/event", body,
		map[string]string{"Authorization": "Splunk " + s.Token})
}

// --------------------------------------------------------------------------- Elastic

// ElasticSink indexes one document per alert.
// https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
type ElasticSink struct {
	URL    string // e.g. https://my-deployment.es.example.io
	Index  string // default snare-alerts
	APIKey string // base64 "id:api_key", as Elastic issues it
	Client *http.Client
}

func (ElasticSink) Name() string { return "elastic" }

func (s ElasticSink) Send(ctx context.Context, a Alert) error {
	idx := s.Index
	if idx == "" {
		idx = "snare-alerts"
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["@timestamp"] = time.UnixMilli(a.Time).UTC().Format(time.RFC3339Nano)
	body, _ := json.Marshal(doc)
	// PUT with the finding uid as the id makes retries idempotent: a retried alert overwrites
	// itself instead of appearing twice.
	u := strings.TrimRight(s.URL, "/") + "/" + url.PathEscape(idx) + "/_doc/" + url.PathEscape(a.FindingInfo.UID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Snare/"+ProductVersion)
	req.Header.Set("Authorization", "ApiKey "+s.APIKey)
	resp, err := clientOr(s.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(excerpt)))
	}
	return nil
}

// --------------------------------------------------------------------------- Sentinel

// SentinelSink sends to Microsoft Sentinel through the Azure Monitor Logs Ingestion API
// (data collection endpoint + data collection rule), authenticating as an Entra ID app with
// client credentials.
// https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview
type SentinelSink struct {
	Endpoint     string // data collection endpoint, e.g. https://my-dce.westeurope-1.ingest.monitor.azure.com
	RuleID       string // DCR immutable id, dcr-...
	Stream       string // e.g. Custom-SnareAlerts_CL
	TenantID     string // Entra ID tenant
	ClientID     string
	ClientSecret string
	Authority    string // default https://login.microsoftonline.com (tests override)
	Client       *http.Client

	mu     *sync.Mutex
	cached *aadToken
}

type aadToken struct {
	value   string
	expires time.Time
}

const sentinelScope = "https://monitor.azure.com//.default" // the double slash is Microsoft's

// NewSentinelSink returns a sink with its own token cache.
func NewSentinelSink(s SentinelSink) *SentinelSink {
	s.mu = &sync.Mutex{}
	return &s
}

func (*SentinelSink) Name() string { return "sentinel" }

func (s *SentinelSink) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && time.Until(s.cached.expires) > 2*time.Minute {
		return s.cached.value, nil
	}
	auth := s.Authority
	if auth == "" {
		auth = "https://login.microsoftonline.com"
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.ClientID},
		"client_secret": {s.ClientSecret},
		"scope":         {sentinelScope},
	}
	u := strings.TrimRight(auth, "/") + "/" + url.PathEscape(s.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := clientOr(s.Client).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tr)
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		return "", fmt.Errorf("entra token: status %d %s", resp.StatusCode, tr.Error)
	}
	s.cached = &aadToken{value: tr.AccessToken, expires: time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)}
	return tr.AccessToken, nil
}

// SentinelRecord flattens the OCSF finding into the columns a DCR transform can map directly
// (TimeGenerated is required by custom tables); the full finding rides along as JSON.
type SentinelRecord struct {
	TimeGenerated string `json:"TimeGenerated"`
	FindingUID    string `json:"FindingUid"`
	Title         string `json:"Title"`
	Severity      string `json:"Severity"`
	SourceIP      string `json:"SrcIp"`
	Channel       string `json:"Channel"`
	TokenKind     string `json:"TokenKind"`
	TokenLabel    string `json:"TokenLabel"`
	OCSF          Alert  `json:"Ocsf"`
}

func (s *SentinelSink) Send(ctx context.Context, a Alert) error {
	tok, err := s.token(ctx)
	if err != nil {
		return err
	}
	rec := []SentinelRecord{{
		TimeGenerated: time.UnixMilli(a.Time).UTC().Format(time.RFC3339Nano),
		FindingUID:    a.FindingInfo.UID, Title: a.FindingInfo.Title, Severity: a.Severity,
		SourceIP: a.SrcEndpoint.IP, Channel: a.Unmapped.Channel,
		TokenKind: a.Unmapped.Kind, TokenLabel: a.Unmapped.Label, OCSF: a,
	}}
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01",
		strings.TrimRight(s.Endpoint, "/"), url.PathEscape(s.RuleID), url.PathEscape(s.Stream))
	err = postJSON(ctx, clientOr(s.Client), u, body, map[string]string{"Authorization": "Bearer " + tok})
	if err != nil && strings.HasPrefix(err.Error(), "status 401") {
		s.mu.Lock()
		s.cached = nil // revoked or rotated: fetch a new token on the retry
		s.mu.Unlock()
	}
	return err
}
