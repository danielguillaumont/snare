package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/egress"
	"github.com/danielguillaumont/snare/internal/seal"
	"github.com/danielguillaumont/snare/internal/store"
)

// SinkConfig is what a tenant submits for one destination. It is sealed whole before it is
// stored; only Public() ever leaves the server.
type SinkConfig struct {
	Type string `json:"type"` // webhook | splunk_hec | elastic | sentinel | slack
	URL  string `json:"url"`  // webhook / HEC base / Elastic base / Sentinel DCE

	Secret string `json:"secret,omitempty"` // webhook HMAC secret
	Token  string `json:"token,omitempty"`  // Splunk HEC token
	Index  string `json:"index,omitempty"`  // Splunk index or Elastic index
	APIKey string `json:"api_key,omitempty"`

	RuleID       string `json:"rule_id,omitempty"` // Sentinel DCR immutable id
	Stream       string `json:"stream,omitempty"`
	AzureTenant  string `json:"azure_tenant_id,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Authority    string `json:"authority,omitempty"` // tests only; must pass the egress check
}

// Public is the config with every secret removed, for listing.
func (c SinkConfig) Public() map[string]string {
	m := map[string]string{"type": c.Type, "url": c.URL}
	if c.Type == "slack" {
		m["url"] = "https://" + slackHost + "/services/..." // the webhook URL is the credential
	}
	for k, v := range map[string]string{"index": c.Index, "rule_id": c.RuleID, "stream": c.Stream,
		"azure_tenant_id": c.AzureTenant, "client_id": c.ClientID} {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

// Validate checks required fields and the egress policy for every URL the sink would call.
func (c SinkConfig) Validate(ctx context.Context, p egress.Policy) error {
	need := func(fields ...[2]string) error {
		for _, f := range fields {
			if strings.TrimSpace(f[1]) == "" {
				return fmt.Errorf("%s sink: %s is required", c.Type, f[0])
			}
		}
		return nil
	}
	var err error
	switch c.Type {
	case "webhook":
		err = need([2]string{"url", c.URL}, [2]string{"secret", c.Secret})
		if err == nil && len(c.Secret) < 16 {
			err = fmt.Errorf("webhook sink: secret must be at least 16 characters")
		}
	case "splunk_hec":
		err = need([2]string{"url", c.URL}, [2]string{"token", c.Token})
	case "elastic":
		err = need([2]string{"url", c.URL}, [2]string{"api_key", c.APIKey})
	case "slack":
		err = need([2]string{"url", c.URL})
		if err == nil {
			err = validSlackURL(c.URL)
		}
	case "sentinel":
		err = need([2]string{"url", c.URL}, [2]string{"rule_id", c.RuleID}, [2]string{"stream", c.Stream},
			[2]string{"azure_tenant_id", c.AzureTenant}, [2]string{"client_id", c.ClientID},
			[2]string{"client_secret", c.ClientSecret})
	default:
		return fmt.Errorf("unknown sink type %q", c.Type)
	}
	if err != nil {
		return err
	}
	if err := p.CheckURL(ctx, c.URL); err != nil {
		return err
	}
	if c.Authority != "" {
		return p.CheckURL(ctx, c.Authority)
	}
	return nil
}

// Build turns a config into a live sink using the guarded client.
func (c SinkConfig) Build(client *http.Client) (Sink, error) {
	switch c.Type {
	case "webhook":
		return WebhookSink{URL: c.URL, Secret: []byte(c.Secret), Client: client}, nil
	case "splunk_hec":
		return SplunkHECSink{URL: c.URL, Token: c.Token, Index: c.Index, Client: client}, nil
	case "elastic":
		return ElasticSink{URL: c.URL, Index: c.Index, APIKey: c.APIKey, Client: client}, nil
	case "slack":
		return SlackSink{URL: c.URL, Client: client}, nil
	case "sentinel":
		return NewSentinelSink(SentinelSink{Endpoint: c.URL, RuleID: c.RuleID, Stream: c.Stream, TenantID: c.AzureTenant,
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, Authority: c.Authority, Client: client}), nil
	}
	return nil, fmt.Errorf("unknown sink type %q", c.Type)
}

// SealConfig and OpenConfig bind the sealed blob to (tenant, sink id).
func SealConfig(s *seal.Sealer, c SinkConfig, tenantID, sinkID string) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return s.Seal(b, tenantID, sinkID)
}

func OpenConfig(s *seal.Sealer, r store.SinkRecord) (SinkConfig, error) {
	b, err := s.Open(r.Config, r.TenantID, r.ID)
	if err != nil {
		return SinkConfig{}, err
	}
	var c SinkConfig
	err = json.Unmarshal(b, &c)
	return c, err
}

// TenantResolver loads a tenant's sinks from the store, opens their configs, and caches the
// built sinks briefly (Sentinel token caches live inside them).
type TenantResolver struct {
	Store  *store.Store
	Sealer *seal.Sealer
	Client *http.Client // egress-guarded
	TTL    time.Duration
	Log    *slog.Logger

	mu    sync.Mutex
	cache map[string]cachedSinks
}

type cachedSinks struct {
	sinks []Target
	at    time.Time
}

// Invalidate drops a tenant's cached sinks (after a sink is added or removed).
func (r *TenantResolver) Invalidate(tenantID string) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}

// Sinks returns the tenant's sinks, each keyed by its sink id.
func (r *TenantResolver) Sinks(ctx context.Context, tenantID string) []Target {
	ttl := r.TTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	r.mu.Lock()
	if c, ok := r.cache[tenantID]; ok && time.Since(c.at) < ttl {
		r.mu.Unlock()
		return c.sinks
	}
	r.mu.Unlock()

	recs, err := r.Store.Tenant(tenantID).ListSinks(ctx)
	if err != nil {
		r.Log.Error("load tenant sinks", "tenant", tenantID, "err", err)
		return nil
	}
	var sinks []Target
	for _, rec := range recs {
		cfg, err := OpenConfig(r.Sealer, rec)
		if err != nil {
			r.Log.Error("tenant sink config does not open; skipped", "tenant", tenantID, "sink", rec.ID)
			continue
		}
		s, err := cfg.Build(r.Client)
		if err != nil {
			r.Log.Error("build tenant sink", "tenant", tenantID, "sink", rec.ID, "err", err)
			continue
		}
		sinks = append(sinks, Target{Ref: rec.ID, Sink: s})
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cachedSinks{}
	}
	r.cache[tenantID] = cachedSinks{sinks: sinks, at: time.Now()}
	r.mu.Unlock()
	return sinks
}
