package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SlackSink posts a short message to a Slack incoming webhook. The webhook URL is itself the
// credential, so it is sealed like any other secret and never listed.
type SlackSink struct {
	URL    string
	Client *http.Client
}

func (s SlackSink) Name() string { return "slack" }

const slackHost = "hooks.slack.com"

// validSlackURL accepts only https://hooks.slack.com/services/..., so a "Slack" sink can't
// be pointed anywhere else.
func validSlackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != slackHost || !strings.HasPrefix(u.Path, "/services/") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("slack sink: url must be a Slack incoming webhook (https://%s/services/...)", slackHost)
	}
	return nil
}

// slackEscape neutralises Slack's control sequences. Event details carry attacker-controlled
// text (paths, user agents, query names); unescaped, "<!channel>" would ping everyone and
// "<https://evil|click>" would render a disguised link.
func slackEscape(s string) string {
	// Truncate first, on a rune boundary, so the cut can't split a character or an entity.
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func (s SlackSink) Send(ctx context.Context, a Alert) error {
	u := a.Unmapped
	when := time.UnixMilli(a.Time).UTC().Format("2006-01-02 15:04:05Z")
	field := func(k, v string) map[string]string {
		return map[string]string{"type": "mrkdwn", "text": "*" + k + "*\n" + slackEscape(v)}
	}
	msg := map[string]any{
		// Fallback for notifications; mrkdwn fields carry the same facts.
		"text": "Snare tripwire touched: " + slackEscape(u.Label),
		"blocks": []any{
			map[string]any{"type": "header", "text": map[string]string{"type": "plain_text", "text": "Tripwire touched"}},
			map[string]any{"type": "section", "fields": []any{
				field("Tripwire", u.Label),
				field("Kind", u.Kind),
				field("Channel", u.Channel),
				field("Source", a.SrcEndpoint.IP),
				field("Time (UTC)", when),
				field("Detail", u.Detail),
			}},
			map[string]any{"type": "context", "elements": []any{
				map[string]string{"type": "mrkdwn", "text": "finding " + slackEscape(a.FindingInfo.UID) + " · tenant " + slackEscape(a.Metadata.TenantUID)},
			}},
		},
		"unfurl_links": false,
		"unfurl_media": false,
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err := postJSON(ctx, clientOr(s.Client), s.URL, body, nil); err != nil {
		// Never echo the URL: it is the credential.
		return fmt.Errorf("slack: %w", err)
	}
	return nil
}
