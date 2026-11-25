package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// LogSink writes alerts as structured log lines.
type LogSink struct{ Log *slog.Logger }

func (LogSink) Name() string { return "log" }

func (s LogSink) Send(_ context.Context, a Alert) error {
	s.Log.Warn("TRIPWIRE",
		"title", a.FindingInfo.Title, "kind", a.Unmapped.Kind, "channel", a.Unmapped.Channel,
		"src_ip", a.SrcEndpoint.IP, "detail", a.Unmapped.Detail, "finding", a.FindingInfo.UID)
	return nil
}

// WebhookSink POSTs the alert as JSON, signed so receivers can verify origin and freshness:
//
//	X-Snare-Timestamp: <unix seconds>
//	X-Snare-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
type WebhookSink struct {
	URL    string
	Secret []byte
	Client *http.Client
	Now    func() time.Time
}

func (WebhookSink) Name() string { return "webhook" }

func Sign(secret []byte, ts string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// VerifyWebhook checks a received webhook. maxAge bounds replay; receivers should use it.
func VerifyWebhook(secret []byte, tsHeader, sigHeader string, body []byte, now time.Time, maxAge time.Duration) error {
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxAge || d < -maxAge {
		return fmt.Errorf("stale timestamp")
	}
	if !hmac.Equal([]byte(Sign(secret, tsHeader, body)), []byte(sigHeader)) {
		return fmt.Errorf("bad signature")
	}
	return nil
}

func (s WebhookSink) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Snare-Webhook/1")
	req.Header.Set("X-Snare-Timestamp", ts)
	req.Header.Set("X-Snare-Signature", Sign(s.Secret, ts, body))
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
