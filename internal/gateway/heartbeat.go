package gateway

// The gateway's heartbeat (docs/M11-heartbeat.md): a synthetic touch of a heartbeat token at
// start and on an interval, proving the path from the agent's machine to Snare works.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Heartbeat configures the gateway's heartbeat. Nil (absent from gw.json) is off.
type Heartbeat struct {
	Token string `json:"token"` // a heartbeat-kind token: its touches are never alerts
	Every string `json:"every"` // Go duration, at least 1m; e.g. "15m"
}

// DefaultHeartbeat is the interval snare plant gateway writes.
const DefaultHeartbeat = 15 * time.Minute

const layerHeartbeat = "heartbeat"

func (h *Heartbeat) interval() (time.Duration, error) {
	if h.Token == "" {
		return 0, errors.New("heartbeat: token is required")
	}
	d, err := time.ParseDuration(h.Every)
	if err != nil {
		return 0, fmt.Errorf("heartbeat: every %q: %w", h.Every, err)
	}
	if d < time.Minute {
		return 0, fmt.Errorf("heartbeat: every %s: at least 1m", d)
	}
	return d, nil
}

// heartbeat beats once now, then every interval until stop closes.
func (g *Gateway) heartbeat(ctx context.Context, every time.Duration, stop <-chan struct{}) {
	g.fire(ctx, g.Cfg.Heartbeat.Token, layerHeartbeat, "", "")
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			g.fire(ctx, g.Cfg.Heartbeat.Token, layerHeartbeat, "", "")
		}
	}
}
