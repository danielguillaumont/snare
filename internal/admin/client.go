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
	Key     string
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
	var evs []store.Event
	err := c.do("GET", fmt.Sprintf("/api/events?token=%s&limit=%d", url.QueryEscape(tokenID), limit), nil, &evs)
	return evs, err
}
