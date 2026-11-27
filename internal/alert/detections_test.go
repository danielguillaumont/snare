package alert

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// The SIEM rules in detections/ must only use fields Snare actually emits. Renaming a field
// in this package without updating them would silently disable a customer's detection, so
// this test reads every rule file, extracts the field paths it uses, and checks each against
// a real, correlated alert in the shape each SIEM receives.

const detectionsDir = "../../detections"

// ocsfPath matches the OCSF attribute paths rules refer to.
var ocsfPath = regexp.MustCompile(`\b(class_uid|severity_id|metadata(?:\.[a-z_]+)+|finding_info(?:\.[a-z_]+)+|src_endpoint(?:\.[a-z_]+)+|unmapped(?:\.[a-z_]+)+)\b`)

// realAlert is what the outbox delivers for the second of two tripwires touched by one
// source, both reported by one gateway session.
func realAlert(t *testing.T) Alert {
	t.Helper()
	ctx := context.Background()
	st := memStore(t)
	v := st.Tenant(store.DefaultTenant)
	_ = v.CreateToken(ctx, store.Token{ID: "tok1", Kind: "honey_credential", Label: "payments .env"})
	_ = v.CreateToken(ctx, store.Token{ID: "tok2", Kind: "decoy_tool", Label: "export_customers"})
	now := time.Now().UTC()
	_, _, _, _, _ = st.RecordHit(ctx, store.Event{TokenID: "tok1", Channel: "http", SourceIP: "198.51.100.7", Session: "s0123456789ab", At: now}, false)
	_, ev, _, _, _ := st.RecordHit(ctx, store.Event{TokenID: "tok2", Channel: "http", SourceIP: "198.51.100.7", Session: "s0123456789ab", Containment: "frozen", Detail: "d", At: now}, false)
	tok, _ := v.GetToken(ctx, "tok2")
	a, err := Build(ctx, st, tok, ev, DefaultCorrelationWindow)
	if err != nil || a.Unmapped.CorrelatedTripwires != 2 || len(a.FindingInfo.RelatedEvents) != 1 {
		t.Fatalf("fixture alert: %+v %v", a.Unmapped, err)
	}
	return a
}

// paths flattens a JSON document into its dotted attribute paths. Arrays are transparent:
// finding_info.related_events.uid exists if any element has uid.
func paths(t *testing.T, v any) map[string]bool {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	_ = json.Unmarshal(raw, &doc)
	out := map[string]bool{}
	var walk func(prefix string, x any)
	walk = func(prefix string, x any) {
		switch x := x.(type) {
		case map[string]any:
			for k, val := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				out[p] = true
				walk(p, val)
			}
		case []any:
			for _, el := range x {
				walk(prefix, el)
			}
		}
	}
	walk("", doc)
	return out
}

func readRule(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(detectionsDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func checkOCSFPaths(t *testing.T, file, text string, have map[string]bool, prefix string, minPaths int) {
	t.Helper()
	found := map[string]bool{}
	for _, p := range ocsfPath.FindAllString(text, -1) {
		found[p] = true
	}
	if len(found) < minPaths {
		t.Errorf("%s: found only %d field paths; the extractor may be broken", file, len(found))
	}
	var missing []string
	for p := range found {
		if !have[prefix+p] {
			missing = append(missing, prefix+p)
		}
	}
	sort.Strings(missing)
	for _, p := range missing {
		t.Errorf("%s uses %s, which Snare's alert does not contain", file, p)
	}
}

func TestDetectionRulesUseRealFields(t *testing.T) {
	a := realAlert(t)
	ocsf := paths(t, a)

	// Splunk HEC and Sigma see the finding itself.
	checkOCSFPaths(t, "splunk/savedsearches.conf", readRule(t, "splunk/savedsearches.conf"), ocsf, "", 10)
	for _, f := range []string{"sigma/snare_tripwire_touched.yml", "sigma/snare_multiple_tripwires.yml"} {
		checkOCSFPaths(t, f, readRule(t, f), ocsf, "", 5)
	}

	// Elastic sees the finding plus @timestamp.
	elastic := paths(t, a)
	elastic["@timestamp"] = true
	rules := readRule(t, "elastic/snare-rules.ndjson")
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(rules), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("elastic rule is not JSON: %v", err)
		}
		for _, k := range []string{"rule_id", "name", "type", "query", "index", "risk_score", "severity", "description"} {
			if _, ok := r[k]; !ok {
				t.Errorf("elastic rule %v lacks %s", r["name"], k)
			}
		}
		n++
	}
	if n != 2 {
		t.Fatalf("%d elastic rules", n)
	}
	checkOCSFPaths(t, "elastic/snare-rules.ndjson", rules, elastic, "", 6)

	// The index template must map only fields that exist.
	var tmpl struct {
		Template struct {
			Mappings struct {
				Properties map[string]any `json:"properties"`
			} `json:"mappings"`
		} `json:"template"`
	}
	if err := json.Unmarshal([]byte(readRule(t, "elastic/index-template.json")), &tmpl); err != nil {
		t.Fatal(err)
	}
	var mapped []string
	var walk func(prefix string, props map[string]any)
	walk = func(prefix string, props map[string]any) {
		for k, v := range props {
			p := strings.TrimPrefix(prefix+"."+k, ".")
			m, _ := v.(map[string]any)
			if sub, ok := m["properties"].(map[string]any); ok {
				walk(p, sub)
				continue
			}
			mapped = append(mapped, p)
		}
	}
	walk("", tmpl.Template.Mappings.Properties)
	if len(mapped) < 15 {
		t.Fatalf("template maps %d fields", len(mapped))
	}
	for _, p := range mapped {
		if !elastic[p] {
			t.Errorf("index template maps %s, which Snare's alert does not contain", p)
		}
	}

	// Sentinel sees SentinelRecord columns, with the finding under Ocsf.
	rec := SentinelRecord{TimeGenerated: "t", FindingUID: a.FindingInfo.UID, Title: a.FindingInfo.Title, Severity: a.Severity,
		SourceIP: a.SrcEndpoint.IP, Channel: a.Unmapped.Channel, TokenKind: a.Unmapped.Kind, TokenLabel: a.Unmapped.Label,
		CorrelatedTripwires: a.Unmapped.CorrelatedTripwires, OCSF: a}
	sent := paths(t, rec)
	columns := map[string]bool{}
	rt := reflect.TypeOf(rec)
	for i := 0; i < rt.NumField(); i++ {
		columns[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	// Names a query defines itself (summarize/extend aliases).
	aliases := map[string]bool{"Tenant": true, "Tripwires": true, "Labels": true, "Channels": true, "FirstSeen": true, "LastSeen": true}
	strLit := regexp.MustCompile(`"[^"]*"`)
	ident := regexp.MustCompile(`\b[A-Z][A-Za-z]+\b`)
	for _, f := range []string{"sentinel/snare-tripwire-touched.yaml", "sentinel/snare-multiple-tripwires.yaml"} {
		text := readRule(t, f)
		q := text[strings.Index(text, "query: |"):]
		q = q[:strings.Index(q, "\nentityMappings:")]
		checkOCSFPaths(t, f, q, sent, "Ocsf.", 4)
		for _, id := range ident.FindAllString(strLit.ReplaceAllString(q, ""), -1) {
			if !columns[id] && !aliases[id] {
				t.Errorf("%s: query uses %s, which is neither a SnareAlerts_CL column nor an alias it defines", f, id)
			}
		}
		for _, k := range []string{"id: ", "name: ", "severity: ", "queryFrequency: ", "queryPeriod: ", "kind: Scheduled"} {
			if !strings.Contains(text, "\n"+k) && !strings.HasPrefix(text, k) {
				t.Errorf("%s lacks %q", f, k)
			}
		}
		if !strings.Contains(text, "columnName: SrcIp") || !sent["SrcIp"] {
			t.Errorf("%s: entity mapping column missing", f)
		}
	}
}

// Every rule excludes the sink test alert (Informational) or keys on correlation, so pressing
// "test" on a sink never pages anyone.
func TestDetectionRulesIgnoreSinkTestAlerts(t *testing.T) {
	for _, f := range []string{"splunk/savedsearches.conf", "elastic/snare-rules.ndjson",
		"sentinel/snare-tripwire-touched.yaml", "sentinel/snare-multiple-tripwires.yaml", "sigma/snare_tripwire_touched.yml"} {
		text := readRule(t, f)
		if !regexp.MustCompile(`severity_id\)?(\|gte:| ?>=) ?4`).MatchString(text) {
			t.Errorf("%s does not exclude severity below High", f)
		}
	}
}
