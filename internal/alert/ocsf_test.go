package alert

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// Excerpt of OCSF 1.3.0 (schema.ocsf.io), Detection Finding [2004]: the attributes the schema
// marks required, with the enumerations we emit. Transcribed by hand; it is a conformance check
// for these fields, not a full schema validation.
var ocsfRequired = map[string][]string{
	"":                 {"activity_id", "category_uid", "class_uid", "finding_info", "metadata", "severity_id", "time", "type_uid"},
	"finding_info":     {"uid", "title"},
	"metadata":         {"product", "version"},
	"metadata.product": {"vendor_name"},
}

var ocsfEnums = map[string]map[float64]string{
	"activity_id":  {0: "Unknown", 1: "Create", 2: "Update", 3: "Close", 99: "Other"},
	"category_uid": {2: "Findings"},
	"class_uid":    {2004: "Detection Finding"},
	"severity_id":  {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal", 99: "Other"},
	"status_id":    {0: "Unknown", 1: "New", 2: "In Progress", 3: "Suppressed", 4: "Resolved", 99: "Other"},
}

// Caption fields that must match their id's enum label.
var ocsfCaptions = map[string]string{
	"activity_id": "activity_name", "category_uid": "category_name", "class_uid": "class_name",
	"severity_id": "severity", "status_id": "status",
}

func sampleAlert() Alert {
	return New(store.Token{ID: "tokid", Kind: "decoy_tool", Label: "support agent decoy"},
		store.Event{ID: 7, TenantID: "tn_a", TokenID: "tokid", Channel: "http", SourceIP: "203.0.113.7",
			Detail: "GET /v1/x", At: time.UnixMilli(1_764_000_000_000)})
}

func TestAlertIsOCSFDetectionFinding(t *testing.T) {
	raw, _ := json.Marshal(sampleAlert())
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	get := func(path string) map[string]any {
		m := doc
		if path == "" {
			return m
		}
		for _, p := range splitDots(path) {
			next, ok := m[p].(map[string]any)
			if !ok {
				t.Fatalf("%s is not an object", path)
			}
			m = next
		}
		return m
	}
	for obj, fields := range ocsfRequired {
		m := get(obj)
		for _, f := range fields {
			if v, ok := m[f]; !ok || v == nil || v == "" {
				t.Errorf("required %s.%s missing", obj, f)
			}
		}
	}
	for f, enum := range ocsfEnums {
		v, ok := doc[f].(float64)
		if !ok {
			t.Errorf("%s missing or not a number", f)
			continue
		}
		label, ok := enum[v]
		if !ok {
			t.Errorf("%s = %v is not in the enumeration", f, v)
			continue
		}
		if cap := ocsfCaptions[f]; doc[cap] != label {
			t.Errorf("%s = %q, want %q for %s %v", cap, doc[cap], label, f, v)
		}
	}
	if doc["type_uid"].(float64) != doc["class_uid"].(float64)*100+doc["activity_id"].(float64) {
		t.Error("type_uid must be class_uid*100 + activity_id")
	}
	if doc["metadata"].(map[string]any)["tenant_uid"] != "tn_a" {
		t.Error("metadata.tenant_uid missing")
	}
	// OCSF timestamps are epoch milliseconds.
	if doc["time"].(float64) != 1_764_000_000_000 {
		t.Errorf("time = %v", doc["time"])
	}
	for _, o := range doc["observables"].([]any) {
		om := o.(map[string]any)
		if om["name"] == "" || om["type_id"] == nil || om["value"] == "" {
			t.Errorf("bad observable %v", om)
		}
	}
}

func splitDots(p string) []string {
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '.' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	return append(out, p[start:])
}
