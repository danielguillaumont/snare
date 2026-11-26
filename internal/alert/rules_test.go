package alert

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/store"
)

// The shipped Prometheus rules must only reference metrics Snare exports, so renaming a
// metric can't silently disable an alert.
func TestPrometheusRulesReferenceRealMetrics(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/prometheus/snare-rules.yml")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := metrics.New()
	NewMetrics(reg, st)
	var b strings.Builder
	reg.Write(&b)
	exported := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (\S+) (\S+)$`).FindAllStringSubmatch(b.String(), -1) {
		exported[m[1]] = true
		if m[2] == "histogram" {
			for _, s := range []string{"_bucket", "_sum", "_count"} {
				exported[m[1]+s] = true
			}
		}
	}
	var exprs int
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "expr:") {
			continue
		}
		exprs++
		for _, name := range regexp.MustCompile(`snare_[a-z_]+`).FindAllString(line, -1) {
			if !exported[name] {
				t.Errorf("rule uses %s, which Snare does not export", name)
			}
		}
	}
	if exprs < 4 {
		t.Fatalf("found %d rule expressions", exprs)
	}
}
