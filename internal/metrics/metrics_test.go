package metrics

import (
	"bufio"
	"regexp"
	"strings"
	"testing"
)

// Lines of the text exposition format: comments, or `name{labels} value`.
var (
	sampleLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*",?)*\})? (-?[0-9.e+-]+|\+Inf|-Inf|NaN)$`)
	metaLine   = regexp.MustCompile(`^# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* .+$`)
)

func render(r *Registry) string {
	var b strings.Builder
	r.Write(&b)
	return b.String()
}

func TestExpositionFormat(t *testing.T) {
	r := New()
	c := r.Counter("snare_hits_total", "Verified tripwire hits.", "channel")
	c.Inc("http")
	c.Inc("http")
	c.Add(3, `d"n\s`)
	plain := r.Counter("snare_alerts_shed_total", "Shed.")
	plain.Inc()
	r.GaugeFunc("snare_deliveries_pending", "Pending.", func() float64 { return 7 })
	h := r.Histogram("snare_delivery_latency_seconds", "Latency.", []float64{0.1, 1, 10})
	for _, v := range []float64{0.05, 0.1, 0.5, 20} {
		h.Observe(v)
	}
	out := render(r)

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !sampleLine.MatchString(line) && !metaLine.MatchString(line) {
			t.Errorf("not exposition format: %q", line)
		}
	}
	for _, want := range []string{
		`snare_hits_total{channel="http"} 2`,
		`snare_hits_total{channel="d\"n\\s"} 3`,
		"snare_alerts_shed_total 1",
		"snare_deliveries_pending 7",
		`snare_delivery_latency_seconds_bucket{le="0.1"} 2`, // 0.05 and 0.1 (le is inclusive)
		`snare_delivery_latency_seconds_bucket{le="1"} 3`,
		`snare_delivery_latency_seconds_bucket{le="10"} 3`,
		`snare_delivery_latency_seconds_bucket{le="+Inf"} 4`,
		"snare_delivery_latency_seconds_sum 20.65",
		"snare_delivery_latency_seconds_count 4",
		"# TYPE snare_delivery_latency_seconds histogram",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if c.Value("http") != 2 {
		t.Fatal("Value")
	}
}

func TestMisuse(t *testing.T) {
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		f()
	}
	r := New()
	c := r.Counter("a_total", "a", "x")
	mustPanic("wrong label count", func() { c.Inc() })
	mustPanic("negative add", func() { c.Add(-1, "v") })
	mustPanic("duplicate name", func() { r.Counter("a_total", "again") })
	mustPanic("unsorted bounds", func() { r.Histogram("h", "h", []float64{2, 1}) })

	var nilC *Counter
	var nilH *Histogram
	nilC.Inc() // nil metrics are no-ops, so callers can leave them unset
	nilH.Observe(1)
}
