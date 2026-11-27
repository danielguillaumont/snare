// Package metrics is a minimal Prometheus text-format registry: counters with labels,
// gauges computed at scrape time, and one histogram type. It exists to avoid pulling the
// client library's dependency tree into a security service for a few dozen series.
//
// Label values must come from small fixed sets; nothing here bounds cardinality.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Registry struct {
	mu      sync.Mutex
	entries []entry
	names   map[string]bool
}

type entry interface {
	write(w io.Writer)
}

func New() *Registry { return &Registry{names: map[string]bool{}} }

func (r *Registry) add(name string, e entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[name] {
		panic("metrics: duplicate " + name)
	}
	r.names[name] = true
	r.entries = append(r.entries, e)
}

// Write writes every metric in registration order.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	es := append([]entry(nil), r.entries...)
	r.mu.Unlock()
	for _, e := range es {
		e.write(w)
	}
}

// ContentType is the Prometheus text exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

func header(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, escHelp(help), name, typ)
}

func escHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func fmtFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func labelString(keys, values []string) string {
	if len(keys) == 0 {
		return ""
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + `="` + escLabel(values[i]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ------------------------------------------------------------------------------- counter

type Counter struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	vals       map[string]float64
	keys       map[string][]string
}

// Counter registers a counter. Pass label names; Inc and Add take values in the same order.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	c := &Counter{name: name, help: help, labels: labels, vals: map[string]float64{}, keys: map[string][]string{}}
	r.add(name, c)
	return c
}

func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

func (c *Counter) Add(v float64, values ...string) {
	if c == nil {
		return
	}
	if len(values) != len(c.labels) {
		panic(fmt.Sprintf("metrics: %s wants %d label values, got %d", c.name, len(c.labels), len(values)))
	}
	if v < 0 {
		panic("metrics: counters only go up")
	}
	k := strings.Join(values, "\xff")
	c.mu.Lock()
	c.vals[k] += v
	if _, ok := c.keys[k]; !ok {
		c.keys[k] = append([]string(nil), values...)
	}
	c.mu.Unlock()
}

// Value returns the current value for one label set (for tests).
func (c *Counter) Value(values ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vals[strings.Join(values, "\xff")]
}

func (c *Counter) write(w io.Writer) {
	header(w, c.name, c.help, "counter")
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.labels) == 0 {
		fmt.Fprintf(w, "%s %s\n", c.name, fmtFloat(c.vals[""]))
		return
	}
	ks := make([]string, 0, len(c.vals))
	for k := range c.vals {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Fprintf(w, "%s%s %s\n", c.name, labelString(c.labels, c.keys[k]), fmtFloat(c.vals[k]))
	}
}

// --------------------------------------------------------------------------------- gauge

type gaugeFunc struct {
	name, help string
	f          func() float64
}

// GaugeFunc registers a gauge whose value is computed at scrape time.
func (r *Registry) GaugeFunc(name, help string, f func() float64) {
	r.add(name, &gaugeFunc{name: name, help: help, f: f})
}

func (g *gaugeFunc) write(w io.Writer) {
	header(w, g.name, g.help, "gauge")
	fmt.Fprintf(w, "%s %s\n", g.name, fmtFloat(g.f()))
}

type gaugeVecFunc struct {
	name, help, label string
	f                 func() map[string]float64
}

// GaugeVecFunc registers a gauge with one label, computed at scrape time: f returns a value
// per label value. Label values must come from a small fixed set.
func (r *Registry) GaugeVecFunc(name, help, label string, f func() map[string]float64) {
	r.add(name, &gaugeVecFunc{name: name, help: help, label: label, f: f})
}

func (g *gaugeVecFunc) write(w io.Writer) {
	header(w, g.name, g.help, "gauge")
	vals := g.f()
	ks := make([]string, 0, len(vals))
	for k := range vals {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Fprintf(w, "%s%s %s\n", g.name, labelString([]string{g.label}, []string{k}), fmtFloat(vals[k]))
	}
}

// ----------------------------------------------------------------------------- histogram

type Histogram struct {
	name, help string
	bounds     []float64
	mu         sync.Mutex
	counts     []uint64 // per bucket, not cumulative; last is +Inf
	sum        float64
	n          uint64
}

// Histogram registers a histogram with the given upper bounds (ascending).
func (r *Registry) Histogram(name, help string, bounds []float64) *Histogram {
	if !sort.Float64sAreSorted(bounds) {
		panic("metrics: histogram bounds must be ascending")
	}
	h := &Histogram{name: name, help: help, bounds: bounds, counts: make([]uint64, len(bounds)+1)}
	r.add(name, h)
	return h
}

func (h *Histogram) Observe(v float64) {
	if h == nil {
		return
	}
	i := sort.SearchFloat64s(h.bounds, v) // first bound >= v
	h.mu.Lock()
	h.counts[i]++
	h.sum += v
	h.n++
	h.mu.Unlock()
}

func (h *Histogram) write(w io.Writer) {
	header(w, h.name, h.help, "histogram")
	h.mu.Lock()
	defer h.mu.Unlock()
	var cum uint64
	for i, b := range h.bounds {
		cum += h.counts[i]
		fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", h.name, fmtFloat(b), cum)
	}
	cum += h.counts[len(h.bounds)]
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %s\n%s_count %d\n", h.name, cum, h.name, fmtFloat(h.sum), h.name, h.n)
}
