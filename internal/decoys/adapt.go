package decoys

// Adaptive decoy names (docs/M12-adaptive-deception.md §1).
//
// Learn reads the real server's tool list; Adapt rewrites each decoy's screened name in that
// server's vocabulary: its namespace, its verbs, its naming style, its argument style and its
// description punctuation. The decoy's meaning (purpose, description, arguments) is the
// screened one.
//
// The limit, stated in the design: every input here is visible to the agent, so an attacker
// who has read this file can run it too. Adaptation defeats skip-lists of known names, not a
// code reader. Operator-defined names (Override) remain the only names no code can enumerate.

import (
	"sort"
	"strings"
	"unicode"
)

// RealTool is what Learn needs from one real tool.
type RealTool struct {
	Name        string
	Description string
	Params      []string
}

// Vocabulary is what Learn found in a real server's tools.
type Vocabulary struct {
	Style      string            `json:"style"`               // snake, camel or kebab
	Namespace  string            `json:"namespace,omitempty"` // shared first word, e.g. "jira"
	Verbs      map[string]string `json:"verbs,omitempty"`     // verb class -> the server's verb
	ParamStyle string            `json:"param_style"`         // snake or camel
	Period     bool              `json:"period"`              // descriptions end with "."
}

// VerbClasses groups verbs that mean the same thing at the start of a decoy name. Each verb is
// in exactly one class (a test enforces it). Verbs outside every class are never replaced.
var VerbClasses = map[string][]string{
	"read":     {"get", "fetch", "read", "load", "retrieve"},
	"list":     {"list", "show", "enumerate"},
	"export":   {"export", "dump", "download", "extract"},
	"query":    {"query", "search", "lookup", "find"},
	"create":   {"create", "open", "start", "new"},
	"disable":  {"disable", "pause", "suspend", "mute", "stop"},
	"generate": {"generate", "build", "make"},
	"copy":     {"copy", "mirror", "replicate", "sync"},
	"change":   {"change", "move", "transfer", "reassign"},
}

var verbClass = func() map[string]string {
	m := map[string]string{}
	for c, vs := range VerbClasses {
		for _, v := range vs {
			m[v] = c
		}
	}
	return m
}()

// VerbClassOf returns the class of a verb, or "" if it has none.
func VerbClassOf(w string) string { return verbClass[w] }

// Words splits a tool or argument name in any style into lowercase words.
func Words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
			(i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// DetectStyle returns the most common naming style among names: snake, camel or kebab
// (snake when there is no signal).
func DetectStyle(names []string) string {
	count := map[string]int{}
	for _, n := range names {
		switch {
		case strings.Contains(n, "_"):
			count["snake"]++
		case strings.Contains(n, "-"):
			count["kebab"]++
		case strings.IndexFunc(n[min(1, len(n)):], unicode.IsUpper) >= 0:
			count["camel"]++
		}
	}
	best := "snake"
	for _, s := range []string{"camel", "kebab"} {
		if count[s] > count[best] {
			best = s
		}
	}
	return best
}

// NamespaceOf returns the first word shared by at least 2 names and at least 60% of them, when
// it isn't a verb and the names have more words after it. The source_reader attacker in the
// M12 evaluation implements this same rule.
func NamespaceOf(names []string) string {
	count := map[string]int{}
	for _, n := range names {
		if w := Words(n); len(w) > 1 {
			count[w[0]]++
		}
	}
	best, bestN := "", 0
	for w, c := range count {
		if c > bestN || (c == bestN && w < best) {
			best, bestN = w, c
		}
	}
	if bestN < 2 || bestN*10 < 6*len(names) || VerbClassOf(best) != "" {
		return ""
	}
	return best
}

// Learn reads a real server's tool list.
func Learn(tools []RealTool) Vocabulary {
	var names, params []string
	for _, t := range tools {
		names = append(names, t.Name)
		params = append(params, t.Params...)
	}
	v := Vocabulary{Style: DetectStyle(names), Namespace: NamespaceOf(names), ParamStyle: "snake", Period: true}
	if DetectStyle(params) == "camel" {
		v.ParamStyle = "camel"
	}
	used := map[string]map[string]int{}
	for _, t := range tools {
		w := Words(t.Name)
		if len(w) > 1 && w[0] == v.Namespace {
			w = w[1:]
		}
		if len(w) == 0 {
			continue
		}
		if c := VerbClassOf(w[0]); c != "" {
			if used[c] == nil {
				used[c] = map[string]int{}
			}
			used[c][w[0]]++
		}
	}
	for c, vs := range used {
		best, bestN := "", 0
		for w, n := range vs {
			if n > bestN || (n == bestN && w < best) {
				best, bestN = w, n
			}
		}
		if v.Verbs == nil {
			v.Verbs = map[string]string{}
		}
		v.Verbs[c] = best
	}
	withDesc, period := 0, 0
	for _, t := range tools {
		if d := strings.TrimSpace(t.Description); d != "" {
			withDesc++
			if strings.HasSuffix(d, ".") {
				period++
			}
		}
	}
	if withDesc > 0 {
		v.Period = period*2 >= withDesc
	}
	return v
}

// Adapt chooses one name per catalog decoy, as Pick does, then writes it in the server's
// vocabulary. real holds the real tool names: an adapted name that would collide with one, or
// with another decoy, falls back to the unadapted name in the server's style. Overrides are
// used verbatim.
func Adapt(v Vocabulary, seed uint64, overrides map[string]Override, real map[string]bool) ([]Choice, error) {
	style := v.Style
	if !validStyle(style) {
		style = "snake"
	}
	base, err := Pick(seed, "snake", overrides)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, c := range base {
		if c.Custom {
			seen[c.Name] = true
		}
	}
	out := make([]Choice, 0, len(base))
	for _, c := range base {
		t, _ := Get(c.Canonical)
		if c.Custom {
			c.Params = t.Params
			out = append(out, c)
			continue
		}
		words := strings.Split(c.Name, "_")
		if cls := VerbClassOf(words[0]); cls != "" && v.Verbs[cls] != "" {
			words[0] = v.Verbs[cls]
		}
		if v.Namespace != "" && words[0] != v.Namespace {
			words = append([]string{v.Namespace}, words...)
		}
		name := Styled(strings.Join(words, "_"), style)
		if real[name] || seen[name] || !ValidName(name) {
			name = Styled(c.Name, style)
		}
		seen[name] = true
		c.Name = name
		if !v.Period {
			c.Description = strings.TrimSuffix(strings.TrimSpace(c.Description), ".")
		}
		for _, p := range t.Params {
			ps := p.Name
			if v.ParamStyle == "camel" {
				ps = Styled(p.Name, "camel")
			}
			c.Params = append(c.Params, Param{Name: ps, Description: p.Description})
		}
		out = append(out, c)
	}
	return out, nil
}

// Space is what a code reader extracts from this package to recognise adapted decoys: every
// stem in the screened pools, and the verb classes. The M12 evaluation's source_reader uses it.
type Space struct {
	Stems       []string            `json:"stems"`
	VerbClasses map[string][]string `json:"verb_classes"`
}

// AdaptSpace returns the generator's space.
func AdaptSpace() Space {
	var stems []string
	for _, t := range Catalog {
		stems = append(stems, append([]string{t.Name}, Alternatives[t.Name]...)...)
	}
	sort.Strings(stems)
	return Space{Stems: stems, VerbClasses: VerbClasses}
}
