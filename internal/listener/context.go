package listener

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Context is what a listener learned about how a token arrived, beyond the token itself
// (docs/M7-incidents.md §1). It travels to the recorder as a context value, so the Recorder
// interface stays the same for listeners that know nothing extra.
type Context struct {
	// Via is "egress" when a Snare gateway found the token in a real tool's arguments,
	// "use" when it was presented as a credential, and empty otherwise.
	Via string
	// Session is the gateway session that reported the touch, if any.
	Session string
	// Containment the gateway took: "blocked" or "frozen" (M8), or empty.
	Containment string
	// Inputs: the tool results the agent received before the touch, oldest first (M9).
	Inputs []Input
}

// Input is one ledger entry a gateway reported (docs/M9-provenance.md §2).
type Input struct {
	Tool        string
	Fingerprint string
	Length      int
	AgeSeconds  int
	Source      string // only when the gateway has provenance names on
}

type contextKey struct{}

// WithContext attaches c to ctx.
func WithContext(ctx context.Context, c Context) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}

// ContextFrom returns the Context attached to ctx, or the zero Context.
func ContextFrom(ctx context.Context) Context {
	c, _ := ctx.Value(contextKey{}).(Context)
	return c
}

// arrival reads the structured context from an HTTP callback's allowlisted parameters.
func arrival(layer, session, contain string) Context {
	c := Context{}
	if layer == "egress" {
		c.Via = "egress"
	}
	if contextValue(session) {
		c.Session = session
	}
	if contain == "blocked" || contain == "frozen" {
		c.Containment = contain
	}
	return c
}

// maxInputs is the gateway ledger's size: in0..in7.
const maxInputs = 8

var (
	inputShape  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}~[0-9a-f]{16}~[0-9]{1,9}~[0-9]{1,7}$`)
	sourceShape = regexp.MustCompile(`^[A-Za-z0-9._/:-]{1,128}$`)
)

// inputs reads in0..in7 and src0..src7. A value that doesn't have the exact shape is
// dropped, with its source; the rest are kept in order.
func inputs(q url.Values) []Input {
	var out []Input
	for i := 0; i < maxInputs; i++ {
		k := strconv.Itoa(i)
		v := q.Get("in" + k)
		if !inputShape.MatchString(v) {
			continue
		}
		f := strings.Split(v, "~")
		n, _ := strconv.Atoi(f[2])
		age, _ := strconv.Atoi(f[3])
		in := Input{Tool: f[0], Fingerprint: f[1], Length: n, AgeSeconds: age}
		if s := q.Get("src" + k); sourceShape.MatchString(s) {
			in.Source = s
		}
		out = append(out, in)
	}
	return out
}
