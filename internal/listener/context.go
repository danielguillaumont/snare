package listener

import "context"

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
