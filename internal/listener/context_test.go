package listener

import "testing"

// A gateway's exposure layer is not a channel the listener knows: the touch is classified by
// its token alone, so a honey key sent with ?layer=exposure is not downgraded (M16 §2).
func TestExposureLayerIsNotAVia(t *testing.T) {
	if c := arrival("exposure", "s0123456789ab", ""); c.Via != "" || c.Session != "s0123456789ab" {
		t.Fatalf("%+v", c)
	}
}
