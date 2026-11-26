package token

// Candidate scanning for Match. These replace three regular expressions:
//
//	v1:  snr[a-z2-7]{32}   (leftmost, non-overlapping)
//	b32: [a-z2-7]{32,}     (maximal runs)
//	hex: [0-9a-f]{40,}     (maximal runs)
//
// Go's regexp turns {32,} into dozens of NFA states, and it ran at about 3 MB/s
// (docs/results-bench.md). Every request to the public callback port is scanned, so that was
// CPU an unauthenticated sender could spend for us. These loops are single-pass and
// allocation-free. scan_test.go checks them against the original expressions as an oracle.

var b32Class, hexClass [256]bool

func init() {
	for c := 'a'; c <= 'z'; c++ {
		b32Class[c] = true
	}
	for c := '2'; c <= '7'; c++ {
		b32Class[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		hexClass[c] = true
	}
	for c := 'a'; c <= 'f'; c++ {
		hexClass[c] = true
	}
}

// runs returns up to limit maximal runs of class bytes at least minLen long, left to right.
func runs(text string, class *[256]bool, minLen, limit int) []string {
	var out []string
	for i := 0; i < len(text) && len(out) < limit; {
		if !class[text[i]] {
			i++
			continue
		}
		j := i + 1
		for j < len(text) && class[text[j]] {
			j++
		}
		if j-i >= minLen {
			out = append(out, text[i:j])
		}
		i = j
	}
	return out
}

// v1Candidates returns up to limit leftmost, non-overlapping matches of snr[a-z2-7]{32}.
func v1Candidates(text string, limit int) []string {
	var out []string
	for i := 0; i+v1Length <= len(text) && len(out) < limit; {
		if text[i] != 's' || text[i+1] != 'n' || text[i+2] != 'r' {
			i++
			continue
		}
		ok := true
		for k := i + len(v1Prefix); k < i+v1Length; k++ {
			if !b32Class[text[k]] {
				ok = false
				break
			}
		}
		if !ok {
			i++
			continue
		}
		out = append(out, text[i:i+v1Length])
		i += v1Length
	}
	return out
}
