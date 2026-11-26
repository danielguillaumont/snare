package token

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The expressions the scanner replaced. They stay here as the specification.
var (
	oracleV1  = regexp.MustCompile(`snr[a-z2-7]{32}`)
	oracleB32 = regexp.MustCompile(`[a-z2-7]{32,}`)
	oracleHex = regexp.MustCompile(`[0-9a-f]{40,}`)
)

func checkScan(t *testing.T, text string) {
	t.Helper()
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"v1", v1Candidates(text, 8), oracleV1.FindAllString(text, 8)},
		{"b32", runs(text, &b32Class, b32Len, 16), oracleB32.FindAllString(text, 16)},
		{"hex", runs(text, &hexClass, hexLen, 16), oracleHex.FindAllString(text, 16)},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Fatalf("%s scan of %q:\n got  %q\n want %q", c.name, text, c.got, c.want)
		}
	}
}

func TestScanMatchesRegexpOracle(t *testing.T) {
	b := strings.Repeat("a", 32)
	for _, text := range []string{
		"", "snr", "snr" + b, "snr" + b[:31], "xsnr" + b + "7", "snrsnr" + b,
		"snr" + b + "snr" + b, "snr" + b[:10] + "!" + b, strings.Repeat("snr"+b, 12),
		b, b[:31], b + "-" + b, strings.Repeat(b+" ", 20), "ABC" + b,
		strings.Repeat("0123456789abcdef", 3), strings.Repeat("0", 39), strings.Repeat("0", 40),
		strings.Repeat("abcdefghijklmnopqrstuvwxyz234567", 64), "\xff\x00" + b + "☃",
		"GET /v1/" + b + " HTTP/1.1", strings.Repeat("snr", 40),
	} {
		checkScan(t, text)
	}
}

func FuzzScanMatchesRegexp(f *testing.F) {
	f.Add("snr" + strings.Repeat("a", 32))
	f.Add(strings.Repeat("ab2", 20) + strings.Repeat("0f", 25))
	f.Add("snrsnr" + strings.Repeat("7", 40))
	f.Fuzz(func(t *testing.T, text string) {
		checkScan(t, strings.ToLower(text))
	})
}
