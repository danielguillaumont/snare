package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestMain lets a test re-run this binary as the snare CLI: SNARE_TEST_ARGS holds the
// arguments. That is how the guide test asks each real subcommand for its flags.
func TestMain(m *testing.M) {
	if args, ok := os.LookupEnv("SNARE_TEST_ARGS"); ok {
		os.Args = append([]string{"snare"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Subcommands that take no flags; asking them for -h would run them (serve would listen).
var noFlags = map[string]bool{"version": true, "keygen": true, "serve": true}

// Subcommands whose first argument selects a further subcommand with its own flag set.
var nested = map[string]bool{"plant": true, "tenant": true}

// TestIntegrationGuideCommandsParse keeps docs/INTEGRATIONS.md honest: every snare command
// in its code blocks names a real subcommand, and every flag it passes is one that
// subcommand's FlagSet defines (read from its -h output, not from a hand-kept list).
func TestIntegrationGuideCommandsParse(t *testing.T) {
	raw, err := os.ReadFile("../../docs/INTEGRATIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	blocks := regexp.MustCompile("(?s)```sh\n(.*?)```").FindAllStringSubmatch(text, -1)
	var cmds [][]string
	for _, b := range blocks {
		for _, line := range strings.Split(b[1], "\n") {
			if f := strings.Fields(line); len(f) > 1 && f[0] == "snare" {
				cmds = append(cmds, f[1:])
			}
		}
	}
	if len(cmds) < 6 {
		t.Fatalf("found only %d snare commands in the guide", len(cmds))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	flagLine := regexp.MustCompile(`(?m)^\s+-([a-z][a-z-]*)`)
	defined := map[string]map[string]bool{}
	for _, args := range cmds {
		sub := args[0]
		n := 1
		if nested[sub] {
			n = 2
		}
		name := strings.Join(args[:n], " ")
		if noFlags[sub] {
			for _, a := range args[1:] {
				if strings.HasPrefix(a, "-") {
					t.Errorf("snare %s takes no flags, guide passes %s", sub, a)
				}
			}
			continue
		}
		if defined[name] == nil {
			cmd := exec.Command(exe, "-test.run=^$")
			cmd.Env = append(os.Environ(), "SNARE_TEST_ARGS="+name+" -h",
				"SNARE_ADMIN_URL=http://127.0.0.1:1", "SNARE_ADMIN_KEY=unused")
			out, _ := cmd.CombinedOutput()
			if strings.Contains(string(out), "usage:\n  snare version") {
				t.Errorf("snare %s: not a subcommand (guide line: snare %s)", name, strings.Join(args, " "))
				continue
			}
			defined[name] = map[string]bool{}
			for _, m := range flagLine.FindAllStringSubmatch(string(out), -1) {
				defined[name][m[1]] = true
			}
			if len(defined[name]) == 0 {
				t.Fatalf("snare %s -h listed no flags:\n%s", name, out)
			}
		}
		for _, a := range args[n:] {
			if a == "--" {
				break // what follows is the wrapped server's own command line
			}
			if !strings.HasPrefix(a, "-") {
				continue
			}
			f := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
			if !defined[name][f] {
				t.Errorf("snare %s has no -%s flag (guide line: snare %s)", name, f, strings.Join(args, " "))
			}
		}
	}
}
