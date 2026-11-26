package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/danielguillaumont/snare/internal/advise"
)

// adviseCmd reads an MCP client config and says where tripwires belong. Offline: it never
// connects to the servers it reads about.
func adviseCmd(args []string) error {
	fs := flag.NewFlagSet("advise", flag.ExitOnError)
	cfgPath := fs.String("config", "", "MCP client config (mcpServers or servers), e.g. claude_desktop_config.json")
	toolsPath := fs.String("tools", "", "optional tools dump: {\"server\": tools/list result}")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fs.Usage()
		return fmt.Errorf("-config is required")
	}
	cfg, err := advise.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	var tools map[string][]advise.Tool
	if *toolsPath != "" {
		if tools, err = advise.LoadTools(*toolsPath); err != nil {
			return err
		}
	}
	rep := advise.Analyze(cfg, tools)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	short := map[advise.Capability]string{advise.UntrustedInput: "untrusted input", advise.PrivateData: "private data", advise.Exfiltration: "way out"}
	fmt.Printf("Servers (%d):\n", len(rep.Servers))
	for _, s := range rep.Servers {
		var cs []string
		for _, c := range s.Capabilities {
			cs = append(cs, short[c])
		}
		capText := strings.Join(cs, ", ")
		if capText == "" {
			capText = "-"
		}
		fmt.Printf("  %-18s %-28s %s\n", s.Name, s.Kind, capText)
	}
	fmt.Println()
	for _, c := range []advise.Capability{advise.UntrustedInput, advise.PrivateData, advise.Exfiltration} {
		who := strings.Join(rep.Legs[c], ", ")
		if who == "" {
			who = "none"
		}
		fmt.Printf("  %-16s %s\n", short[c]+":", who)
	}
	fmt.Printf("\nRisk: %s", strings.ToUpper(rep.Risk))
	if rep.Trifecta {
		fmt.Print(" (all three: an injection here can reach data and send it out)")
	}
	fmt.Print("\n\nRecommendations:\n")
	for i, r := range rep.Recommendations {
		fmt.Printf("%d. %s\n   %s\n", i+1, r.Why, r.Action)
		if r.Command != "" {
			fmt.Printf("   $ %s\n", r.Command)
		}
	}
	fmt.Printf("\nNote: %s\n", rep.Caveat)
	return nil
}
