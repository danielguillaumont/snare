// Command snare runs the Snare callback server and plants tripwires.
//
//	snare version                         print the version
//	snare keygen                          print random keys for SNARE_KEY / SNARE_ADMIN_KEY / SNARE_SEAL_KEY
//	snare serve                           run listeners (config from SNARE_* env vars)
//	snare mint -kind K -label L           mint a token through the admin API
//	snare events [-token ID] [-status S]  list recent tripwire events
//	snare incidents [-id N]               list incidents, or print one incident's timeline
//	snare triage -event ID -status S      record what a touch turned out to be
//	snare tokens [-disable ID|-enable ID] list tripwires; mute or unmute one
//	snare demo                            run a self-contained local demo
//	snare tenant create|list|key|revoke   manage tenants and their API keys (operator key)
//	snare advise -config F [-tools F]     where to put tripwires for an agent (offline)
//	snare advise -manifest F              which kill-chain layers your plants arm
//	snare audit [-tenant ID] [-verify]    audit log, or verify its hash chain (operator key)
//	snare deliveries [-state S] [-retry ID]  alert deliveries; requeue a dead one
//	snare plant repo|corpus <dir>         plant honey credentials / canary docs
//	snare plant mcp -config F             write a decoy MCP server config
//	snare decoy-mcp -config F             run the decoy MCP server on stdio
//	snare plant gateway -config F         write a gateway config (decoys + fingerprints)
//	snare gateway -config F -- CMD...     run the gateway in front of a real MCP server
//	snare decoys [-all]                   print decoy names as JSON (for the eval harness)
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/mcp"
	"github.com/danielguillaumont/snare/internal/plant"
	"github.com/danielguillaumont/snare/internal/server"
	"github.com/danielguillaumont/snare/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println("snare", alert.ProductVersion)
	case "keygen":
		err = keygen()
	case "serve":
		err = serve()
	case "mint":
		err = mint(os.Args[2:])
	case "advise":
		err = adviseCmd(os.Args[2:])
	case "audit":
		err = auditCmd(os.Args[2:])
	case "deliveries":
		err = deliveriesCmd(os.Args[2:])
	case "tenant":
		err = tenantCmd(os.Args[2:])
	case "events":
		err = events(os.Args[2:])
	case "incidents":
		err = incidentsCmd(os.Args[2:])
	case "triage":
		err = triageCmd(os.Args[2:])
	case "tokens":
		err = tokensCmd(os.Args[2:])
	case "demo":
		err = demoCmd(os.Args[2:])
	case "plant":
		err = plantCmd(os.Args[2:])
	case "decoy-mcp":
		err = decoyMCP(os.Args[2:])
	case "gateway":
		err = gatewayCmd(os.Args[2:])
	case "decoys":
		err = decoysCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "snare:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  snare version
  snare demo [-http ADDR] [-admin ADDR] [-dashboard ADDR]
  snare keygen
  snare serve
  snare mint -kind K -label L [-memo M]
  snare events [-token ID] [-status open|acknowledged|resolved|false_positive] [-limit N]
  snare incidents [-limit N] | -id N
  snare triage -event ID -status acknowledged|resolved|false_positive|open [-note TEXT]
  snare tokens [-disable ID | -enable ID]
  snare advise -config F [-tools F] [-manifest F] [-json] | -manifest F [-json]
  snare audit [-tenant ID] [-limit N] [-verify]
  snare deliveries [-state pending|delivered|dead] [-limit N] [-retry ID]
  snare tenant create -name N | list | key -tenant ID [-role admin|viewer]
               | revoke -key ID | disable -tenant ID | enable -tenant ID
  snare plant repo   [-dry-run] [-manifest F] <dir>
  snare plant corpus [-dry-run] [-manifest F] [-with-instruction] <dir>
  snare plant mcp    [-dry-run] [-manifest F] -config F [-name N] [-exclude a,b]
                     [-style snake|camel|kebab] [-seed N] [-names F] [-catalog-names]
  snare plant gateway [-dry-run] [-manifest F] -config F [-style auto|snake|camel|kebab|catalog]
                     [-seed N] [-names F] [-exclude a,b] | -refresh -config F
  snare gateway -config F [-v] -- <real server command> [args]
  snare decoy-mcp -config F
  snare decoys [-seed N -style S -names F [-screen] | -all | -table]
`)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func keygen() error {
	fmt.Printf("SNARE_KEY=%s\nSNARE_ADMIN_KEY=%s\nSNARE_WEBHOOK_SECRET=%s\nSNARE_SEAL_KEY=%s\n",
		randHex(32), randHex(24), randHex(24), randHex(32))
	return nil
}

func serve() error {
	cfg, err := server.FromEnv()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	s, err := server.Start(cfg, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.Shutdown(sctx)
	return nil
}

func client() *admin.Client {
	u := os.Getenv("SNARE_ADMIN_URL")
	if u == "" {
		u = "http://127.0.0.1:8081"
	}
	return &admin.Client{BaseURL: u, Key: os.Getenv("SNARE_ADMIN_KEY"), Tenant: os.Getenv("SNARE_TENANT")}
}

func mint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	kind := fs.String("kind", "", "token kind: decoy_tool, honey_credential, canary_doc, canary_url, canary_instruction, other")
	label := fs.String("label", "", "where this tripwire is planted (shown in alerts)")
	memo := fs.String("memo", "", "optional notes")
	_ = fs.Parse(args)
	if !admin.Kinds[*kind] || *label == "" {
		fs.Usage()
		return fmt.Errorf("-kind and -label are required")
	}
	resp, err := client().Mint(*kind, *label, *memo)
	if err != nil {
		return err
	}
	fmt.Printf("token:    %s\nid:       %s\n", resp.Token, resp.ID)
	if resp.URL != "" {
		fmt.Printf("url:      %s\n", resp.URL)
	}
	if resp.Hostname != "" {
		fmt.Printf("hostname: %s\n", resp.Hostname)
	}
	return nil
}

func events(args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	tok := fs.String("token", "", "filter by token id")
	status := fs.String("status", "", "filter by triage status: open, acknowledged, resolved, false_positive")
	limit := fs.Int("limit", 50, "max events")
	_ = fs.Parse(args)
	evs, err := client().EventsFiltered(store.EventFilter{TokenID: *tok, Status: *status}, *limit)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIME\tSTATUS\tCHANNEL\tTOKEN\tSOURCE\tDETAIL")
	for _, e := range evs {
		st := e.Status
		if e.Muted {
			st += " (muted)"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.At.Format(time.RFC3339), st, e.Channel, e.TokenID, e.SourceIP, e.Detail)
	}
	return tw.Flush()
}

func plantCmd(args []string) error {
	if len(args) < 1 {
		usage()
		return fmt.Errorf("plant needs a target: repo, corpus or mcp")
	}
	target := args[0]
	fs := flag.NewFlagSet("plant "+target, flag.ExitOnError)
	dry := fs.Bool("dry-run", false, "print what would be written; mint and write nothing")
	manifest := fs.String("manifest", "snare-planted.json", "manifest file (must be outside the planted directory)")
	withInstr := fs.Bool("with-instruction", false, "corpus: also add a canary instruction (opt-in)")
	config := fs.String("config", "", "mcp: path for the decoy-mcp config file")
	name := fs.String("name", "internal-ops", "mcp: server name advertised to clients")
	exclude := fs.String("exclude", "", "mcp: comma-separated decoys to skip (ones overlapping the agent's real job)")
	style := fs.String("style", "snake", "mcp: decoy naming style to match your real tools: snake, camel or kebab")
	seed := fs.String("seed", "", "mcp: seed for per-install decoy names (default: random)")
	namesFile := fs.String("names", "", "mcp: JSON file {catalog_name: {name, description}} of your own decoy names")
	catalogNames := fs.Bool("catalog-names", false, "mcp: use the public catalog names (easy to fingerprint; not recommended)")
	refresh := fs.Bool("refresh", false, "gateway: re-fetch fingerprints for an existing -config")
	_ = fs.Parse(args[1:])
	styleSet := false
	fs.Visit(func(f *flag.Flag) { styleSet = styleSet || f.Name == "style" })
	opts := plant.Options{DryRun: *dry}
	c := client()

	var entries []plant.Entry
	var err error
	switch target {
	case "repo", "corpus":
		if fs.NArg() != 1 {
			return fmt.Errorf("plant %s needs exactly one directory", target)
		}
		dir := fs.Arg(0)
		if err := plant.CheckManifestOutside(*manifest, dir); err != nil {
			return err
		}
		if target == "repo" {
			entries, err = plant.Repo(c, dir, opts)
		} else {
			entries, err = plant.Corpus(c, dir, *withInstr, opts)
		}
	case "mcp":
		var ex []string
		for _, x := range strings.Split(*exclude, ",") {
			if x = strings.TrimSpace(x); x != "" {
				ex = append(ex, x)
			}
		}
		mo := plant.MCPOptions{Options: opts, ConfigPath: *config, ServerName: *name, Exclude: ex}
		if mo.Seed, mo.Overrides, err = nameOptions(*seed, *namesFile); err != nil {
			return err
		}
		if !*catalogNames {
			mo.Style = *style
		}
		mo.Command, _ = os.Executable()
		var snippet string
		entries, snippet, err = plant.MCP(c, mo)
		if err == nil {
			fmt.Println("Add this to your MCP client config (e.g. .mcp.json or claude_desktop_config.json):")
			fmt.Println(snippet)
		}
	case "gateway":
		if *config == "" {
			return errors.New("plant gateway needs -config")
		}
		if *refresh {
			n, err := plant.RefreshGateway(c, *config)
			if err != nil {
				return err
			}
			fmt.Printf("%s: fingerprints refreshed for %d tripwires\n", *config, n)
			return nil
		}
		ex := strings.FieldsFunc(*exclude, func(r rune) bool { return r == ',' || r == ' ' })
		gwo := plant.GatewayOptions{Options: opts, ConfigPath: *config, Exclude: ex, Style: "auto"}
		if styleSet {
			gwo.Style = *style
		}
		if *catalogNames {
			gwo.Style = "catalog"
		}
		if gwo.Seed, gwo.Overrides, err = nameOptions(*seed, *namesFile); err != nil {
			return err
		}
		gwo.Command, _ = os.Executable()
		var snippet string
		entries, snippet, err = plant.Gateway(c, gwo)
		if err == nil {
			fmt.Println("Wrap each real MCP server in your client config like this:")
			fmt.Println(snippet)
		}
	default:
		return fmt.Errorf("unknown plant target %q (want repo, corpus, mcp or gateway)", target)
	}
	if err != nil {
		return err
	}
	if *dry {
		fmt.Println("dry run: nothing minted or written")
		return nil
	}
	for _, e := range entries {
		fmt.Printf("planted %-6s %s  (token %s)\n", e.Type, e.Label, e.TokenID)
	}
	if err := plant.AppendManifest(*manifest, entries); err != nil {
		return fmt.Errorf("planted, but writing manifest failed: %w", err)
	}
	fmt.Printf("manifest: %s (keep it out of the planted repo/corpus)\n", *manifest)
	return nil
}

// nameOptions parses -seed (random when empty) and -names.
func nameOptions(seed, namesFile string) (uint64, map[string]decoys.Override, error) {
	var n uint64
	if seed == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.LittleEndian.Uint64(b[:])
	} else if _, err := fmt.Sscan(seed, &n); err != nil {
		return 0, nil, fmt.Errorf("-seed %q: want an unsigned integer", seed)
	}
	if namesFile == "" {
		return n, nil, nil
	}
	b, err := os.ReadFile(namesFile)
	if err != nil {
		return 0, nil, err
	}
	var ov map[string]decoys.Override
	if err := json.Unmarshal(b, &ov); err != nil {
		return 0, nil, fmt.Errorf("%s: %w", namesFile, err)
	}
	return n, ov, nil
}

// decoysCmd prints decoy names as JSON. The eval harness reads it so names have one source
// of truth (this Go package). -all lists every name the built-in generator can produce.
func decoysCmd(args []string) error {
	fs := flag.NewFlagSet("decoys", flag.ExitOnError)
	all := fs.Bool("all", false, "list every generated name in every style")
	table := fs.Bool("table", false, "print each decoy's name pool (catalog name first) in -style")
	style := fs.String("style", "snake", "naming style: snake, camel or kebab")
	seed := fs.String("seed", "", "seed (default: random)")
	namesFile := fs.String("names", "", "JSON file of operator-defined names")
	screen := fs.Bool("screen", false, "print the decoys as `killtest screen --decoys` input (names as shown)")
	_ = fs.Parse(args)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if *all {
		return enc.Encode(decoys.AllGenerated())
	}
	if *table {
		pools, err := decoys.Pools(*style)
		if err != nil {
			return err
		}
		return enc.Encode(pools)
	}
	n, ov, err := nameOptions(*seed, *namesFile)
	if err != nil {
		return err
	}
	picks, err := decoys.Pick(n, *style, ov)
	if err != nil {
		return err
	}
	type row struct {
		Canonical   string            `json:"canonical"`
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Params      map[string]string `json:"params,omitempty"`
	}
	var out []row
	for _, p := range picks {
		r := row{Canonical: p.Canonical, Name: p.Name, Description: p.Description}
		if *screen {
			// Screen exactly what this install will show: same name, description and arguments.
			t, _ := decoys.Get(p.Canonical)
			r.Params = map[string]string{}
			for _, prm := range t.Params {
				r.Params[prm.Name] = prm.Description
			}
		}
		out = append(out, r)
	}
	return enc.Encode(out)
}

func decoyMCP(args []string) error {
	fs := flag.NewFlagSet("decoy-mcp", flag.ExitOnError)
	config := fs.String("config", "", "decoy-mcp config written by `snare plant mcp`")
	_ = fs.Parse(args)
	cfg, err := mcp.LoadConfig(*config)
	if err != nil {
		return err
	}
	// stdout carries the protocol; logs go to stderr only.
	s := &mcp.Server{Cfg: cfg, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return s.Serve(ctx, os.Stdin, os.Stdout)
}
