// Package advise is the placement advisor (docs/M4b-hardening.md §4).
//
// It reads an agent's MCP client configuration and says whether the agent combines the
// three capabilities that make prompt injection damaging: it reads untrusted input, it can
// reach private data, and it has a way to send data out. Where it does, it recommends where
// to put tripwires, in terms of existing `snare plant` commands.
//
// The advisor never connects to a server. Classification is by fixed rules over names,
// commands, package names and URLs, or over tool names and descriptions when a tools/list
// dump is supplied. Those are heuristics, and the report says so.
package advise

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type Capability string

const (
	UntrustedInput Capability = "untrusted_input"
	PrivateData    Capability = "private_data"
	Exfiltration   Capability = "exfiltration"
)

var allCaps = []Capability{UntrustedInput, PrivateData, Exfiltration}

// Server is one entry of an MCP client config (Claude Desktop / Claude Code `mcpServers`,
// or VS Code `servers`).
type Server struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	URL     string            `json:"url,omitempty"`
	Type    string            `json:"type,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

type Config struct {
	MCPServers map[string]Server `json:"mcpServers"`
	Servers    map[string]Server `json:"servers"` // VS Code's key
}

func (c Config) all() map[string]Server {
	out := map[string]Server{}
	for k, v := range c.Servers {
		out[k] = v
	}
	for k, v := range c.MCPServers {
		out[k] = v
	}
	return out
}

// Tool is one entry of a tools/list result.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// LoadConfig reads an MCP client config file.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(c.all()) == 0 {
		return Config{}, fmt.Errorf("%s: no mcpServers or servers entries", path)
	}
	return c, nil
}

// LoadTools reads a tools dump: {"server name": [tools...]} or {"server name": {"tools": [...]}}
// (the second is the raw tools/list result).
func LoadTools(path string) (map[string][]Tool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string][]Tool{}
	for name, msg := range raw {
		var list []Tool
		if err := json.Unmarshal(msg, &list); err != nil {
			var wrapped struct {
				Tools []Tool `json:"tools"`
			}
			if err2 := json.Unmarshal(msg, &wrapped); err2 != nil {
				return nil, fmt.Errorf("%s: server %q: want a tool list or a tools/list result", path, name)
			}
			list = wrapped.Tools
		}
		out[name] = list
	}
	return out, nil
}

// ------------------------------------------------------------------ classification rules

type serverRule struct {
	kind     string // what this kind of server is, for the report
	keywords []string
	caps     []Capability
}

// Matched against whole tokens of the server's name, command, args and URL, so "fs" never
// matches inside "offset". Order matters only for the reported kind.
var serverRules = []serverRule{
	{"snare decoy server", []string{"decoy-mcp"}, nil},
	{"email", []string{"gmail", "email", "imap", "outlook", "mail", "smtp", "mailgun", "sendgrid"}, []Capability{UntrustedInput, Exfiltration}},
	{"chat", []string{"slack", "discord", "teams", "telegram", "mattermost", "whatsapp"}, []Capability{UntrustedInput, Exfiltration}},
	{"code host", []string{"github", "gitlab", "bitbucket", "gitea"}, []Capability{UntrustedInput, PrivateData, Exfiltration}},
	{"ticketing / support", []string{"jira", "linear", "zendesk", "intercom", "freshdesk", "servicenow", "helpscout", "asana", "trello"}, []Capability{UntrustedInput, PrivateData}},
	{"web access", []string{"fetch", "browser", "puppeteer", "playwright", "web", "brave", "tavily", "exa", "firecrawl", "crawl", "scrape", "http", "curl", "search"}, []Capability{UntrustedInput, Exfiltration}},
	{"filesystem", []string{"filesystem", "fs", "files", "desktop-commander"}, []Capability{PrivateData}},
	{"database", []string{"postgres", "postgresql", "mysql", "sqlite", "mongo", "mongodb", "redis", "bigquery", "snowflake", "supabase", "database", "db", "sql", "clickhouse", "dynamodb"}, []Capability{PrivateData}},
	{"documents / knowledge base", []string{"gdrive", "drive", "dropbox", "box", "onedrive", "sharepoint", "notion", "confluence", "obsidian", "wiki", "docs", "rag", "vector", "pinecone", "qdrant", "weaviate", "chroma"}, []Capability{PrivateData, UntrustedInput}},
	{"business records", []string{"salesforce", "hubspot", "stripe", "crm", "shopify", "quickbooks", "xero"}, []Capability{PrivateData}},
	{"secrets / cloud control", []string{"vault", "1password", "secrets", "aws", "gcp", "azure", "kubernetes", "k8s", "terraform", "cloudflare"}, []Capability{PrivateData, Exfiltration}},
	{"local utility", []string{"memory", "sequential-thinking", "sequentialthinking", "time", "calculator", "everything"}, nil},
}

type toolRule struct {
	cap   Capability
	words []string
}

// Tool rules look at tool names (split on _ - and case) and descriptions.
var toolRules = []toolRule{
	{Exfiltration, []string{"send", "post", "reply", "forward", "upload", "publish", "share", "comment", "create_issue", "create_pull_request", "webhook", "http_request", "request", "fetch", "navigate", "email", "message", "invite", "push", "gist"}},
	{UntrustedInput, []string{"inbox", "email", "emails", "messages", "message", "ticket", "tickets", "issue", "issues", "comments", "fetch", "browse", "navigate", "search_web", "web", "url", "page", "scrape", "rss", "feed", "chat"}},
	{PrivateData, []string{"read_file", "file", "files", "directory", "query", "sql", "database", "table", "records", "customer", "customers", "account", "accounts", "invoice", "secret", "secrets", "credential", "credentials", "document", "documents", "repository", "repo", "drive", "payroll", "employee", "patient"}},
}

func tokens(s string) []string {
	s = strings.ToLower(s)
	return strings.FieldsFunc(s, func(r rune) bool { return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') })
}

// tokenSet also adds the dash-separated parts, so "server-github" yields "github" and
// "sequential-thinking" survives as one token.
func tokenSet(parts ...string) map[string]bool {
	set := map[string]bool{}
	for _, p := range parts {
		for _, t := range tokens(p) {
			set[t] = true
			for _, sub := range strings.Split(t, "-") {
				if sub != "" {
					set[sub] = true
				}
			}
		}
	}
	return set
}

// ------------------------------------------------------------------ report

type ServerReport struct {
	Name         string       `json:"name"`
	Kind         string       `json:"kind"`
	Capabilities []Capability `json:"capabilities"`
	Evidence     []string     `json:"evidence"`
	From         string       `json:"classified_from"` // "config" or "tools"
	Unknown      bool         `json:"unknown,omitempty"`
	Decoy        bool         `json:"snare_decoy,omitempty"`
	Paths        []string     `json:"paths,omitempty"` // filesystem roots seen in args
}

type Recommendation struct {
	Why     string `json:"why"`
	Action  string `json:"action"`
	Command string `json:"command,omitempty"`
}

type Report struct {
	Servers         []ServerReport          `json:"servers"`
	Legs            map[Capability][]string `json:"legs"` // capability -> servers providing it
	Trifecta        bool                    `json:"trifecta"`
	Risk            string                  `json:"risk"` // high, medium, low
	HasDecoys       bool                    `json:"has_snare_decoys"`
	Recommendations []Recommendation        `json:"recommendations"`
	Caveat          string                  `json:"caveat"`
}

const caveat = "Classified from names, commands, URLs and tool descriptions, not from what the servers actually do. Check each server's real permissions before relying on this."

func classifyServer(name string, s Server, tools []Tool) ServerReport {
	r := ServerReport{Name: name, From: "config"}
	// Directory arguments are data, not identity: a filesystem root called "docs" must not
	// make the server look like a knowledge base.
	paths := pathArgs(s.Args)
	isPath := map[string]bool{}
	for _, p := range paths {
		isPath[p] = true
	}
	ident := []string{name, s.Command, s.URL}
	for _, a := range s.Args {
		if !isPath[a] {
			ident = append(ident, a)
		}
	}
	set := tokenSet(ident...)
	caps := map[Capability]bool{}
	kinds := map[string]bool{}
	for _, rule := range serverRules {
		for _, k := range rule.keywords {
			if !set[k] {
				continue
			}
			if r.Kind == "" {
				r.Kind = rule.kind
			}
			kinds[rule.kind] = true
			if rule.kind == "snare decoy server" {
				r.Decoy = true
			}
			for _, c := range rule.caps {
				caps[c] = true
			}
			r.Evidence = append(r.Evidence, fmt.Sprintf("%q suggests %s", k, rule.kind))
			break
		}
	}
	if kinds["filesystem"] {
		r.Paths = paths
	}
	if len(tools) > 0 && !r.Decoy {
		// A tools dump is better evidence than a name: it replaces the name-based guess.
		caps = map[Capability]bool{}
		r.Evidence = nil
		r.From = "tools"
		for _, t := range tools {
			nameSet := tokenSet(strings.ReplaceAll(t.Name, "_", " "), t.Description)
			nameSet[strings.ToLower(t.Name)] = true
			for _, rule := range toolRules {
				for _, w := range rule.words {
					if nameSet[w] {
						if !caps[rule.cap] {
							r.Evidence = append(r.Evidence, fmt.Sprintf("tool %s: %q suggests %s", t.Name, w, rule.cap))
						}
						caps[rule.cap] = true
						break
					}
				}
			}
		}
		if r.Kind == "" {
			r.Kind = "classified from its tools"
		}
	}
	for _, c := range allCaps {
		if caps[c] {
			r.Capabilities = append(r.Capabilities, c)
		}
	}
	if r.Kind == "" {
		r.Kind = "unknown"
		r.Unknown = true
		r.Evidence = append(r.Evidence, "no rule matched; supply a tools/list dump with -tools to classify it")
	}
	if r.Capabilities == nil {
		r.Capabilities = []Capability{}
	}
	return r
}

// pathArgs returns arguments that look like directories handed to a filesystem server.
func pathArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "@") || strings.Contains(a, "server-filesystem") {
			continue
		}
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~") || strings.HasPrefix(a, ".") ||
			filepath.IsAbs(a) || (len(a) > 2 && a[1] == ':') {
			out = append(out, a)
		}
	}
	return out
}

// Analyze classifies every server and builds recommendations. tools may be nil.
func Analyze(cfg Config, tools map[string][]Tool) Report {
	servers := cfg.all()
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)

	rep := Report{Legs: map[Capability][]string{}, Caveat: caveat}
	for _, n := range names {
		sr := classifyServer(n, servers[n], tools[n])
		rep.Servers = append(rep.Servers, sr)
		if sr.Decoy {
			rep.HasDecoys = true
			continue // a decoy server's tools are traps, not capabilities
		}
		for _, c := range sr.Capabilities {
			rep.Legs[c] = append(rep.Legs[c], n)
		}
	}
	legs := 0
	for _, c := range allCaps {
		if len(rep.Legs[c]) > 0 {
			legs++
		}
	}
	rep.Trifecta = legs == 3
	switch {
	case rep.Trifecta:
		rep.Risk = "high"
	case legs == 2:
		rep.Risk = "medium"
	default:
		rep.Risk = "low"
	}
	rep.Recommendations = recommend(rep)
	return rep
}

func recommend(rep Report) []Recommendation {
	var out []Recommendation
	add := func(why, action, cmd string) { out = append(out, Recommendation{why, action, cmd}) }
	join := func(c Capability) string { return strings.Join(rep.Legs[c], ", ") }

	if rep.Trifecta {
		add(fmt.Sprintf("Untrusted input (%s) can steer the agent to private data (%s) and send it out (%s).",
			join(UntrustedInput), join(PrivateData), join(Exfiltration)),
			"This agent is the one where a successful injection does damage. Put tripwires on every path below, and treat any touch as an incident.", "")
	}
	if len(rep.Legs[PrivateData]) > 0 && !rep.HasDecoys && rep.Risk != "low" {
		add("A steered agent looks for data first. Decoy tools named for this agent's private-data domain sit right on that path.",
			"Add the decoy MCP server. Screen the decoy names against this agent's real tools before deploying.",
			"snare plant mcp -config decoy-mcp.json   # then: killtest screen (docs/M2-tripwire-kit.md)")
	}
	for _, s := range rep.Servers {
		for _, p := range s.Paths {
			add(fmt.Sprintf("%s exposes %s to the agent.", s.Name, p),
				"Plant honey credentials there. A stolen key used anywhere fires an alert that names this file.",
				"snare plant repo "+shellQuote(p))
		}
		if s.Kind == "documents / knowledge base" {
			add(fmt.Sprintf("%s is a knowledge source the agent reads and searches.", s.Name),
				"Plant canary documents (a break-glass runbook with a honey link and credentials) in it, or in the folder it is exported from.",
				"snare plant corpus <kb-export-dir>")
		}
		if s.Kind == "database" || s.Kind == "business records" {
			add(fmt.Sprintf("%s holds records the agent can query.", s.Name),
				"Insert a canary record whose fields carry a honey credential or canary URL (mint one per record so the alert names it).",
				"snare mint -kind honey_credential -label \""+s.Name+": canary record\"")
		}
	}
	if rep.Risk != "low" {
		// Seed into a source you can write an item into (a queue or inbox), not the open web.
		seedable := map[string]bool{"email": true, "chat": true, "ticketing / support": true, "code host": true, "documents / knowledge base": true}
		for _, s := range rep.Servers {
			if s.Decoy || !seedable[s.Kind] {
				continue
			}
			add(fmt.Sprintf("Outsiders can put content in front of the agent through %s.", s.Name),
				"Seed one item there (a ticket, email or message carrying a canary URL). A touch then also tells you which source the agent was steered from.",
				"snare mint -kind canary_url -label \"seeded item in "+s.Name+"\"")
			break
		}
	}
	for _, n := range rep.Legs[Exfiltration] {
		for _, s := range rep.Servers {
			if s.Name == n && s.Kind == "web access" {
				add(n+" can make outbound requests.",
					"Run the DNS listener (SNARE_ZONE) so canary hostnames fire even where HTTP egress is filtered: resolvers leak lookups.",
					"")
			}
		}
	}
	for _, s := range rep.Servers {
		if s.Unknown {
			add(s.Name+" could not be classified.",
				"Dump its tools (tools/list) into a JSON file and rerun with -tools, or review its permissions by hand.", "")
		}
	}
	if rep.Risk == "low" {
		add("The agent does not combine untrusted input, private data and a way out.",
			"Tripwires add little here. Re-run this when the agent gains a tool.", "")
	}
	return out
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " '\"$`\\") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
