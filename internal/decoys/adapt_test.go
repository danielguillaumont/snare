package decoys

import (
	"reflect"
	"strings"
	"testing"
)

func TestVerbClassesAreDisjoint(t *testing.T) {
	seen := map[string]string{}
	for c, vs := range VerbClasses {
		for _, v := range vs {
			if prev, ok := seen[v]; ok {
				t.Errorf("verb %q in both %s and %s", v, prev, c)
			}
			seen[v] = c
		}
	}
}

func TestWords(t *testing.T) {
	for in, want := range map[string]string{
		"jira_get_issue":    "jira get issue",
		"getIssueComments":  "get issue comments",
		"list-projects":     "list projects",
		"fetchAPIKeys":      "fetch api keys",
		"query_vault_v2":    "query vault v2",
		"S3BucketMirror":    "s3 bucket mirror",
		"read":              "read",
		"github.list_repos": "github list repos",
	} {
		if got := strings.Join(Words(in), " "); got != want {
			t.Errorf("Words(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNamespaceOf(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"jira_get_issue", "jira_list_projects", "jira_search", "server_info"}, "jira"},
		{[]string{"get_issue", "get_user", "list_projects"}, ""},           // "get" is a verb
		{[]string{"jira_get_issue", "list_projects", "search", "x_y"}, ""}, // 1 of 4: too few
		{[]string{"slackPostMessage", "slackListChannels"}, "slack"},
		{[]string{"jira"}, ""},
	}
	for _, c := range cases {
		if got := NamespaceOf(c.names); got != c.want {
			t.Errorf("NamespaceOf(%v) = %q, want %q", c.names, got, c.want)
		}
	}
}

func TestLearn(t *testing.T) {
	v := Learn([]RealTool{
		{Name: "jiraFetchIssue", Description: "Fetch one issue", Params: []string{"issueKey"}},
		{Name: "jiraFetchProject", Description: "Fetch a project", Params: []string{"projectKey"}},
		{Name: "jiraSearchIssues", Description: "Search issues with JQL", Params: []string{"jql"}},
		{Name: "jiraListBoards", Description: "List boards.", Params: nil},
	})
	want := Vocabulary{Style: "camel", Namespace: "jira", ParamStyle: "camel", Period: false,
		Verbs: map[string]string{"read": "fetch", "query": "search", "list": "list"}}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("Learn = %+v\nwant   %+v", v, want)
	}
	// No descriptions: keep the catalog's punctuation. No tools: snake, no namespace.
	if v := Learn(nil); v.Style != "snake" || v.Namespace != "" || !v.Period || v.ParamStyle != "snake" {
		t.Errorf("empty Learn = %+v", v)
	}
}

func byCanon(cs []Choice) map[string]Choice {
	m := map[string]Choice{}
	for _, c := range cs {
		m[c.Canonical] = c
	}
	return m
}

func TestAdaptRewritesInTheServersVocabulary(t *testing.T) {
	v := Vocabulary{Style: "camel", Namespace: "jira", ParamStyle: "camel", Period: false,
		Verbs: map[string]string{"read": "fetch", "list": "show", "export": "download"}}
	for seed := uint64(1); seed <= 40; seed++ {
		got, err := Adapt(v, seed, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		base, _ := Pick(seed, "snake", nil)
		if len(got) != len(Catalog) {
			t.Fatalf("%d choices", len(got))
		}
		seen := map[string]bool{}
		for i, c := range got {
			if seen[c.Name] {
				t.Fatalf("seed %d: duplicate %q", seed, c.Name)
			}
			seen[c.Name] = true
			if !strings.HasPrefix(c.Name, "jira") || strings.Contains(c.Name, "_") {
				t.Errorf("seed %d: %q not in the server's namespace and style", seed, c.Name)
			}
			if strings.HasSuffix(c.Description, ".") {
				t.Errorf("%q: description keeps its period", c.Name)
			}
			// The verb is replaced within its class only.
			bw, aw := strings.Split(base[i].Name, "_"), Words(c.Name)[1:]
			if cls := VerbClassOf(bw[0]); cls != "" && v.Verbs[cls] != "" {
				if aw[0] != v.Verbs[cls] {
					t.Errorf("%s -> %s: verb not the server's %s", base[i].Name, c.Name, v.Verbs[cls])
				}
			} else if aw[0] != bw[0] {
				t.Errorf("%s -> %s: unclassed verb changed", base[i].Name, c.Name)
			}
			cat, _ := Get(c.Canonical)
			if len(c.Params) != len(cat.Params) {
				t.Fatalf("%s: params %v", c.Name, c.Params)
			}
			for j, p := range c.Params {
				if p.Name != Styled(cat.Params[j].Name, "camel") || p.Description != cat.Params[j].Description {
					t.Errorf("%s: param %+v", c.Name, p)
				}
			}
		}
	}
	// read_env_secrets' whole pool starts with a read-class verb, so any seed shows "fetch".
	got, _ := Adapt(v, 7, nil, nil)
	if n := byCanon(got)["read_env_secrets"].Name; !strings.HasPrefix(n, "jiraFetch") {
		t.Errorf("read_env_secrets -> %q", n)
	}
}

func TestAdaptFallsBackOnCollisionAndKeepsOverrides(t *testing.T) {
	v := Vocabulary{Style: "snake", Verbs: map[string]string{"read": "get"}}
	base := byCanon(mustPick(t, 3))
	stem := base["get_admin_credentials"].Name // e.g. fetch_admin_credentials
	adapted := "get_" + strings.SplitN(stem, "_", 2)[1]
	if VerbClassOf(strings.Split(stem, "_")[0]) != "read" {
		t.Skip("seed 3 picked a stem without a read verb")
	}
	got := byCanon(must(Adapt(v, 3, nil, map[string]bool{adapted: true})))
	if n := got["get_admin_credentials"].Name; n == adapted {
		t.Errorf("collided with a real tool: %q", n)
	} else if n != stem {
		t.Errorf("fallback = %q, want the unadapted %q", n, stem)
	}
	ov := map[string]Override{"list_api_keys": {Name: "partner_gateway_keys", Description: "Mine."}}
	got = byCanon(must(Adapt(Vocabulary{Style: "camel", Namespace: "jira", Verbs: map[string]string{"list": "show"}}, 3, ov, nil)))
	if c := got["list_api_keys"]; c.Name != "partner_gateway_keys" || c.Description != "Mine." || !c.Custom {
		t.Errorf("override not verbatim: %+v", c)
	}
}

func mustPick(t *testing.T, seed uint64) []Choice {
	cs, err := Pick(seed, "snake", nil)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func must(cs []Choice, err error) []Choice {
	if err != nil {
		panic(err)
	}
	return cs
}

func TestAdaptSpaceCoversEveryStem(t *testing.T) {
	s := AdaptSpace()
	n := 0
	for _, t := range Catalog {
		n += 1 + len(Alternatives[t.Name])
	}
	if len(s.Stems) != n {
		t.Fatalf("%d stems, want %d", len(s.Stems), n)
	}
	if !reflect.DeepEqual(s.VerbClasses, VerbClasses) {
		t.Error("verb classes differ")
	}
}
