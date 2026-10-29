// Package privileges finds the OPNsense privileges an API user needs for a set of MCP tools
// or Terraform resources, from two sources: the ACL.xml files of OPNsense (zz_gen_acl.go,
// pinned with the models) and the endpoints each tool and resource calls (endpoints/*.json,
// recorded by the tests against the fake).
package privileges

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Privilege is one entry of an ACL.xml file, with its API patterns.
type Privilege struct {
	// Key is the element name, e.g. page-firewall-aliases; Name is what the web UI shows.
	Key, Name string
	// Source is the ACL.xml file below gen/models.
	Source   string
	Patterns []string
}

// Grants reports whether the privilege allows endpoint (a path below /api/).
func (p Privilege) Grants(endpoint string) bool {
	for _, pat := range p.Patterns {
		if urlMatch("/api/"+strings.ReplaceAll(endpoint, "{arg}", "x"), pat) {
			return true
		}
	}
	return false
}

var (
	patternCache   = map[string]*regexp.Regexp{}
	trailingMarker = regexp.MustCompile(`([/&?])\.\*$`)
)

// urlMatch is ACL::urlMatch of OPNsense core: "*" is a wildcard, and a pattern that ends in
// "/*", "&*" or "?*" also matches the URL without that part.
func urlMatch(url, pattern string) bool {
	re, ok := patternCache[pattern]
	if !ok {
		parts := strings.Split(pattern, "*")
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		m := trailingMarker.ReplaceAllString(strings.Join(parts, ".*"), "($1.*)?")
		re = regexp.MustCompile("^/" + m + "$")
		patternCache[pattern] = re
	}
	url, _, _ = strings.Cut(url, "#")
	return re.MatchString(url)
}

// All returns every privilege with API patterns.
func All() []Privilege { return acl }

//go:embed endpoints/mcp.json
var mcpJSON []byte

//go:embed endpoints/terraform.json
var terraformJSON []byte

var mcpEndpoints, terraformEndpoints = mustLoad(mcpJSON), mustLoad(terraformJSON)

func mustLoad(b []byte) map[string][]string {
	var m map[string][]string
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}

// ToolEndpoints returns the endpoints an MCP tool calls; ResourceEndpoints those of a
// Terraform resource type.
func ToolEndpoints(tool string) []string    { return mcpEndpoints[tool] }
func ResourceEndpoints(typ string) []string { return terraformEndpoints[typ] }

// known lists every endpoint any tool or resource calls.
func known() []string {
	set := map[string]bool{}
	for _, m := range []map[string][]string{mcpEndpoints, terraformEndpoints} {
		for _, eps := range m {
			for _, e := range eps {
				set[e] = true
			}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
