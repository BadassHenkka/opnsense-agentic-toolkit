package mcpserver_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

// TestDocsToolNames checks that every MCP tool the README and the skill mention exists. Brace
// lists are expanded and * matches any run of name characters.
func TestDocsToolNames(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{})
	tools := toolNames(t, cs)
	tok := regexp.MustCompile("`([a-z0-9_{},*]+_(?:list|get|status|wake|\\{[a-z,]+\\}|\\*))`")
	for _, doc := range []string{"../../README.md", "../../.claude/skills/opnsense-iac/SKILL.md"} {
		src, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range tok.FindAllStringSubmatch(string(src), -1) {
			if strings.HasPrefix(m[1], "opnsense_") {
				continue
			}
			for _, name := range expand(m[1]) {
				rx := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(name), `\*`, "[a-z0-9_]+") + "$")
				found := false
				for _, tl := range tools {
					if rx.MatchString(tl) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s mentions tool %s, which the server does not register", doc, name)
				}
			}
		}
	}
}

func expand(s string) []string {
	i, j := strings.Index(s, "{"), strings.Index(s, "}")
	if i < 0 || j < i {
		return []string{s}
	}
	var out []string
	for _, alt := range strings.Split(s[i+1:j], ",") {
		out = append(out, expand(s[:i]+alt+s[j+1:])...)
	}
	return out
}
