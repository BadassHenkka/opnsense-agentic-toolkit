package main

import (
	"html"
	"slices"
	"sort"
	"strings"

	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
)

// privilegesMarkdown renders the privileges an API user needs for endpoints, or "" when
// there are none (Terraform actions have no recorded endpoints).
func privilegesMarkdown(endpoints []string) string {
	if len(endpoints) == 0 {
		return ""
	}
	plan := privileges.For(endpoints)
	var b strings.Builder
	b.WriteString("## Privileges\n\nThe API user needs:\n\n")
	for _, g := range plan.Grants {
		b.WriteString("- **" + g.Name + "** (`" + strings.Join(g.Patterns, "`, `") + "`)." + alsoAllows(g) + "\n")
	}
	for _, n := range notNeeded(plan) {
		b.WriteString("\n" + n + "\n")
	}
	return b.String() + "\n"
}

func privilegesHTML(endpoints []string) string {
	if len(endpoints) == 0 {
		return ""
	}
	plan := privileges.For(endpoints)
	var b strings.Builder
	b.WriteString("<h2>Privileges</h2>\n<p>The API user needs:</p>\n<ul>\n")
	for _, g := range plan.Grants {
		b.WriteString("<li><strong>" + html.EscapeString(g.Name) + "</strong> (<code>" +
			html.EscapeString(strings.Join(g.Patterns, "</code>, <code>")) + "</code>)." + html.EscapeString(alsoAllows(g)) + "</li>\n")
	}
	b.WriteString("</ul>\n")
	for _, n := range notNeeded(plan) {
		b.WriteString("<p>" + html.EscapeString(n) + "</p>\n")
	}
	return b.String()
}

// alsoAllows names the endpoints beyond those needed, so a reader sees what the privilege
// gives away, for example the writes behind a read.
func alsoAllows(g privileges.Grant) string {
	if len(g.AlsoAllows) == 0 {
		return ""
	}
	var actions []string
	for _, e := range g.AlsoAllows {
		e = strings.ReplaceAll(e, "/{arg}", "")
		if !slices.Contains(actions, e) {
			actions = append(actions, e)
		}
	}
	return " It also allows " + strings.Join(actions, ", ") + "."
}

func notNeeded(plan privileges.Plan) []string {
	var keys []string
	for e := range plan.Optional {
		keys = append(keys, e)
	}
	sort.Strings(keys)
	var out []string
	for _, e := range keys {
		out = append(out, "It also calls "+e+", "+plan.Optional[e]+", so that call doesn't need a privilege of its own.")
	}
	return out
}
