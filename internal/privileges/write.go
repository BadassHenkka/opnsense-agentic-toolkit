package privileges

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// Write prints plan for a user who sets up an API user: each privilege with its patterns and
// what else it allows. With verbose, it also lists the endpoints each privilege is for.
func Write(w io.Writer, plan Plan, verbose bool) error {
	var b strings.Builder
	if len(plan.Grants) == 0 && len(plan.Ungranted) == 0 {
		b.WriteString("No privileges needed.\n")
	}
	for _, g := range plan.Grants {
		fmt.Fprintf(&b, "%s\n  patterns:    %s\n", g.Name, strings.Join(g.Patterns, " "))
		if verbose {
			fmt.Fprintf(&b, "  needed for:  %s\n", strings.Join(g.For, " "))
		}
		if len(g.AlsoAllows) == 0 {
			b.WriteString("  also allows: no other endpoint the toolkit calls\n\n")
		} else {
			fmt.Fprintf(&b, "  also allows: %s\n\n", byController(g.AlsoAllows))
		}
	}
	if len(plan.Ungranted) > 0 {
		fmt.Fprintf(&b, "Only \"All pages\" grants: %s\n\n", strings.Join(plan.Ungranted, " "))
	}
	for _, o := range plan.Optional {
		fmt.Fprintf(&b, "Not needed: %s, %s.\n", o.Endpoint, o.Why)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// byController groups endpoints as "module/controller: action action; ...", each action once.
func byController(endpoints []string) string {
	actions := map[string][]string{}
	var order []string
	for _, e := range endpoints {
		parts := strings.SplitN(e, "/", 4)
		if len(parts) < 3 {
			parts = append(parts, "", "")
		}
		ctrl := parts[0] + "/" + parts[1]
		if _, ok := actions[ctrl]; !ok {
			order = append(order, ctrl)
		}
		if !slices.Contains(actions[ctrl], parts[2]) {
			actions[ctrl] = append(actions[ctrl], parts[2])
		}
	}
	var out []string
	for _, c := range order {
		out = append(out, c+": "+strings.Join(actions[c], " "))
	}
	return strings.Join(out, "; ")
}
