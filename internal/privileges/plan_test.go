package privileges

import (
	"slices"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

func names(p Plan) string {
	var n []string
	for _, g := range p.Grants {
		n = append(n, g.Name)
	}
	return strings.Join(n, ", ")
}

func TestURLMatch(t *testing.T) {
	for _, tc := range []struct {
		url, pattern string
		want         bool
	}{
		{"/api/firewall/alias/searchItem", "api/firewall/alias/search*", true},
		{"/api/firewall/alias/setItem/x", "api/firewall/alias/search*", false},
		{"/api/firewall/alias", "api/firewall/alias/*", true}, // a trailing /* also matches the flat URL
		{"/api/firewall/aliasx", "api/firewall/alias/*", false},
		{"/api/firewall/alias/export", "api/firewall/alias/export", true},
		{"/api/firewall/alias/export/x", "api/firewall/alias/export", false},
		{"/api/core/firmware/info", "api/core/firmware.info", false}, // "." is literal
	} {
		if got := urlMatch(tc.url, tc.pattern); got != tc.want {
			t.Errorf("urlMatch(%q, %q) = %v", tc.url, tc.pattern, got)
		}
	}
}

func TestFor(t *testing.T) {
	// Reading aliases needs only the read privilege, not the edit one.
	if got := names(For(ToolEndpoints("firewall_alias_list"))); got != "Firewall: Aliases" {
		t.Errorf("alias list: %s", got)
	}
	if got := names(For(ResourceEndpoints("opnsense_firewall_alias"))); got != "Firewall: Alias: Edit" {
		t.Errorf("alias resource: %s", got)
	}
	p := For(ResourceEndpoints("opnsense_wireguard_peer"))
	if len(p.Grants) == 0 || len(p.Ungranted) > 0 {
		t.Fatalf("wireguard peer: %+v", p)
	}
	for _, g := range For([]string{"firewall/alias/searchItem"}).Grants {
		if !slices.Contains(g.AlsoAllows, "firewall/alias/getItem/{arg}") {
			t.Errorf("%s: also allows %v", g.Name, g.AlsoAllows)
		}
	}
}

// Every endpoint of every tool and resource has a privilege other than "All pages".
func TestEveryEndpointHasAPrivilege(t *testing.T) {
	if p := For(known()); len(p.Ungranted) > 0 {
		t.Errorf("no privilege grants %v", p.Ungranted)
	}
}

// The privilege --check names for a denied probe must be the one OPNsense calls it.
func TestProbePrivileges(t *testing.T) {
	for _, p := range opnsense.Probes() {
		if got := names(For([]string{p.Path})); got != p.Privilege {
			t.Errorf("%s: --check says %q, the ACL gives %q", p.Path, p.Privilege, got)
		}
	}
}

// Recorded endpoints keep arguments as {arg}. No pattern may tell an argument apart, or the
// files would hide a privilege the real call needs.
func TestEndpointArgumentsDoNotMatter(t *testing.T) {
	for _, e := range known() {
		if !strings.Contains(e, "{arg}") {
			continue
		}
		for _, p := range acl {
			for _, pat := range p.Patterns {
				want := urlMatch("/api/"+strings.ReplaceAll(e, "{arg}", "x"), pat)
				for _, arg := range []string{"00000000-0000-4000-8000-000000000001", "os-ddclient", "lan"} {
					if urlMatch("/api/"+strings.ReplaceAll(e, "{arg}", arg), pat) != want {
						t.Errorf("%s: %s pattern %s depends on the argument", e, p.Name, pat)
					}
				}
			}
		}
	}
}
