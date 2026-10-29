package mcpserver_test

import (
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestFirewallRuleTools(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"firewall_rule"}})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	ifs := must("firewall_interface_list", map[string]any{})
	if len(ifs["interfaces"].([]any)) != 4 {
		t.Fatalf("interfaces: %v", ifs)
	}

	// Interfaces by description; created disabled by default.
	out := must("firewall_rule_create", map[string]any{
		"description": "site2 to NAS", "interfaces": []string{"WG_SITE2"}, "protocol": "TCP",
		"source": []string{"opt3"}, "destination": []string{"192.168.1.10"}, "destination_port": "445",
	})
	id := out["uuid"].(string)
	if rec, _ := fake.Get("rule", id); rec["enabled"] != "0" || rec["interface"] != "opt3" || rec["source_net"] != "opt3" {
		t.Fatalf("stored %v", rec)
	}
	if !strings.Contains(out["note"].(string), "DISABLED") {
		t.Fatalf("note: %v", out["note"])
	}
	must("firewall_rule_create", map[string]any{"description": "site2 block non-LAN", "interfaces": []string{"opt3"},
		"action": "block", "destination": []string{"lan"}, "destination_not": true, "enabled": true})

	must("firewall_rule_update", map[string]any{"name": "site2 to NAS", "enabled": true})
	must("firewall_rule_move", map[string]any{"rule": map[string]any{"name": "site2 block non-LAN"},
		"before": map[string]any{"name": "site2 to NAS"}})

	list := must("firewall_rule_list", map[string]any{"interface": "WG_SITE2"})
	if list["total"].(float64) != 5 { // 2 rules + 2 automatic + 1 legacy
		t.Fatalf("list: %v", list)
	}
	// Inversion must show in the list, not only in get: "!lan" listed as "lan" means the opposite.
	inverted := false
	for _, it := range list["items"].([]any) {
		if row := it.(map[string]any); row["description"] == "site2 block non-LAN" {
			inverted = row["destination_net"] == "lan" && row["destination_not"] == "1" && row["source_not"] == "0"
		}
	}
	if !inverted {
		t.Fatalf("inverted rule not listed as inverted: %v", list)
	}
	got := must("firewall_rule_get", map[string]any{"name": "site2 to NAS"})
	if got["enabled"] != true || got["destination_port"] != "445" {
		t.Fatalf("get: %v", got)
	}

	if a := must("firewall_rule_apply", map[string]any{}); a["verified"] != true {
		t.Fatalf("apply: %v", a)
	}

	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"description": "x", "interfaces": []string{"opt3"}, "destination_port": "80"}, "ports need protocol"},
		{map[string]any{"description": "x", "interfaces": []string{"nope"}}, `no interface or group "nope"`},
		{map[string]any{"description": " ", "interfaces": []string{"opt3"}}, "description is required"},
		{map[string]any{"description": "x", "interfaces": []string{"opt3"}, "source": []string{"any", "lan"}}, "any cannot be combined"},
	} {
		out, ok := call(t, cs, "firewall_rule_create", tc.args)
		if ok || !strings.Contains(out["error"].(string), tc.want) {
			t.Errorf("%v: want %q, got %v", tc.args, tc.want, out)
		}
	}
	if out, ok := call(t, cs, "firewall_rule_get", map[string]any{"name": "Anti-Lockout Rule"}); ok {
		t.Fatalf("automatic rules must not resolve: %v", out)
	}
}

func TestFirewallRuleApplyLockout(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"firewall_rule"}})
	fake.LockOutAfter = "firewall/filter/apply"
	out, ok := call(t, cs, "firewall_rule_apply", map[string]any{})
	if !ok || out["verified"] != false || !strings.Contains(out["note"].(string), "anti-lockout") {
		t.Fatalf("lockout apply: %v", out)
	}
}
