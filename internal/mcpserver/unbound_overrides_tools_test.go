package mcpserver_test

import (
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestUnboundToolsFlow(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"unbound"}})

	out, ok := call(t, cs, "unbound_host_override_create", map[string]any{
		"hostname": "nas", "domain": "home.lan", "server": "10.0.10.6",
	})
	if !ok {
		t.Fatalf("create A: %v", out)
	}
	aID := out["uuid"].(string)
	if rec, _ := fake.Get("host", aID); rec["rr"] != "A" || rec["addptr"] != "1" || rec["enabled"] != "1" {
		t.Fatalf("defaults not applied: %v", rec)
	}
	if out, ok = call(t, cs, "unbound_host_override_create", map[string]any{
		"hostname": "nas", "domain": "home.lan", "type": "AAAA", "server": "fd00::6",
	}); !ok {
		t.Fatalf("create AAAA: %v", out)
	}

	// The name alone is ambiguous now.
	out, ok = call(t, cs, "unbound_host_override_get", map[string]any{"name": "nas.home.lan"})
	if ok || !strings.Contains(out["error"].(string), "several") {
		t.Fatalf("ambiguous get: %v", out)
	}

	out, ok = call(t, cs, "unbound_host_alias_create", map[string]any{
		"host": map[string]any{"name": "nas.home.lan", "type": "A"}, "hostname": "truenas",
		"domain": "home.lan",
	})
	if !ok {
		t.Fatalf("alias create: %v", out)
	}
	aliasID := out["uuid"].(string)
	if rec, _ := fake.Get("alias", aliasID); rec["host"] != aID {
		t.Fatalf("alias points at %q, want %q", rec["host"], aID)
	}
	if out, ok := call(t, cs, "unbound_host_alias_get", map[string]any{"name": "truenas.home.lan"}); !ok ||
		out["uuid"] != aliasID || out["host_uuid"] != aID || out["hostname"] != "truenas" {
		t.Fatalf("alias get: %v", out)
	}

	out, ok = call(t, cs, "unbound_host_override_get", map[string]any{"name": "nas.home.lan", "type": "A"})
	if !ok || out["uuid"] != aID || len(out["aliases"].([]any)) != 1 {
		t.Fatalf("get with aliases: %v", out)
	}

	if out, ok = call(t, cs, "unbound_host_override_update", map[string]any{
		"uuid": aID, "server": "10.0.10.7", "ttl": 300,
	}); !ok {
		t.Fatalf("update: %v", out)
	}
	if rec, _ := fake.Get("host", aID); rec["server"] != "10.0.10.7" || rec["ttl"] != "300" || rec["hostname"] != "nas" {
		t.Fatalf("after update: %v", rec)
	}
	if _, ok := call(t, cs, "unbound_host_override_update", map[string]any{"uuid": aID, "clear_ttl": true}); !ok {
		t.Fatal("clear ttl failed")
	}
	if rec, _ := fake.Get("host", aID); rec["ttl"] != "" {
		t.Fatalf("ttl not cleared: %v", rec)
	}

	out, ok = call(t, cs, "unbound_host_alias_list", map[string]any{"host_uuid": aID})
	if !ok || out["total"].(float64) != 1 {
		t.Fatalf("alias list: %v", out)
	}
	if out, ok = call(t, cs, "unbound_host_alias_update", map[string]any{"name": "truenas.home.lan", "description": "web UI"}); !ok {
		t.Fatalf("alias update: %v", out)
	}

	if _, ok := call(t, cs, "unbound_apply", map[string]any{}); !ok || fake.Applies["unbound/service/reconfigure"] != 1 {
		t.Fatal("apply did not reconfigure unbound")
	}

	if out, ok = call(t, cs, "unbound_host_override_delete", map[string]any{"uuid": aID}); !ok {
		t.Fatalf("delete: %v", out)
	}
	if _, exists := fake.Get("alias", aliasID); exists {
		t.Fatal("alias should be deleted with its host override")
	}
}

func TestUnboundToolValidation(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{Toolsets: []string{"unbound"}})
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"unbound_host_override_create", map[string]any{"domain": "home.lan"}, "needs server"},
		{"unbound_host_override_create", map[string]any{"domain": "home.lan", "type": "MX", "mx": "mail"}, "mx_priority"},
		{"unbound_host_override_create", map[string]any{"domain": "home.lan", "type": "TXT"}, "txt_data"},
		{"unbound_host_override_get", map[string]any{"name": "missing.lan"}, "no host override"},
		{"unbound_host_alias_create", map[string]any{"host": map[string]any{"name": "missing.lan"}, "hostname": "x"}, "host:"},
	} {
		out, ok := call(t, cs, tc.tool, tc.args)
		if ok || !strings.Contains(out["error"].(string), tc.want) {
			t.Errorf("%s %v: want error containing %q, got %v", tc.tool, tc.args, tc.want, out)
		}
	}
}
