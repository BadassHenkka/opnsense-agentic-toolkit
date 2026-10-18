package mcpserver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestWolTools(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"wol"}})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	// Interface by description (LAN → lan); MAC in Windows notation.
	must("wol_host_create", map[string]any{"description": "gaming-pc", "interface": "LAN", "mac": "00-11-22-33-44-55"})
	if rec, _ := fake.Get("host", must("wol_host_list", map[string]any{})["items"].([]any)[0].(map[string]any)["uuid"].(string)); rec["mac"] != "00:11:22:33:44:55" || rec["interface"] != "lan" {
		t.Fatalf("stored %v", rec)
	}
	if out, ok := call(t, cs, "wol_host_create", map[string]any{"description": "dup", "interface": "lan", "mac": "00:11:22:33:44:55"}); ok ||
		!strings.Contains(out["error"].(string), "already saved") {
		t.Fatalf("duplicate MAC: %v", out)
	}

	if out := must("wol_wake", map[string]any{"host": map[string]any{"name": "gaming-pc"}}); out["sent"] != true {
		t.Fatalf("wake by name: %v", out)
	}
	must("wol_wake", map[string]any{"mac": "00:11:22:33:44:55"})                          // saved MAC, no interface needed
	must("wol_wake", map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "interface": "WG_SITE2"}) // unsaved MAC
	if got := fake.Wakes(); !slices.Equal(got, []string{"lan 00:11:22:33:44:55", "lan 00:11:22:33:44:55", "opt3 aa:bb:cc:dd:ee:ff"}) {
		t.Fatalf("wakes %v", got)
	}

	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"mac": "aa:bb:cc:dd:ee:00"}, "give the interface"},
		{map[string]any{"mac": "aa:bb:cc:dd:ee:00", "interface": "wan"}, "Incorrect IPv4"},
		{map[string]any{"host": map[string]any{"name": "nope"}}, "no Wake on LAN host named"},
		{map[string]any{}, "give host"},
	} {
		out, ok := call(t, cs, "wol_wake", tc.args)
		if ok || !strings.Contains(out["error"].(string), tc.want) {
			t.Errorf("%v: want %q, got %v", tc.args, tc.want, out)
		}
	}

	if out := must("wol_wake_all", map[string]any{}); len(out["results"].([]any)) != 1 {
		t.Fatalf("wake all: %v", out)
	}
	must("wol_host_update", map[string]any{"name": "gaming-pc", "new_description": "desktop"})
	must("wol_host_delete", map[string]any{"name": "desktop"})
	if out := must("wol_host_list", map[string]any{}); out["total"].(float64) != 0 {
		t.Fatalf("after delete: %v", out)
	}
}
