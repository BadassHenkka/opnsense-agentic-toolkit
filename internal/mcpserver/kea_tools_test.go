package mcpserver_test

import (
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestKeaLeaseList(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"kea"}})
	if out, ok := call(t, cs, "kea_lease4_list", map[string]any{}); !ok || out["total"].(float64) != 0 {
		t.Fatalf("empty list: %v", out)
	}
	fake.KeaLeases4 = []map[string]string{{"address": "10.0.0.60", "hwaddr": "aa:bb:cc:dd:ee:01", "hostname": "tv"}}
	out, ok := call(t, cs, "kea_lease4_list", map[string]any{})
	if !ok || out["total"].(float64) != 1 || out["items"].([]any)[0].(map[string]any)["hostname"] != "tv" {
		t.Fatalf("list: %v", out)
	}
	if out, ok := call(t, cs, "kea_lease6_list", map[string]any{}); !ok || out["total"].(float64) != 0 {
		t.Fatalf("v6 list: %v", out)
	}
}
