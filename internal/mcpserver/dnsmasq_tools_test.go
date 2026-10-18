package mcpserver_test

import (
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestDnsmasqLeaseList(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"dnsmasq"}})
	if out, ok := call(t, cs, "dnsmasq_lease_list", map[string]any{}); !ok || out["total"].(float64) != 0 {
		t.Fatalf("empty list: %v", out)
	}
	fake.Leases = []map[string]string{{"address": "10.0.0.50", "hostname": "printer", "hwaddr": "aa:bb:cc:dd:ee:ff", "if_name": "lan"}}
	out, ok := call(t, cs, "dnsmasq_lease_list", map[string]any{})
	if !ok || out["total"].(float64) != 1 {
		t.Fatalf("list: %v", out)
	}
	if it := out["items"].([]any)[0].(map[string]any); it["hostname"] != "printer" || it["address"] != "10.0.0.50" {
		t.Fatalf("item %v", it)
	}
}
