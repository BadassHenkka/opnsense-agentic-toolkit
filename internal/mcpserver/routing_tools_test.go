package mcpserver_test

import (
	"context"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

func TestRoutingToolsFlow(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"routing"}})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	gw := must("routing_gateway_create", map[string]any{"name": "WG_SITE2", "interface": "opt3", "address": "10.20.0.2"})
	if rec, _ := fake.Get("gateway_item", gw["uuid"].(string)); rec["fargw"] != "1" || rec["monitor_disable"] != "1" {
		t.Fatalf("gateway defaults: %v", rec)
	}
	must("routing_route_create", map[string]any{"network": "192.168.50.0/24", "gateway": "WG_SITE2"})

	if out, ok := call(t, cs, "routing_gateway_delete", map[string]any{"name": "WG_SITE2"}); ok ||
		!strings.Contains(out["error"].(string), "in use on Static Route") {
		t.Fatalf("delete in-use gateway: %v", out)
	}
	r := must("routing_route_get", map[string]any{"name": "192.168.50.0/24"})
	if r["gateway"] != "WG_SITE2" {
		t.Fatalf("route: %v", r)
	}
	must("routing_route_update", map[string]any{"network_ref": "192.168.50.0/24", "network": "192.168.51.0/24"})
	must("routing_apply", map[string]any{})
	if st := must("routing_gateway_status", map[string]any{}); len(st["items"].([]any)) != 1 {
		t.Fatalf("status: %v", st)
	}
	must("routing_route_delete", map[string]any{"name": "192.168.51.0/24"})
	must("routing_gateway_delete", map[string]any{"name": "WG_SITE2"})

	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"routing_route_create", map[string]any{"network": "192.168.50.0", "gateway": "WAN_DHCP"}, "CIDR"},
		{"routing_route_create", map[string]any{"network": "192.168.50.0/24", "gateway": "NOPE"}, `no gateway named "NOPE"`},
		{"routing_gateway_create", map[string]any{"name": "X", "interface": "opt3", "address": "vpn.example.com"}, "not an IP"},
	} {
		out, ok := call(t, cs, tc.tool, tc.args)
		if ok || !strings.Contains(out["error"].(string), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.tool, tc.want, out)
		}
	}
}

func TestRoutingGatewayGroupRead(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"routing"}})
	c := fake.Client(t)
	id, err := c.Routing.GatewayGroups.Add(context.Background(), opnsense.GatewayGroup{
		Name: "FAILOVER", Tier1: opnsense.CSVList{"WAN_A"}, Tier2: opnsense.CSVList{"WAN_B"}, Trigger: "down"})
	if err != nil {
		t.Fatal(err)
	}
	if out, ok := call(t, cs, "routing_gateway_group_list", map[string]any{}); !ok || out["total"].(float64) != 1 {
		t.Fatalf("list: %v", out)
	}
	out, ok := call(t, cs, "routing_gateway_group_get", map[string]any{"name": "FAILOVER"})
	if !ok || out["uuid"] != id {
		t.Fatalf("get: %v", out)
	}
	tiers := out["tiers"].([]any)
	if len(tiers) != 5 || tiers[0].([]any)[0] != "WAN_A" || tiers[1].([]any)[0] != "WAN_B" {
		t.Fatalf("tiers %v", tiers)
	}
}
