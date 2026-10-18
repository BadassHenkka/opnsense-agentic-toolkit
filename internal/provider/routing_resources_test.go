package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func gatewayPlan(name, addr string) genGatewayModel {
	p := genGatewayPlan()
	p.Name, p.Address = types.StringValue(name), types.StringValue(addr)
	p.Enabled, p.Monitoring, p.FarGateway = types.BoolValue(true), types.BoolValue(false), types.BoolValue(true)
	return p
}

func TestGatewayAndRouteResources(t *testing.T) {
	fake := opnsensetest.New(t)
	gws := newHarness(t, fake, NewGatewayResource())
	routes := newHarness(t, fake, NewRouteResource())

	var gw genGatewayModel
	gwState, ok := gws.create(gatewayPlan("WG_SITE2", "10.20.0.2"), &gw)
	if !ok {
		t.Fatal("gateway create failed")
	}
	rec, _ := fake.Get("gateway_item", gw.ID.ValueString())
	if rec["disabled"] != "0" || rec["monitor_disable"] != "1" || rec["fargw"] != "1" || rec["interface"] != "opt3" {
		t.Fatalf("gateway stored %v (enabled/monitoring are inverted in OPNsense)", rec)
	}

	plan := genRoutePlan()
	plan.Gateway = gw.Name
	var rt genRouteModel
	rtState, ok := routes.create(plan, &rt)
	if !ok || rt.Gateway.ValueString() != "WG_SITE2" {
		t.Fatalf("route create: %+v", rt)
	}
	if fake.Applies["routes/routes/reconfigure"] != 2 {
		t.Fatalf("applies = %v", fake.Applies)
	}
	if imp, ok := routes.importID("192.168.50.0/24"); !ok || imp != rt.ID.ValueString() {
		t.Fatalf("import route by network = %q", imp)
	}
	if imp, ok := gws.importID("WG_SITE2"); !ok || imp != gw.ID.ValueString() {
		t.Fatalf("import gateway by name = %q", imp)
	}

	// Change the remote network.
	plan.ID, plan.Network = rt.ID, types.StringValue("192.168.51.0/24")
	rtState = routes.update(rtState, plan, &rt)
	if r, _ := fake.Get("route", rt.ID.ValueString()); r["network"] != "192.168.51.0/24" {
		t.Fatalf("route after update %v", r)
	}

	// Destroying the gateway before the route fails with OPNsense's own message.
	resp := gws.deleteResp(gwState)
	if !resp.HasError() || !strings.Contains(resp.Errors()[0].Detail(), "in use on Static Route") {
		t.Fatalf("delete in-use gateway: %v", resp)
	}
	routes.delete(rtState)
	gws.delete(gwState)

	bad := plan
	bad.Network = types.StringValue("192.168.50.0")
	if !routes.validateStrings(bad).HasError() {
		t.Fatal("network without prefix length should fail validation")
	}
}
