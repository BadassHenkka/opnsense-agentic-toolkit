package opnsense_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestGatewayAndRoute(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	rt := fake.Client(t).Routing

	gw, err := rt.Gateways.Add(ctx, opnsense.Gateway{
		Name: "WG_SITE2", Interface: "opt3", IPProtocol: "inet", Address: "10.20.0.2",
		FarGateway: true, MonitorDisable: true, Priority: opnsense.IntOf(255), Weight: opnsense.IntOf(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := rt.GatewayByName(ctx, "WG_SITE2"); err != nil || id != gw {
		t.Fatalf("GatewayByName = %q, %v", id, err)
	}
	// Dynamic gateways have no uuid.
	if _, err := rt.GatewayByName(ctx, "WAN_DHCP"); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("dynamic gateway: %v", err)
	}

	route, err := rt.Routes.Add(ctx, opnsense.Route{
		Enabled: true, Network: "192.168.50.0/24", Gateway: "WG_SITE2", Description: "site 2 LAN",
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := rt.Routes.Get(ctx, route)
	if err != nil || r.Gateway != "WG_SITE2" || r.Network != "192.168.50.0/24" {
		t.Fatalf("route = %+v, %v", r, err)
	}
	if id, err := opnsense.ResolveByName(ctx, rt.Routes, "192.168.50.0/24"); err != nil || id != route {
		t.Fatalf("route by network = %q, %v", id, err)
	}

	// A gateway in use cannot be deleted; the UserException message comes through.
	err = rt.Gateways.Delete(ctx, gw)
	if err == nil || !strings.Contains(err.Error(), "in use on Static Route") {
		t.Fatalf("delete in-use gateway: %v", err)
	}

	_, err = rt.Routes.Add(ctx, opnsense.Route{Enabled: true, Network: "192.168.60.0/24", Gateway: "NOPE"})
	var ve *opnsense.ValidationError
	if !errors.As(err, &ve) || ve.Fields["route.gateway"] == "" {
		t.Fatalf("unknown gateway: %v", err)
	}

	st, err := rt.GatewayStatus(ctx)
	if err != nil || len(st) != 1 || st[0].StatusText != "Online" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if err := rt.Routes.Delete(ctx, route); err != nil {
		t.Fatal(err)
	}
	if err := rt.Gateways.Delete(ctx, gw); err != nil {
		t.Fatalf("delete unused gateway: %v", err)
	}
	if err := rt.Apply(ctx); err != nil || fake.Applies["routes/routes/reconfigure"] != 1 {
		t.Fatalf("apply: %v", err)
	}
}
