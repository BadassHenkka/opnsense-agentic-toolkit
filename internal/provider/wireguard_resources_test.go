package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func instancePlan(name string, priv types.String) genWireguardInstanceModel {
	m := genWireguardInstancePlan()
	m.Name, m.PrivateKey = types.StringValue(name), priv
	return m
}

func TestWireguardInstanceKeys(t *testing.T) {
	h := newHarness(t, nil, NewWireguardInstanceResource())

	// No private key configured: one is generated and the public key derived.
	var got genWireguardInstanceModel
	st, ok := h.create(instancePlan("home", types.StringUnknown()), &got)
	if !ok {
		t.Fatal("create failed")
	}
	derived, err := opnsense.WireguardPublicKey(got.PrivateKey.ValueString())
	if err != nil || derived != got.PublicKey.ValueString() {
		t.Fatalf("keys: priv=%q pub=%q", got.PrivateKey, got.PublicKey)
	}
	if got.Interface.ValueString() != "wg0" || got.InstanceNumber.ValueString() != "0" {
		t.Fatalf("interface %q / number %q", got.Interface, got.InstanceNumber)
	}
	if rec, _ := h.fake.Get("server", got.ID.ValueString()); rec["pubkey"] != derived {
		t.Fatalf("stored pubkey %q", rec["pubkey"])
	}

	// Planning with a configured key fills in the public key before apply.
	priv, pub, _ := opnsense.WireguardKeyPair()
	p := h.plan(instancePlan("site2site", types.StringValue(priv)))
	resp := resource.ModifyPlanResponse{Plan: p}
	h.r.(resource.ResourceWithModifyPlan).ModifyPlan(h.ctx, resource.ModifyPlanRequest{
		Plan: p, State: h.state(), Config: tfsdk.Config{Schema: h.schema.Schema, Raw: p.Raw}}, &resp)
	var planned types.String
	resp.Plan.GetAttribute(h.ctx, path.Root("public_key"), &planned)
	if planned.ValueString() != pub {
		t.Fatalf("planned public_key %q, want %q", planned, pub)
	}

	// An instance update keeps peers attached by opnsense_wireguard_peer.
	c := h.fake.Client(t)
	_, devicePub, _ := opnsense.WireguardKeyPair()
	peerID, err := c.Wireguard.Peers.Add(context.Background(), opnsense.WireguardPeer{
		Name: "phone", PublicKey: devicePub, TunnelAddress: opnsense.CSVList{"10.10.10.2/32"},
		Instances: opnsense.CSVList{got.ID.ValueString()},
	})
	if err != nil {
		t.Fatal(err)
	}
	upd := instancePlan("home", got.PrivateKey)
	upd.ID, upd.ListenPort, upd.Interface, upd.InstanceNumber = got.ID, types.Int64Value(51821), got.Interface, got.InstanceNumber
	h.update(st, upd, &got)
	if rec, _ := h.fake.Get("server", got.ID.ValueString()); rec["peers"] != peerID || rec["port"] != "51821" {
		t.Fatalf("after instance update: %v", rec)
	}
}

func TestWireguardPeerMembership(t *testing.T) {
	fake := opnsensetest.New(t)
	instances := newHarness(t, fake, NewWireguardInstanceResource())
	peers := newHarness(t, fake, NewWireguardPeerResource())

	var a, b genWireguardInstanceModel
	instances.create(instancePlan("a", types.StringUnknown()), &a)
	instances.create(instancePlan("b", types.StringUnknown()), &b)

	_, devicePub, _ := opnsense.WireguardKeyPair()
	psk, _ := opnsense.WireguardPresharedKey()
	plan := genWireguardPeerPlan()
	plan.Name, plan.PublicKey, plan.PresharedKey = types.StringValue("laptop"), types.StringValue(devicePub), types.StringValue(psk)
	plan.TunnelAddresses, plan.Keepalive = strSet("10.10.10.3/32"), types.Int64Value(25)
	plan.InstanceIDs = types.SetValueMust(types.StringType, []attr.Value{a.ID})
	var got genWireguardPeerModel
	st, ok := peers.create(plan, &got)
	if !ok {
		t.Fatal("peer create failed")
	}
	id := got.ID.ValueString()
	if rec, _ := fake.Get("server", a.ID.ValueString()); rec["peers"] != id {
		t.Fatalf("instance a peers = %q", rec["peers"])
	}

	// Move to b: a loses it, b gains it, and state reads it back.
	plan.ID, plan.InstanceIDs = got.ID, types.SetValueMust(types.StringType, []attr.Value{b.ID})
	st = peers.update(st, plan, &got)
	ra, _ := fake.Get("server", a.ID.ValueString())
	rb, _ := fake.Get("server", b.ID.ValueString())
	if ra["peers"] != "" || rb["peers"] != id {
		t.Fatalf("after move: a=%q b=%q", ra["peers"], rb["peers"])
	}
	var ids []string
	got.InstanceIDs.ElementsAs(context.Background(), &ids, false)
	if len(ids) != 1 || ids[0] != b.ID.ValueString() {
		t.Fatalf("state instance_ids %v", ids)
	}

	// Removing the peer from an instance in the web UI shows up as drift.
	c := fake.Client(t)
	p, _ := c.Wireguard.Peers.Get(context.Background(), id)
	p.Instances = nil
	if err := c.Wireguard.Peers.Set(context.Background(), id, *p); err != nil {
		t.Fatal(err)
	}
	peers.read(st, &got)
	if len(got.InstanceIDs.Elements()) != 0 {
		t.Fatalf("drift not detected: %v", got.InstanceIDs)
	}

	peers.delete(st)
	if _, ok := fake.Get("client", id); ok {
		t.Fatal("peer not deleted")
	}

	// Invalid keys and addresses fail validation.
	bad := plan
	bad.PublicKey, bad.TunnelAddresses = types.StringValue("not-a-key"), strSet("10.10.10.3")
	diags := peers.validateAttrs(bad)
	var sd = peers.validateStrings(bad)
	if !diags.HasError() || !sd.HasError() {
		t.Fatalf("want set and string validation errors, got %v / %v", diags, sd)
	}
}
