package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func hostOverridePlan(hostname, rr, server string) genHostOverrideModel {
	m := genHostOverridePlan()
	m.Hostname, m.Type, m.Server = types.StringValue(hostname), types.StringValue(rr), types.StringValue(server)
	return m
}

func TestUnboundHostOverrideCRUD(t *testing.T) {
	h := newHarness(t, nil, NewHostOverrideResource())

	var got genHostOverrideModel
	st, ok := h.create(hostOverridePlan("nas", "A", "10.0.10.6"), &got)
	if !ok {
		t.Fatal("create failed")
	}
	id := got.ID.ValueString()
	if !got.TTL.IsNull() || !got.MXPriority.IsNull() || h.fake.Applies["unbound/service/reconfigure"] != 1 {
		t.Fatalf("after create: %+v applies=%v", got, h.fake.Applies)
	}

	upd := hostOverridePlan("nas", "A", "10.0.10.7")
	upd.ID, upd.TTL = got.ID, types.Int64Value(600)
	st = h.update(st, upd, &got)
	if rec, _ := h.fake.Get("host", id); rec["server"] != "10.0.10.7" || rec["ttl"] != "600" {
		t.Fatalf("stored %v", rec)
	}
	if got.TTL.ValueInt64() != 600 {
		t.Fatalf("state ttl = %v", got.TTL)
	}

	// Removing ttl from config clears it in OPNsense.
	upd.TTL = types.Int64Null()
	st = h.update(st, upd, &got)
	if rec, _ := h.fake.Get("host", id); rec["ttl"] != "" || !got.TTL.IsNull() {
		t.Fatalf("ttl not cleared: %v / %v", rec, got.TTL)
	}

	// A second record for the same name makes name-only import ambiguous.
	if _, ok := h.create(hostOverridePlan("nas", "AAAA", "fd00::6"), &genHostOverrideModel{}); !ok {
		t.Fatal("create AAAA failed")
	}
	if _, ok := h.importID("nas.home.lan"); ok {
		t.Fatal("ambiguous import should fail")
	}
	if imp, ok := h.importID("nas.home.lan/a"); !ok || imp != id {
		t.Fatalf("import name/TYPE = %q, %v", imp, ok)
	}

	h.delete(st)
	if _, ok := h.read(st, &got); ok {
		t.Fatal("read after delete should drop the resource from state")
	}
}

func TestUnboundHostOverrideValidateConfig(t *testing.T) {
	h := newHarness(t, nil, NewHostOverrideResource())
	cfg := func(rr string) genHostOverrideModel {
		m := hostOverridePlan("x", rr, "")
		m.Server, m.MX, m.TXTData = types.StringNull(), types.StringNull(), types.StringNull()
		return m
	}
	for rr, wantAttrs := range map[string]int{"A": 1, "AAAA": 1, "MX": 2, "TXT": 1} {
		if n := h.validate(cfg(rr)).Diagnostics.ErrorsCount(); n != wantAttrs {
			t.Errorf("type %s: %d errors, want %d", rr, n, wantAttrs)
		}
	}
	ok := cfg("MX")
	ok.MX, ok.MXPriority = types.StringValue("mail.home.lan"), types.Int64Value(10)
	if d := h.validate(ok).Diagnostics; d.HasError() {
		t.Errorf("valid MX config rejected: %v", d)
	}
	unknown := cfg("A")
	unknown.Server = types.StringUnknown() // e.g. from another resource's output
	if d := h.validate(unknown).Diagnostics; d.HasError() {
		t.Errorf("unknown server should pass: %v", d)
	}
}

func TestUnboundHostAliasCRUD(t *testing.T) {
	hosts := newHarness(t, nil, NewHostOverrideResource())
	aliases := newHarness(t, hosts.fake, NewHostAliasResource())

	var host genHostOverrideModel
	hostState, _ := hosts.create(hostOverridePlan("nas", "A", "10.0.10.6"), &host)

	plan := genHostAliasPlan()
	plan.HostOverrideID, plan.Hostname = host.ID, types.StringValue("truenas")
	var got genHostAliasModel
	st, ok := aliases.create(plan, &got)
	if !ok || got.HostOverrideID.ValueString() != host.ID.ValueString() {
		t.Fatalf("create alias: %+v", got)
	}
	if imp, ok := aliases.importID("truenas.home.lan"); !ok || imp != got.ID.ValueString() {
		t.Fatalf("import alias = %q", imp)
	}

	plan.ID, plan.Description = got.ID, types.StringValue("web UI")
	st = aliases.update(st, plan, &got)
	if got.Description.ValueString() != "web UI" {
		t.Fatalf("update: %+v", got)
	}

	// Deleting the host override cascades in OPNsense. Read drops the alias, and a Delete of
	// the already-gone alias (destroy order) must not fail.
	hosts.delete(hostState)
	if _, ok := aliases.read(st, &got); ok {
		t.Fatal("alias should be gone after its host override was deleted")
	}
	aliases.delete(st)

	bad := plan
	bad.Hostname, bad.Domain = types.StringValue(""), types.StringValue("")
	if !aliases.validate(bad).Diagnostics.HasError() {
		t.Fatal("alias with neither hostname nor domain should fail validation")
	}
}

// Applying a blocklist downloads the lists before reloading Unbound.
func TestUnboundBlocklistApply(t *testing.T) {
	h := newHarness(t, nil, NewUnboundBlocklistResource())
	var got genUnboundBlocklistModel
	if _, ok := h.create(genUnboundBlocklistPlan(), &got); !ok {
		t.Fatal("create failed")
	}
	if ops := h.fake.Operations(); len(ops) != 1 || ops[0] != "unbound/service/dnsbl" {
		t.Fatalf("operations %v", ops)
	}
	if h.fake.Applies["unbound/service/reconfigure"] != 1 {
		t.Fatalf("applies %v", h.fake.Applies)
	}

	// source_nets is a NetworkField without NetMaskRequired: a bare address is valid.
	m := genUnboundBlocklistPlan()
	m.SourceNets = strSet("192.168.10.4", "192.168.20.0/24", "fd00::4")
	if d := h.validateAttrs(m); d.HasError() {
		t.Fatalf("addresses and networks: %v", d)
	}
	m.SourceNets = strSet("not-an-address")
	if !h.validateAttrs(m).HasError() {
		t.Fatal("an invalid source should fail validation")
	}
}
