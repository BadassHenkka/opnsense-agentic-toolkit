package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestInterfaceAssignment(t *testing.T) {
	h := newHarness(t, nil, NewNetworkInterfaceResource())
	var got genNetworkInterfaceModel
	if _, ok := h.create(genNetworkInterfacePlan(), &got); !ok {
		t.Fatal("create failed")
	}
	if got.ID.ValueString() != "opt1" || got.Identifier.ValueString() != "opt1" {
		t.Fatalf("id %v, identifier %v; want opt1", got.ID, got.Identifier)
	}
	if h.fake.Applies["interfaces/assignment/reconfigure"] != 1 {
		t.Fatalf("applies %v", h.fake.Applies)
	}
	for in, want := range map[string]string{"lan": "lan", "WAN": "wan", "IOT": "opt1"} {
		if id, ok := h.importID(in); !ok || id != want {
			t.Errorf("import %q = %q, want %q", in, id, want)
		}
	}
	if _, ok := h.importID("nope"); ok {
		t.Error("import of an unknown interface succeeded")
	}
}

// An optional masked field accepts an explicit "", because OPNsense skips the mask for an empty
// value. `tofu plan -generate-config-out` writes "" for every empty field of an imported
// interface, and `= ""` clears a field.
func TestInterfaceEmptyMaskedFields(t *testing.T) {
	h := newHarness(t, nil, NewNetworkInterfaceResource())
	plan := genNetworkInterfacePlan()
	plan.Dhcp6Ifid = types.StringValue("0x1a")
	if d := h.validateStrings(plan); d.HasError() {
		t.Fatalf("valid plan rejected: %v", d)
	}
	var got genNetworkInterfaceModel
	st, ok := h.create(plan, &got)
	if !ok {
		t.Fatal("create failed")
	}
	id := got.ID.ValueString()

	bad := plan
	bad.Dhcp6Ifid = types.StringValue("1a")
	if !h.validateStrings(bad).HasError() {
		t.Error("dhcp6_ifid without 0x accepted")
	}

	plan.ID, plan.Identifier = got.ID, got.Identifier
	for _, s := range []*types.String{&plan.Dhcp6Ifid, &plan.Dhcp6PrefixID, &plan.Track6Ifid, &plan.Track6PrefixID} {
		*s = types.StringValue("")
	}
	if d := h.validateStrings(plan); d.HasError() {
		t.Fatalf("explicit empty values rejected: %v", d)
	}
	h.update(st, plan, &got)
	if rec, _ := h.fake.Get("interface", id); rec["dhcp6_ifid"] != "" {
		t.Errorf("dhcp6_ifid not cleared: %q", rec["dhcp6_ifid"])
	}

	// Import: the generated config is the state read after import, with every value explicit.
	if imp, ok := h.importID(id); !ok || imp != id {
		t.Fatalf("import = %q", imp)
	}
	imported := h.state()
	if d := imported.SetAttribute(h.ctx, pathID, id); d.HasError() {
		t.Fatal(d)
	}
	var config genNetworkInterfaceModel
	if _, ok := h.read(imported, &config); !ok {
		t.Fatal("read after import removed the resource")
	}
	if config.Dhcp6Ifid.IsNull() || config.Dhcp6Ifid.ValueString() != "" {
		t.Fatalf("imported dhcp6_ifid = %v, want \"\"", config.Dhcp6Ifid)
	}
	if d := h.validateStrings(config); d.HasError() {
		t.Errorf("config generated on import rejected: %v", d)
	}
}
