package provider

import "testing"

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
