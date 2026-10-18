package provider

import "testing"

func TestTrafficShaperNumbers(t *testing.T) {
	h := newHarness(t, nil, NewTrafficShaperPipeResource())
	var a, b genTrafficShaperPipeModel
	if _, ok := h.create(genTrafficShaperPipePlan(), &a); !ok {
		t.Fatal("first pipe failed")
	}
	p2 := genTrafficShaperPipePlan()
	if _, ok := h.create(p2, &b); !ok {
		t.Fatal("second pipe failed")
	}
	if a.Number.ValueString() != "1" || b.Number.ValueString() != "2" {
		t.Fatalf("numbers %v, %v; want 1, 2", a.Number, b.Number)
	}
}
