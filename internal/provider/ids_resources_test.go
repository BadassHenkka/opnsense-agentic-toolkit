package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestIDSRuleset(t *testing.T) {
	fake := opnsensetest.New(t)
	h := newHarness(t, fake, NewIDSRulesetResource())
	var m idsRulesetModel
	st, ok := h.create(idsRulesetModel{ID: types.StringUnknown(), Filename: types.StringValue("emerging-scan.rules"),
		Enabled: types.BoolValue(true), Description: types.StringUnknown()}, &m)
	if !ok || m.Description.ValueString() != "ET open/scan" {
		t.Fatalf("create %+v ok=%v", m, ok)
	}
	rs, err := fake.Client(t).IDS.Ruleset(context.Background(), "emerging-scan.rules")
	if err != nil || !bool(rs.Enabled) {
		t.Fatalf("ruleset %+v err %v", rs, err)
	}
	h.delete(st)
	if rs, _ := fake.Client(t).IDS.Ruleset(context.Background(), "emerging-scan.rules"); bool(rs.Enabled) {
		t.Fatal("still enabled after delete")
	}
	if _, ok := h.create(idsRulesetModel{ID: types.StringUnknown(), Filename: types.StringValue("nope.rules"),
		Enabled: types.BoolValue(true), Description: types.StringUnknown()}, &m); ok {
		t.Fatal("unknown ruleset must fail")
	}
}
