package provider

import (
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func rulePlan(desc string) firewallRuleModel {
	return firewallRuleModel{
		ID: types.StringUnknown(), Description: types.StringValue(desc), Sequence: types.Int64Unknown(),
		Enabled: types.BoolValue(true), Action: types.StringValue("pass"), Quick: types.BoolValue(true),
		Interfaces: strSet("opt3"), InterfaceNot: types.BoolValue(false), Direction: types.StringValue("in"),
		IPProtocol: types.StringValue("inet"), Protocol: types.StringValue("TCP"),
		Source: strSet("opt3"), SourceNot: types.BoolValue(false), SourcePort: types.StringValue(""),
		Destination: strSet("192.168.1.10"), DestinationNot: types.BoolValue(false),
		DestinationPort: types.StringValue("445"), Gateway: types.StringValue(""), Log: types.BoolValue(false),
		StateType: types.StringValue("keep"), Categories: strSet(),
	}
}

func TestFirewallRuleResource(t *testing.T) {
	h := newHarness(t, nil, NewFirewallRuleResource())

	var a, b firewallRuleModel
	stA, ok := h.create(rulePlan("site2 to NAS"), &a)
	if !ok {
		t.Fatal("create failed")
	}
	if _, ok := h.create(rulePlan("site2 to NAS backup"), &b); !ok {
		t.Fatal("create failed")
	}
	// Sequence is assigned by OPNsense when omitted.
	if a.Sequence.ValueInt64() != 100 || b.Sequence.ValueInt64() != 200 {
		t.Fatalf("sequences %v, %v", a.Sequence, b.Sequence)
	}
	if h.fake.Applies["firewall/filter/apply"] != 2 {
		t.Fatalf("applies %v", h.fake.Applies)
	}

	// Explicit sequence and a policy-routing gateway.
	upd := rulePlan("site2 to NAS")
	upd.ID, upd.Sequence, upd.Gateway = a.ID, types.Int64Value(50), types.StringValue("WG_SITE2")
	stA = h.update(stA, upd, &a)
	rec, _ := h.fake.Get("rule", a.ID.ValueString())
	if rec["sequence"] != "50" || rec["gateway"] != "WG_SITE2" {
		t.Fatalf("after update %v", rec)
	}

	if imp, ok := h.importID("site2 to NAS"); !ok || imp != a.ID.ValueString() {
		t.Fatalf("import = %q", imp)
	}
	if _, ok := h.importID("Anti-Lockout Rule"); ok {
		t.Fatal("automatic rules must not be importable")
	}

	h.delete(stA)
	if _, ok := h.fake.Get("rule", a.ID.ValueString()); ok {
		t.Fatal("not deleted")
	}

	// Plan-time validation.
	bad := rulePlan("x")
	bad.Protocol = types.StringValue("any")
	if !h.validate(bad).Diagnostics.HasError() {
		t.Fatal("port with protocol any should fail")
	}
	bad = rulePlan("x")
	bad.Source = strSet("any", "lan")
	if !h.validate(bad).Diagnostics.HasError() {
		t.Fatal("any combined with lan should fail")
	}
}

func TestFirewallRuleLockout(t *testing.T) {
	fake := opnsensetest.New(t)
	fake.LockOutAfter = "firewall/filter/apply"
	defer func(w time.Duration) { ruleVerifyWait = w }(ruleVerifyWait)
	ruleVerifyWait = time.Second
	h := newHarness(t, fake, NewFirewallRuleResource())
	var got firewallRuleModel
	st, ok := h.create(rulePlan("block me"), &got)
	if ok {
		t.Fatal("create should report the lockout")
	}
	// The rule is still tracked in state, so the next run can fix or destroy it.
	if st.Raw.IsNull() {
		t.Fatal("rule should be in state after a lockout")
	}
}
