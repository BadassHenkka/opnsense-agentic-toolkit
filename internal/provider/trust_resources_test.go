package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestTrustCAAndCert(t *testing.T) {
	fake := opnsensetest.New(t)
	ch := newHarness(t, fake, NewTrustCAResource())
	plan := genTrustCAPlan()
	plan.KeyType = types.StringValue("4096")
	var ca genTrustCAModel
	st, ok := ch.create(plan, &ca)
	if !ok {
		t.Fatal("CA create failed")
	}
	if ca.Certificate.ValueString() == "" || !ca.PrivateKey.IsNull() || ca.Refid.ValueString() == "" {
		t.Fatalf("certificate %q, private key %v, refid %v", ca.Certificate, ca.PrivateKey, ca.Refid)
	}
	if _, ok := ch.read(st, &ca); !ok || ca.KeyType.ValueString() != "4096" || ca.Method.ValueString() != "internal" {
		t.Fatalf("write-only values not kept: key %v method %v", ca.KeyType, ca.Method)
	}
	cert := ca.Certificate.ValueString()
	upd := ca
	upd.Description = types.StringValue("Home root CA")
	ch.update(st, upd, &ca)
	if ca.Certificate.ValueString() != cert || ca.Description.ValueString() != "Home root CA" {
		t.Fatalf("update changed the certificate or lost the description: %+v", ca)
	}

	eh := newHarness(t, fake, NewTrustCertResource())
	cp := genTrustCertPlan()
	cp.IssuerRefid = ca.Refid
	var c genTrustCertModel
	cst, ok := eh.create(cp, &c)
	if !ok || c.Certificate.ValueString() == "" || !c.PrivateKey.IsNull() {
		t.Fatalf("cert %+v", c)
	}
	upc := c
	upc.Description = types.StringValue("nas.home.lan")
	eh.update(cst, upc, &c)
	want := []string{"ca:internal", "ca:existing", "cert:internal", "cert:manual"}
	if ops := fake.Operations(); !slices.Equal(ops, want) {
		t.Fatalf("operations %v, want %v", ops, want)
	}

	// Import: write-only values stay null until the configuration supplies them.
	id, ok := ch.importID("Home root CA")
	if !ok || id != ca.ID.ValueString() {
		t.Fatalf("import %q", id)
	}
}

func TestReplaceOnChange(t *testing.T) {
	for _, tc := range []struct {
		state types.String
		want  bool
	}{{types.StringNull(), false}, {types.StringValue("2048"), true}} {
		req := planmodifier.StringRequest{StateValue: tc.state, PlanValue: types.StringValue("4096"), ConfigValue: types.StringValue("4096")}
		req.State.Raw, req.Plan.Raw = nonNullRaw(), nonNullRaw()
		var resp planmodifier.StringResponse
		resp.PlanValue = req.PlanValue
		replaceOnChangeString().PlanModifyString(context.Background(), req, &resp)
		if resp.RequiresReplace != tc.want {
			t.Errorf("state %v: replace %v, want %v", tc.state, resp.RequiresReplace, tc.want)
		}
	}
}

func nonNullRaw() tftypes.Value { return tftypes.NewValue(tftypes.String, "x") }
