package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func strMap(kv ...string) types.Map {
	m := map[string]attr.Value{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = types.StringValue(kv[i+1])
	}
	return types.MapValueMust(types.StringType, m)
}

func TestAcmeSettingsResource(t *testing.T) {
	h := newHarness(t, nil, NewAcmeSettingsResource())
	plan := genAcmeSettingsPlan()
	plan.Enabled, plan.Environment = types.BoolValue(true), types.StringValue("stg")
	var got genAcmeSettingsModel
	st, ok := h.create(plan, &got)
	if !ok || got.ID.ValueString() != "acmeclient" {
		t.Fatalf("create: %+v", got)
	}
	if s := h.fake.AcmeSettings(); s["enabled"] != "1" || s["environment"] != "stg" {
		t.Fatalf("stored %v", s)
	}
	if h.fake.Applies["acmeclient/service/reconfigure"] != 1 {
		t.Fatal("settings change was not applied")
	}
	h.delete(st)
	if s := h.fake.AcmeSettings(); s["enabled"] != "0" || s["environment"] != "stg" {
		t.Fatalf("destroy should only disable: %v", s)
	}
}

func challengePlan(params types.Map) acmeChallengeTypeModel {
	return acmeChallengeTypeModel{
		ID: types.StringUnknown(), Name: types.StringValue("cloudflare"), Description: types.StringValue(""),
		Method: types.StringValue("dns01"), DNSService: types.StringValue("dns_cf"), DNSSleep: types.Int64Value(0),
		Params: params, Enabled: types.BoolValue(true),
	}
}

func TestAcmeChallengeTypeParams(t *testing.T) {
	h := newHarness(t, nil, NewAcmeChallengeTypeResource())

	plan := challengePlan(strMap("dns_cf_token", "tok", "dns_cf_account_id", "acc"))
	var got acmeChallengeTypeModel
	st, ok := h.create(plan, &got)
	if !ok {
		t.Fatal("create failed")
	}
	id := got.ID.ValueString()
	if len(got.Params.Elements()) != 2 {
		t.Fatalf("state should hold only managed params: %v", got.Params)
	}

	// Drift in a managed key is detected; unmanaged fields are ignored.
	c := h.fake.Client(t)
	v, _ := c.Acme.ChallengeTypes.Get(context.Background(), id)
	v.Params = map[string]string{"dns_cf_token": "rotated-in-ui", "dns_cf_zone_id": "zone"}
	if err := c.Acme.ChallengeTypes.Set(context.Background(), id, *v); err != nil {
		t.Fatal(err)
	}
	st, _ = h.read(st, &got)
	var params map[string]string
	got.Params.ElementsAs(context.Background(), &params, false)
	if params["dns_cf_token"] != "rotated-in-ui" || len(params) != 2 {
		t.Fatalf("after read: %v", params)
	}

	// Removing a key from the configuration clears it in OPNsense.
	upd := challengePlan(strMap("dns_cf_token", "tok2"))
	upd.ID = got.ID
	h.update(st, upd, &got)
	rec, _ := h.fake.Get("validation", id)
	if rec["dns_cf_token"] != "tok2" || rec["dns_cf_account_id"] != "" || rec["dns_cf_zone_id"] != "zone" {
		t.Fatalf("after update: %v", rec)
	}

	// Unknown field names fail at plan time.
	if d := h.modifyPlan(challengePlan(strMap("dns_cf_tokn", "x"))); !d.HasError() {
		t.Fatal("unknown param should fail the plan")
	}
	if d := h.modifyPlan(challengePlan(types.MapNull(types.StringType))); d.HasError() {
		t.Fatalf("no params should pass: %v", d)
	}

	// dns01 without dns_service fails validation.
	bad := challengePlan(types.MapNull(types.StringType))
	bad.DNSService = types.StringNull()
	if !h.validate(bad).Diagnostics.HasError() {
		t.Fatal("dns01 without dns_service should fail")
	}
}

func TestAcmeCertificateResource(t *testing.T) {
	fake := opnsensetest.New(t)
	accounts := newHarness(t, fake, NewAcmeAccountResource())
	challenges := newHarness(t, fake, NewAcmeChallengeTypeResource())
	automations := newHarness(t, fake, NewAcmeAutomationResource())
	certs := newHarness(t, fake, NewAcmeCertificateResource())

	var acct genAcmeAccountModel
	if _, ok := accounts.create(genAcmeAccountPlan(), &acct); !ok {
		t.Fatal("account create failed")
	}
	if acct.StatusCode.ValueString() != "100" {
		t.Fatalf("account status %v", acct.StatusCode)
	}
	var ch acmeChallengeTypeModel
	challenges.create(challengePlan(types.MapNull(types.StringType)), &ch)
	var auto acmeAutomationModel
	if _, ok := automations.create(acmeAutomationModel{
		ID: types.StringUnknown(), Name: types.StringValue("restart-gui"), Description: types.StringValue(""),
		Type: types.StringValue("configd_restart_gui"), Params: types.MapNull(types.StringType), Enabled: types.BoolValue(true),
	}, &auto); !ok {
		t.Fatal("automation create failed")
	}

	plan := genAcmeCertificatePlan()
	plan.Name, plan.AltNames, plan.AccountID, plan.ChallengeTypeID = types.StringValue("fw.example.com"), strSet("vpn.example.com"), acct.ID, ch.ID
	plan.AutomationIDs = types.SetValueMust(types.StringType, []attr.Value{auto.ID})
	plan.KeyLength = types.StringValue("key_ec256")
	var got genAcmeCertificateModel
	st, ok := certs.create(plan, &got)
	if !ok {
		t.Fatal("certificate create failed")
	}
	if got.StatusCode.ValueString() != "100" || got.CertRefID.ValueString() != "" {
		t.Fatalf("after create: %+v", got)
	}

	// OPNsense issues it; the next refresh picks up the status without a diff.
	c := fake.Client(t)
	if _, err := c.Acme.IssueCertificate(context.Background(), got.ID.ValueString()); err != nil {
		t.Fatal(err)
	}
	st, _ = certs.read(st, &got)
	if got.StatusCode.ValueString() != "200" || got.CertRefID.ValueString() == "" || got.LastUpdate.ValueString() == "" {
		t.Fatalf("after issue: %+v", got)
	}

	// Updates must not send OPNsense-maintained fields back (the fake returns 400 if they do).
	plan.ID, plan.AltNames = got.ID, strSet("vpn.example.com", "www.example.com")
	certs.update(st, plan, &got)
	if rec, _ := fake.Get("certificate", got.ID.ValueString()); rec["altNames"] != "vpn.example.com,www.example.com" || rec["statusCode"] != "200" {
		t.Fatalf("after update: %v", rec)
	}

	if imp, ok := certs.importID("fw.example.com"); !ok || imp != got.ID.ValueString() {
		t.Fatalf("import by name = %q", imp)
	}

	upper := plan
	upper.AltNames = strSet("VPN.example.com")
	var resp = certs.validateAttrs(upper)
	if !resp.HasError() {
		t.Fatal("upper-case alt name should be rejected")
	}
}
