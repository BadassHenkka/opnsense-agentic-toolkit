package provider

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

// The generated test covers the basics; this checks os-wol's quirks.
func TestWolHostResource(t *testing.T) {
	h := newHarness(t, nil, NewWolHostResource())
	plan := genWolHostPlan()
	var got genWolHostModel
	st, ok := h.create(plan, &got)
	if !ok || got.MAC.ValueString() != "00:11:22:33:44:55" {
		t.Fatalf("create: %+v", got)
	}
	if imp, ok := h.importID("nas"); !ok || imp != got.ID.ValueString() {
		t.Fatalf("import %q", imp)
	}
	plan.ID, plan.Interface = got.ID, types.StringValue("opt3")
	st = h.update(st, plan, &got)
	// delHost returns an empty body; delete must still succeed.
	h.delete(st)
	if _, ok := h.fake.Get("host", got.ID.ValueString()); ok {
		t.Fatal("not deleted")
	}
	bad := plan
	bad.MAC = types.StringValue("00-11-22-33-44-55")
	if !h.validateStrings(bad).HasError() {
		t.Fatal("dash-separated MAC should fail validation")
	}
}

// invokeWake runs the wake action with the given config values (nil = null).
func invokeWake(t *testing.T, fake *opnsensetest.Server, vals map[string]*string) (validate, invoke []string, progress []string) {
	t.Helper()
	ctx := context.Background()
	a := NewWolWakeAction().(*wolWakeAction)
	var cresp action.ConfigureResponse
	a.Configure(ctx, action.ConfigureRequest{ProviderData: fake.Client(t)}, &cresp)
	var sresp action.SchemaResponse
	a.Schema(ctx, action.SchemaRequest{}, &sresp)

	attrs := map[string]tftypes.Value{}
	for _, k := range []string{"host_id", "interface", "mac"} {
		var v any
		if vals[k] != nil {
			v = *vals[k]
		}
		attrs[k] = tftypes.NewValue(tftypes.String, v)
	}
	typ := sresp.Schema.Type().TerraformType(ctx)
	cfg := tfsdk.Config{Schema: sresp.Schema, Raw: tftypes.NewValue(typ, attrs)}

	var vresp action.ValidateConfigResponse
	a.ValidateConfig(ctx, action.ValidateConfigRequest{Config: cfg}, &vresp)
	for _, d := range vresp.Diagnostics.Errors() {
		validate = append(validate, d.Summary())
	}
	if len(validate) > 0 {
		return
	}
	iresp := action.InvokeResponse{SendProgress: func(e action.InvokeProgressEvent) { progress = append(progress, e.Message) }}
	a.Invoke(ctx, action.InvokeRequest{Config: cfg}, &iresp)
	for _, d := range iresp.Diagnostics.Errors() {
		invoke = append(invoke, d.Detail())
	}
	return
}

func str(s string) *string { return &s }

func TestWolWakeAction(t *testing.T) {
	fake := opnsensetest.New(t)
	h := newHarness(t, fake, NewWolHostResource())
	var host genWolHostModel
	h.create(genWolHostPlan(), &host)

	_, inv, prog := invokeWake(t, fake, map[string]*string{"host_id": str(host.ID.ValueString())})
	if len(inv) != 0 || len(prog) != 1 {
		t.Fatalf("wake host: %v %v", inv, prog)
	}
	_, inv, _ = invokeWake(t, fake, map[string]*string{"interface": str("opt3"), "mac": str("AA-BB-CC-DD-EE-FF")})
	if len(inv) != 0 {
		t.Fatalf("wake by MAC: %v", inv)
	}
	if got := fake.Wakes(); !slices.Equal(got, []string{"lan 00:11:22:33:44:55", "opt3 aa:bb:cc:dd:ee:ff"}) {
		t.Fatalf("wakes %v", got)
	}

	if v, _, _ := invokeWake(t, fake, map[string]*string{"mac": str("00:11:22:33:44:55")}); len(v) == 0 {
		t.Fatal("mac without interface should fail validation")
	}
	if v, _, _ := invokeWake(t, fake, map[string]*string{"host_id": str("x"), "mac": str("00:11:22:33:44:55"), "interface": str("lan")}); len(v) == 0 {
		t.Fatal("host_id with mac should fail validation")
	}
	if _, inv, _ := invokeWake(t, fake, map[string]*string{"interface": str("wan"), "mac": str("00:11:22:33:44:55")}); len(inv) == 0 || !strings.Contains(inv[0], "Incorrect IPv4") {
		t.Fatalf("wan wake: %v", inv)
	}
}
