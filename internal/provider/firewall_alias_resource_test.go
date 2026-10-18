package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

// These tests drive the resource methods directly against the fake API. They cover the
// CRUD logic without a terraform binary; acceptance tests against a real OPNsense come later.

var pathID = path.Root("id")

func TestProviderSchemaValid(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	var presp fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &presp)
	if presp.Diagnostics.HasError() {
		t.Fatal(presp.Diagnostics)
	}
	for _, newRes := range p.Resources(ctx) {
		var resp resource.SchemaResponse
		newRes().Schema(ctx, resource.SchemaRequest{}, &resp)
		if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
			t.Fatal(d)
		}
	}
}

func newTestResource(t *testing.T) (*genAliasResource, *opnsensetest.Server, resource.SchemaResponse) {
	t.Helper()
	fake := opnsensetest.New(t)
	r := NewAliasResource().(*genAliasResource)
	var cresp resource.ConfigureResponse
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: fake.Client(t)}, &cresp)
	if cresp.Diagnostics.HasError() {
		t.Fatal(cresp.Diagnostics)
	}
	var sresp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sresp)
	return r, fake, sresp
}

func strSet(vals ...string) types.Set {
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, elems)
}

func planModel(name string, content ...string) genAliasModel {
	m := genAliasPlan()
	m.Name, m.Content = types.StringValue(name), strSet(content...)
	m.Description = types.StringValue("managed by terraform")
	return m
}

func emptyRaw(ctx context.Context, s resource.SchemaResponse) tftypes.Value {
	return tftypes.NewValue(s.Schema.Type().TerraformType(ctx), nil)
}

func TestFirewallAliasCRUD(t *testing.T) {
	ctx := context.Background()
	r, fake, s := newTestResource(t)

	// Create
	plan := tfsdk.Plan{Schema: s.Schema, Raw: emptyRaw(ctx, s)}
	if d := plan.Set(ctx, planModel("tf_servers", "10.0.10.5", "10.0.10.6")); d.HasError() {
		t.Fatal(d)
	}
	cresp := resource.CreateResponse{State: tfsdk.State{Schema: s.Schema, Raw: emptyRaw(ctx, s)}}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &cresp)
	if cresp.Diagnostics.HasError() {
		t.Fatal(cresp.Diagnostics)
	}
	var got genAliasModel
	cresp.State.Get(ctx, &got)
	id := got.ID.ValueString()
	if id == "" || fake.Applies["firewall/alias/reconfigure"] != 1 {
		t.Fatalf("create: id=%q applies=%d", id, fake.Applies["firewall/alias/reconfigure"])
	}
	if rec, _ := fake.Get("alias", id); rec["content"] != "10.0.10.5\n10.0.10.6" || rec["enabled"] != "1" {
		t.Fatalf("stored %+v", rec)
	}

	// Update: change content, state carries the id.
	upd := planModel("tf_servers", "10.0.10.5")
	upd.ID = got.ID
	uplan := tfsdk.Plan{Schema: s.Schema, Raw: emptyRaw(ctx, s)}
	uplan.Set(ctx, upd)
	uresp := resource.UpdateResponse{State: cresp.State}
	r.Update(ctx, resource.UpdateRequest{Plan: uplan, State: cresp.State}, &uresp)
	if uresp.Diagnostics.HasError() {
		t.Fatal(uresp.Diagnostics)
	}
	if rec, _ := fake.Get("alias", id); rec["content"] != "10.0.10.5" {
		t.Fatalf("after update stored %+v", rec)
	}

	// Read reflects out-of-band changes (drift).
	c := fake.Client(t)
	a, _ := c.Firewall.Aliases.Get(ctx, id)
	a.Description = "edited in the UI"
	if err := c.Firewall.Aliases.Set(ctx, id, *a); err != nil {
		t.Fatal(err)
	}
	rresp := resource.ReadResponse{State: uresp.State}
	r.Read(ctx, resource.ReadRequest{State: uresp.State}, &rresp)
	rresp.State.Get(ctx, &got)
	if got.Description.ValueString() != "edited in the UI" {
		t.Fatalf("read did not pick up drift: %v", got.Description)
	}

	// Import by name.
	iresp := resource.ImportStateResponse{State: tfsdk.State{Schema: s.Schema, Raw: emptyRaw(ctx, s)}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "tf_servers"}, &iresp)
	if iresp.Diagnostics.HasError() {
		t.Fatal(iresp.Diagnostics)
	}
	var imported types.String
	iresp.State.GetAttribute(ctx, pathID, &imported)
	if imported.ValueString() != id {
		t.Fatalf("import resolved %q, want %q", imported.ValueString(), id)
	}

	// Delete, then Read removes the resource from state.
	dresp := resource.DeleteResponse{State: rresp.State}
	r.Delete(ctx, resource.DeleteRequest{State: rresp.State}, &dresp)
	if dresp.Diagnostics.HasError() {
		t.Fatal(dresp.Diagnostics)
	}
	if _, ok := fake.Get("alias", id); ok {
		t.Fatal("alias still exists after delete")
	}
	rresp = resource.ReadResponse{State: rresp.State}
	r.Read(ctx, resource.ReadRequest{State: rresp.State}, &rresp)
	if !rresp.State.Raw.IsNull() {
		t.Fatal("read of a deleted alias should remove it from state")
	}
}

func TestFirewallAliasCreateValidationError(t *testing.T) {
	ctx := context.Background()
	r, _, s := newTestResource(t)
	for i, wantErr := range []bool{false, true} { // second create collides on name
		plan := tfsdk.Plan{Schema: s.Schema, Raw: emptyRaw(ctx, s)}
		plan.Set(ctx, planModel("dup"))
		resp := resource.CreateResponse{State: tfsdk.State{Schema: s.Schema, Raw: emptyRaw(ctx, s)}}
		r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
		if resp.Diagnostics.HasError() != wantErr {
			t.Fatalf("create #%d: diagnostics %v", i+1, resp.Diagnostics)
		}
	}
}
