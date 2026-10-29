package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
)

// harness drives one resource's methods directly against the fake API, the way Terraform
// would, without a terraform binary.
type harness struct {
	t      *testing.T
	ctx    context.Context
	r      resource.Resource
	schema resource.SchemaResponse
	fake   *opnsensetest.Server
}

func newHarness(t *testing.T, fake *opnsensetest.Server, r resource.Resource) *harness {
	t.Helper()
	ctx := context.Background()
	if fake == nil {
		fake = opnsensetest.New(t)
	}
	var cresp resource.ConfigureResponse
	r.(resource.ResourceWithConfigure).Configure(ctx, resource.ConfigureRequest{ProviderData: fake.Client(t)}, &cresp)
	if cresp.Diagnostics.HasError() {
		t.Fatal(cresp.Diagnostics)
	}
	var meta resource.MetadataResponse
	r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "opnsense"}, &meta)
	h := &harness{t: t, ctx: endpoints.Context(ctx, meta.TypeName), r: r, fake: fake}
	r.Schema(ctx, resource.SchemaRequest{}, &h.schema)
	return h
}

// endpoints records the API endpoints each resource type calls.
var endpoints privileges.Recorder

func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if err := endpoints.Finish("../privileges/endpoints/terraform.json"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

func (h *harness) empty() tftypes.Value {
	return tftypes.NewValue(h.schema.Schema.Type().TerraformType(h.ctx), nil)
}

func (h *harness) state() tfsdk.State { return tfsdk.State{Schema: h.schema.Schema, Raw: h.empty()} }

func (h *harness) plan(model any) tfsdk.Plan {
	h.t.Helper()
	p := tfsdk.Plan{Schema: h.schema.Schema, Raw: h.empty()}
	if d := p.Set(h.ctx, model); d.HasError() {
		h.t.Fatal(d)
	}
	return p
}

// validate runs ValidateConfig on a model treated as configuration.
func (h *harness) validate(model any) resource.ValidateConfigResponse {
	h.t.Helper()
	p := h.plan(model)
	var resp resource.ValidateConfigResponse
	h.r.(resource.ResourceWithValidateConfig).ValidateConfig(h.ctx,
		resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: h.schema.Schema, Raw: p.Raw}}, &resp)
	return resp
}

func (h *harness) create(model any, out any) (tfsdk.State, bool) {
	h.t.Helper()
	resp := resource.CreateResponse{State: h.state()}
	h.r.Create(h.ctx, resource.CreateRequest{Plan: h.plan(model)}, &resp)
	if resp.Diagnostics.HasError() {
		h.t.Logf("create: %v", resp.Diagnostics)
		return resp.State, false
	}
	resp.State.Get(h.ctx, out)
	return resp.State, true
}

func (h *harness) update(st tfsdk.State, model any, out any) tfsdk.State {
	h.t.Helper()
	resp := resource.UpdateResponse{State: st}
	h.r.Update(h.ctx, resource.UpdateRequest{Plan: h.plan(model), State: st}, &resp)
	if resp.Diagnostics.HasError() {
		h.t.Fatalf("update: %v", resp.Diagnostics)
	}
	resp.State.Get(h.ctx, out)
	return resp.State
}

// read returns the refreshed state; ok is false when the resource was removed from state.
func (h *harness) read(st tfsdk.State, out any) (tfsdk.State, bool) {
	h.t.Helper()
	resp := resource.ReadResponse{State: st}
	h.r.Read(h.ctx, resource.ReadRequest{State: st}, &resp)
	if resp.Diagnostics.HasError() {
		h.t.Fatalf("read: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		return resp.State, false
	}
	resp.State.Get(h.ctx, out)
	return resp.State, true
}

func (h *harness) delete(st tfsdk.State) {
	h.t.Helper()
	resp := resource.DeleteResponse{State: st}
	h.r.Delete(h.ctx, resource.DeleteRequest{State: st}, &resp)
	if resp.Diagnostics.HasError() {
		h.t.Fatalf("delete: %v", resp.Diagnostics)
	}
}

// importID runs ImportState and returns the resolved id, or "" with ok=false on error.
func (h *harness) importID(id string) (string, bool) {
	h.t.Helper()
	resp := resource.ImportStateResponse{State: h.state()}
	h.r.(resource.ResourceWithImportState).ImportState(h.ctx, resource.ImportStateRequest{ID: id}, &resp)
	if resp.Diagnostics.HasError() {
		return "", false
	}
	var got string
	resp.State.GetAttribute(h.ctx, pathID, &got)
	return got, true
}

// modifyPlan runs ModifyPlan for a create (no prior state) and returns its diagnostics.
func (h *harness) modifyPlan(model any) diag.Diagnostics {
	h.t.Helper()
	p := h.plan(model)
	resp := resource.ModifyPlanResponse{Plan: p}
	h.r.(resource.ResourceWithModifyPlan).ModifyPlan(h.ctx, resource.ModifyPlanRequest{
		Plan: p, State: h.state(), Config: tfsdk.Config{Schema: h.schema.Schema, Raw: p.Raw},
	}, &resp)
	return resp.Diagnostics
}

// validateAttrs runs the schema's attribute validators on a model treated as configuration.
func (h *harness) validateAttrs(model any) diag.Diagnostics {
	h.t.Helper()
	p := h.plan(model)
	var diags diag.Diagnostics
	for name, a := range h.schema.Schema.Attributes {
		sa, ok := a.(interface {
			SetValidators() []validator.Set
		})
		if !ok {
			continue
		}
		var v types.Set
		p.GetAttribute(h.ctx, path.Root(name), &v)
		for _, val := range sa.SetValidators() {
			resp := &validator.SetResponse{}
			val.ValidateSet(h.ctx, validator.SetRequest{Path: path.Root(name), ConfigValue: v}, resp)
			diags.Append(resp.Diagnostics...)
		}
	}
	return diags
}

// validateStrings runs string attribute validators on a model treated as configuration.
func (h *harness) validateStrings(model any) diag.Diagnostics {
	h.t.Helper()
	p := h.plan(model)
	var diags diag.Diagnostics
	for name, a := range h.schema.Schema.Attributes {
		sa, ok := a.(interface {
			StringValidators() []validator.String
		})
		if !ok {
			continue
		}
		var v types.String
		p.GetAttribute(h.ctx, path.Root(name), &v)
		for _, val := range sa.StringValidators() {
			resp := &validator.StringResponse{}
			val.ValidateString(h.ctx, validator.StringRequest{Path: path.Root(name), ConfigValue: v}, resp)
			diags.Append(resp.Diagnostics...)
		}
	}
	return diags
}

// deleteResp runs Delete and returns its diagnostics instead of failing the test.
func (h *harness) deleteResp(st tfsdk.State) diag.Diagnostics {
	h.t.Helper()
	resp := resource.DeleteResponse{State: st}
	h.r.Delete(h.ctx, resource.DeleteRequest{State: st}, &resp)
	return resp.Diagnostics
}
