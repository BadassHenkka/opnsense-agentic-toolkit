package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var (
	_ resource.ResourceWithImportState = (*acmeAutomationResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*acmeAutomationResource)(nil)
)

// NewAcmeAutomationResource returns the opnsense_acme_automation resource.
func NewAcmeAutomationResource() resource.Resource { return &acmeAutomationResource{} }

type acmeAutomationResource struct{ baseResource }

type acmeAutomationModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
	Params      types.Map    `tfsdk:"params"`
	Enabled     types.Bool   `tfsdk:"enabled"`

	prior *acmeAutomationModel
}

func (m *acmeAutomationModel) setPrior(p *acmeAutomationModel) { m.prior = p }

func (r *acmeAutomationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_automation"
}

func (r *acmeAutomationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An ACME automation (Services → ACME Client → Automations): an action run after a " +
			"certificate is issued or renewed.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("automation"),
			"name":        schema.StringAttribute{Required: true},
			"description": optionalString(""),
			"type": schema.StringAttribute{
				Required: true,
				Description: "Automation type, e.g. `configd_restart_gui`, `configd_restart_haproxy`, " +
					"`configd_upload_sftp`, `acme_proxmoxve`, `acme_truenas`.",
			},
			"params": paramsAttribute("Type-specific fields by their OPNsense name, e.g. " +
				"`{ acme_proxmoxve_server = \"pve.lan\" }`. Only the keys set here are managed."),
			"enabled": enabledAttribute(),
		},
	}
}

func (r *acmeAutomationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.client == nil {
		return
	}
	var params types.Map
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("params"), &params)...)
	checkParamKeys(ctx, params, r.client.Acme.AutomationTemplate, &resp.Diagnostics)
}

func (m *acmeAutomationModel) toAPI(ctx context.Context) (opnsense.AcmeAutomation, diag.Diagnostics) {
	prior := types.MapNull(types.StringType)
	if m.prior != nil {
		prior = m.prior.Params
	}
	params, diags := paramsToAPI(ctx, m.Params, prior)
	return opnsense.AcmeAutomation{
		Enabled: opnsense.Bool(m.Enabled.ValueBool()), Name: m.Name.ValueString(),
		Description: m.Description.ValueString(), Type: opnsense.Option(m.Type.ValueString()), Params: params,
	}, diags
}

func (m *acmeAutomationModel) fromAPI(ctx context.Context, id string, a *opnsense.AcmeAutomation) diag.Diagnostics {
	m.ID = types.StringValue(id)
	m.Name = types.StringValue(a.Name)
	m.Description = types.StringValue(a.Description)
	m.Type = types.StringValue(string(a.Type))
	m.Enabled = types.BoolValue(bool(a.Enabled))
	var diags diag.Diagnostics
	m.Params, diags = paramsFromAPI(ctx, m.Params, a.Params)
	return diags
}

func (m *acmeAutomationModel) itemID() string { return m.ID.ValueString() }

var acmeAutomationCRUD = itemCRUD[opnsense.AcmeAutomation, opnsense.AcmeAutomationRow, acmeAutomationModel, *acmeAutomationModel]{
	what: "ACME automation",
	items: func(c *opnsense.Client) *opnsense.ItemController[opnsense.AcmeAutomation, opnsense.AcmeAutomationRow] {
		return c.Acme.Automations
	},
	apply: func(c *opnsense.Client) func(context.Context) error { return c.Acme.Apply },
}

func (r *acmeAutomationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	acmeAutomationCRUD.create(ctx, r.client, req, resp)
}

func (r *acmeAutomationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	acmeAutomationCRUD.read(ctx, r.client, req, resp)
}

func (r *acmeAutomationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	acmeAutomationCRUD.update(ctx, r.client, req, resp)
}

func (r *acmeAutomationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	acmeAutomationCRUD.delete(ctx, r.client, req, resp)
}

func (r *acmeAutomationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp, r.client.Acme.Automations, "ACME automation")
}
