package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var (
	_ resource.ResourceWithConfigure   = (*idsRulesetResource)(nil)
	_ resource.ResourceWithImportState = (*idsRulesetResource)(nil)
)

// NewIDSRulesetResource returns the opnsense_ids_ruleset resource.
func NewIDSRulesetResource() resource.Resource { return &idsRulesetResource{} }

type idsRulesetResource struct{ baseResource }

type idsRulesetModel struct {
	ID          types.String `tfsdk:"id"`
	Filename    types.String `tfsdk:"filename"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Description types.String `tfsdk:"description"`
}

func (r *idsRulesetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ids_ruleset"
}

func (r *idsRulesetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Whether a downloadable IDS rule file is enabled (Services → Intrusion Detection → Download). The file must already exist in the list, so run the rule download once (`ids/service/updateRules`) before applying. Destroying the resource disables the ruleset.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}, Description: "The file name."},
			"filename": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Description: "Rule file name, e.g. `abuse.ch.sslblacklist.rules`."},
			"enabled":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "Use the rules of this file."},
			"description": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}, Description: "Description from the rule catalogue."},
		},
	}
}

func (r *idsRulesetResource) apply(ctx context.Context, m *idsRulesetModel) error {
	if err := r.client.IDS.SetRulesetEnabled(ctx, m.Filename.ValueString(), m.Enabled.ValueBool()); err != nil {
		return err
	}
	rs, err := r.client.IDS.Ruleset(ctx, m.Filename.ValueString())
	if err != nil {
		return err
	}
	m.ID, m.Description = types.StringValue(rs.Filename), types.StringValue(rs.Description)
	return nil
}

func (r *idsRulesetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m idsRulesetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		resp.Diagnostics.AddError("Unable to set IDS ruleset", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *idsRulesetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m idsRulesetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rs, err := r.client.IDS.Ruleset(ctx, m.ID.ValueString())
	if errors.Is(err, opnsense.ErrNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read IDS ruleset", err.Error())
		return
	}
	m.Filename, m.Enabled, m.Description = types.StringValue(rs.Filename), types.BoolValue(bool(rs.Enabled)), types.StringValue(rs.Description)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *idsRulesetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m idsRulesetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		resp.Diagnostics.AddError("Unable to set IDS ruleset", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Delete disables the ruleset; the file stays in the catalogue.
func (r *idsRulesetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m idsRulesetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.IDS.SetRulesetEnabled(ctx, m.Filename.ValueString(), false); err != nil {
		resp.Diagnostics.AddError("Unable to disable IDS ruleset", err.Error())
	}
}

func (r *idsRulesetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("filename"), req.ID)...)
}
