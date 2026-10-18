package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var (
	_ resource.ResourceWithConfigure   = (*authAPIKeyResource)(nil)
	_ resource.ResourceWithImportState = (*authAPIKeyResource)(nil)
)

// NewAuthAPIKeyResource returns the opnsense_auth_api_key resource.
func NewAuthAPIKeyResource() resource.Resource { return &authAPIKeyResource{} }

type authAPIKeyResource struct{ baseResource }

type authAPIKeyModel struct {
	ID     types.String `tfsdk:"id"`
	User   types.String `tfsdk:"user"`
	Key    types.String `tfsdk:"key"`
	Secret types.String `tfsdk:"secret"`
}

func (r *authAPIKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_api_key"
}

func (r *authAPIKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "An API key of a local user (System → Access → Users → API keys). OPNsense stores only a hash of the secret, so the secret is known only when Terraform creates the key; it is kept in state (sensitive) and is null after import. Keys cannot be changed: any change creates a new key.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true, PlanModifiers: keep, Description: "The key."},
			"user":   schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Description: "Login name of the user (`opnsense_auth_user.x.name`)."},
			"key":    schema.StringAttribute{Computed: true, PlanModifiers: keep, Description: "API key (the username part of basic auth)."},
			"secret": schema.StringAttribute{Computed: true, Sensitive: true, PlanModifiers: keep, Description: "API secret; only available for keys Terraform created."},
		},
	}
}

func (r *authAPIKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m authAPIKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := r.client.Auth.AddAPIKey(ctx, m.User.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create API key", err.Error())
		return
	}
	m.ID, m.Key, m.Secret = types.StringValue(k.Key), types.StringValue(k.Key), types.StringValue(k.Secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *authAPIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m authAPIKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := r.client.Auth.APIKey(ctx, m.ID.ValueString())
	if errors.Is(err, opnsense.ErrNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read API key", err.Error())
		return
	}
	m.User, m.Key = types.StringValue(k.Username), types.StringValue(k.Key)
	if m.Secret.IsUnknown() {
		m.Secret = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Update is never called with a change (user forces replacement); it keeps the state.
func (r *authAPIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, req.State)...)
}

func (r *authAPIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m authAPIKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Auth.DeleteAPIKey(ctx, m.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to delete API key", err.Error())
	}
}

// ImportState accepts the key; the secret stays null.
func (r *authAPIKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("secret"), types.StringNull())...)
}
