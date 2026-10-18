package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var _ resource.ResourceWithImportState = (*pluginResource)(nil)

// pluginJobTimeout bounds one install or remove; pkg jobs can be slow on small boxes.
var pluginJobTimeout = 15 * time.Minute

// NewPluginResource returns the opnsense_plugin resource.
func NewPluginResource() resource.Resource { return &pluginResource{} }

type pluginResource struct{ baseResource }

type pluginModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	AllowThirdParty types.Bool   `tfsdk:"allow_third_party"`
	Version         types.String `tfsdk:"version"`
	Repository      types.String `tfsdk:"repository"`
	Tier            types.String `tfsdk:"tier"`
}

func (r *pluginResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plugin"
}

func (r *pluginResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An installed OPNsense plugin or package (System → Firmware → Plugins). Creating installs it " +
			"and destroying removes it; both wait for the package job. Configure the plugin with its own resources.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{
				Required: true, Description: "Package name, e.g. `os-ddclient`.",
				Validators:    []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`^[a-zA-Z0-9._+-]+$`), "must be a package name")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"allow_third_party": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Allow packages from repositories other than OPNsense and SunnyValley (tier 4, " +
					"not reviewed by the OPNsense team), e.g. `os-adguardhome-maxit` from the mimugmail repository.",
			},
			"version":    schema.StringAttribute{Computed: true, Description: "Installed version."},
			"repository": schema.StringAttribute{Computed: true, Description: "Repository the package came from."},
			"tier":       schema.StringAttribute{Computed: true, Description: "Support tier: 1 core … 3 community, 4 third-party/unknown."},
		},
	}
}

func (m *pluginModel) load(p *opnsense.Package) {
	m.ID = types.StringValue(string(p.Name))
	m.Version = types.StringValue(string(p.Version))
	m.Repository = types.StringValue(string(p.Repository))
	m.Tier = types.StringValue(string(p.Tier))
}

func (r *pluginResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pluginModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	fw := r.client.Firmware
	p, err := fw.Find(ctx, name)
	if errors.Is(err, opnsense.ErrNotFound) {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "Package not available",
			fmt.Sprintf("No configured repository provides %q. Community repositories must be added on the "+
				"firewall first (the API cannot add repositories).", name))
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read packages", err.Error())
		return
	}
	if p.ThirdParty() && !plan.AllowThirdParty.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("allow_third_party"), "Third-party package",
			fmt.Sprintf("%s comes from the %q repository (tier 4, not reviewed by OPNsense). Set "+
				"allow_third_party = true to install it.", name, p.Repository))
		return
	}
	if !p.IsInstalled() {
		jobCtx, cancel := context.WithTimeout(ctx, pluginJobTimeout)
		defer cancel()
		if _, err := fw.Install(jobCtx, name); err != nil {
			resp.Diagnostics.AddError("Unable to install "+name, err.Error())
			return
		}
		if p, err = fw.Find(ctx, name); err != nil {
			resp.Diagnostics.AddError("Unable to read "+name+" after install", err.Error())
			return
		}
	}
	plan.load(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pluginResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pluginModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.Firmware.Find(ctx, state.Name.ValueString())
	if errors.Is(err, opnsense.ErrNotFound) || (err == nil && !p.IsInstalled()) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read packages", err.Error())
		return
	}
	state.load(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update only changes allow_third_party, which has no effect on the firewall.
func (r *pluginResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state pluginModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	plan.ID, plan.Version, plan.Repository, plan.Tier = state.ID, state.Version, state.Repository, state.Tier
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pluginResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state pluginModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	p, err := r.client.Firmware.Find(ctx, name)
	if errors.Is(err, opnsense.ErrNotFound) || (err == nil && !p.IsInstalled()) {
		return
	}
	jobCtx, cancel := context.WithTimeout(ctx, pluginJobTimeout)
	defer cancel()
	if _, err := r.client.Firmware.Remove(jobCtx, name); err != nil {
		resp.Diagnostics.AddError("Unable to remove "+name, err.Error())
	}
}

// ImportState takes the package name: terraform import opnsense_plugin.ddclient os-ddclient
// allow_third_party is set to whether the package is third-party, so an imported official
// plugin matches a config that leaves it at its default.
func (r *pluginResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	thirdParty := true // if the package can't be looked up, Read removes it anyway
	if p, err := r.client.Firmware.Find(ctx, req.ID); err == nil {
		thirdParty = p.ThirdParty()
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("allow_third_party"), thirdParty)...)
}
