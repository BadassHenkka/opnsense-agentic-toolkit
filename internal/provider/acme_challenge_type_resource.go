package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var (
	_ resource.ResourceWithImportState    = (*acmeChallengeTypeResource)(nil)
	_ resource.ResourceWithValidateConfig = (*acmeChallengeTypeResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*acmeChallengeTypeResource)(nil)
)

// NewAcmeChallengeTypeResource returns the opnsense_acme_challenge_type resource.
func NewAcmeChallengeTypeResource() resource.Resource { return &acmeChallengeTypeResource{} }

type acmeChallengeTypeResource struct{ baseResource }

type acmeChallengeTypeModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Method      types.String `tfsdk:"method"`
	DNSService  types.String `tfsdk:"dns_service"`
	DNSSleep    types.Int64  `tfsdk:"dns_sleep"`
	Params      types.Map    `tfsdk:"params"`
	Enabled     types.Bool   `tfsdk:"enabled"`

	prior *acmeChallengeTypeModel // state before an update; see setPrior
}

func (m *acmeChallengeTypeModel) setPrior(p *acmeChallengeTypeModel) { m.prior = p }

func (r *acmeChallengeTypeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_challenge_type"
}

func (r *acmeChallengeTypeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An ACME challenge type (Services → ACME Client → Challenge Types): how domain " +
			"ownership is proven.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("challenge type"),
			"name":        schema.StringAttribute{Required: true},
			"description": optionalString(""),
			"method": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("dns01"),
				Description: "dns01, http01 or tlsalpn01.",
				Validators:  []validator.String{stringvalidator.OneOf(opnsense.AcmeChallengeMethods...)},
			},
			"dns_service": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "DNS provider for dns01, as the acme.sh hook name, e.g. `dns_cf` for Cloudflare.",
				// Unused for other methods; OPNsense then stores its default. Keep it stable.
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"dns_sleep": schema.Int64Attribute{
				Optional: true, Computed: true, Default: int64default.StaticInt64(0),
				Description: "Seconds to wait for DNS propagation; 0 lets acme.sh decide.",
				Validators:  []validator.Int64{int64validator.AtLeast(0)},
			},
			"params": paramsAttribute("Method or provider fields by their OPNsense name, e.g. " +
				"`{ dns_cf_token = var.cf_token }` for dns_cf, or `http_service` for http01. Only the keys set " +
				"here are managed; removing a key clears it."),
			"enabled": enabledAttribute(),
		},
	}
}

func (r *acmeChallengeTypeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m acmeChallengeTypeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Method.IsUnknown() {
		return
	}
	method := m.Method.ValueString()
	if m.Method.IsNull() {
		method = "dns01"
	}
	if method == "dns01" && m.DNSService.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("dns_service"), "Missing attribute",
			"dns_service is required when method is dns01.")
	}
}

// ModifyPlan checks param names against OPNsense at plan time. OPNsense would silently drop
// an unknown field, so a typo would otherwise only show up as perpetual drift.
func (r *acmeChallengeTypeResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.client == nil {
		return
	}
	var params types.Map
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("params"), &params)...)
	checkParamKeys(ctx, params, r.client.Acme.ChallengeTypeTemplate, &resp.Diagnostics)
}

func checkParamKeys(ctx context.Context, params types.Map, template func(context.Context) (*opnsense.AcmeTemplate, error), diags *diag.Diagnostics) {
	if params.IsNull() || params.IsUnknown() {
		return
	}
	t, err := template(ctx)
	if err != nil {
		diags.AddWarning("Could not check params", err.Error())
		return
	}
	var unknown []string
	for k := range params.Elements() {
		if _, ok := t.Defaults[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		diags.AddAttributeError(path.Root("params"), "Unknown OPNsense fields",
			fmt.Sprintf("OPNsense has no field %s.", strings.Join(unknown, ", ")))
	}
}

func (m *acmeChallengeTypeModel) toAPI(ctx context.Context) (opnsense.AcmeChallengeType, diag.Diagnostics) {
	prior := types.MapNull(types.StringType)
	if m.prior != nil {
		prior = m.prior.Params
	}
	params, diags := paramsToAPI(ctx, m.Params, prior)
	v := opnsense.AcmeChallengeType{
		Enabled: opnsense.Bool(m.Enabled.ValueBool()), Name: m.Name.ValueString(),
		Description: m.Description.ValueString(), Method: opnsense.Option(m.Method.ValueString()),
		DNSService: opnsense.Option(m.DNSService.ValueString()), DNSSleep: apiInt(m.DNSSleep),
		Params: params,
	}
	if m.DNSService.IsNull() || m.DNSService.IsUnknown() {
		v.DNSService = "dns_freedns" // the model's default; the field is required even when unused
	}
	return v, diags
}

func (m *acmeChallengeTypeModel) fromAPI(ctx context.Context, id string, v *opnsense.AcmeChallengeType) diag.Diagnostics {
	m.ID = types.StringValue(id)
	m.Name = types.StringValue(v.Name)
	m.Description = types.StringValue(v.Description)
	m.Method = types.StringValue(string(v.Method))
	m.DNSService = types.StringValue(string(v.DNSService))
	m.DNSSleep = int64Value(v.DNSSleep)
	m.Enabled = types.BoolValue(bool(v.Enabled))
	var diags diag.Diagnostics
	m.Params, diags = paramsFromAPI(ctx, m.Params, v.Params)
	return diags
}

func (m *acmeChallengeTypeModel) itemID() string { return m.ID.ValueString() }

var acmeChallengeTypeCRUD = itemCRUD[opnsense.AcmeChallengeType, opnsense.AcmeChallengeTypeRow, acmeChallengeTypeModel, *acmeChallengeTypeModel]{
	what: "ACME challenge type",
	items: func(c *opnsense.Client) *opnsense.ItemController[opnsense.AcmeChallengeType, opnsense.AcmeChallengeTypeRow] {
		return c.Acme.ChallengeTypes
	},
	apply: func(c *opnsense.Client) func(context.Context) error { return c.Acme.Apply },
}

func (r *acmeChallengeTypeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	acmeChallengeTypeCRUD.create(ctx, r.client, req, resp)
}

func (r *acmeChallengeTypeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	acmeChallengeTypeCRUD.read(ctx, r.client, req, resp)
}

func (r *acmeChallengeTypeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	acmeChallengeTypeCRUD.update(ctx, r.client, req, resp)
}

func (r *acmeChallengeTypeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	acmeChallengeTypeCRUD.delete(ctx, r.client, req, resp)
}

// ImportState accepts a UUID or name. params start empty: add the keys you want to manage
// to the configuration, and the next apply takes them over.
func (r *acmeChallengeTypeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp, r.client.Acme.ChallengeTypes, "ACME challenge type")
}
