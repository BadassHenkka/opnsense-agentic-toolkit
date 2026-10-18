package provider

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var (
	_ resource.ResourceWithImportState    = (*firewallRuleResource)(nil)
	_ resource.ResourceWithValidateConfig = (*firewallRuleResource)(nil)
)

// NewFirewallRuleResource returns the opnsense_firewall_rule resource.
func NewFirewallRuleResource() resource.Resource { return &firewallRuleResource{} }

type firewallRuleResource struct{ baseResource }

type firewallRuleModel struct {
	ID              types.String `tfsdk:"id"`
	Description     types.String `tfsdk:"description"`
	Sequence        types.Int64  `tfsdk:"sequence"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	Action          types.String `tfsdk:"action"`
	Quick           types.Bool   `tfsdk:"quick"`
	Interfaces      types.Set    `tfsdk:"interfaces"`
	InterfaceNot    types.Bool   `tfsdk:"interface_not"`
	Direction       types.String `tfsdk:"direction"`
	IPProtocol      types.String `tfsdk:"ip_protocol"`
	Protocol        types.String `tfsdk:"protocol"`
	Source          types.Set    `tfsdk:"source"`
	SourceNot       types.Bool   `tfsdk:"source_not"`
	SourcePort      types.String `tfsdk:"source_port"`
	Destination     types.Set    `tfsdk:"destination"`
	DestinationNot  types.Bool   `tfsdk:"destination_not"`
	DestinationPort types.String `tfsdk:"destination_port"`
	Gateway         types.String `tfsdk:"gateway"`
	Log             types.Bool   `tfsdk:"log"`
	StateType       types.String `tfsdk:"state_type"`
	Categories      types.Set    `tfsdk:"categories"`
}

func anySet() types.Set {
	return types.SetValueMust(types.StringType, []attr.Value{types.StringValue("any")})
}

func (r *firewallRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

func (r *firewallRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	b := func(def bool, desc string) schema.BoolAttribute {
		return schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(def), Description: desc}
	}
	str := func(def, desc string, v ...validator.String) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(def),
			Description: desc, Validators: v}
	}
	addrSet := func(desc string) schema.SetAttribute {
		return schema.SetAttribute{ElementType: types.StringType, Optional: true, Computed: true,
			Default: setdefault.StaticValue(anySet()), Description: desc}
	}
	resp.Schema = schema.Schema{
		Description: "A firewall filter rule (Firewall → Rules). Rules are evaluated in `sequence` order and, with " +
			"`quick`, the first match wins. Every change reloads the rules and then checks over a new connection " +
			"that the API is still reachable; if not, the apply fails with a lockout warning. OPNsense has no " +
			"automatic rollback.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute("rule"),
			"description": schema.StringAttribute{Required: true,
				Description: "Describes the rule; also used to import it."},
			"sequence": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "Evaluation order, lower first. Omit to append at the end; OPNsense then assigns " +
					"the next free number (+100). Set explicit numbers with gaps (100, 200, ...) to control order.",
				Validators:    []validator.Int64{int64validator.Between(1, 999999)},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"enabled": enabledAttribute(),
			"action":  str("pass", "pass, block, reject or match.", stringvalidator.OneOf(opnsense.FilterActions...)),
			"quick":   b(true, "First match wins. With false, the last matching rule wins (pf semantics)."),
			"interfaces": schema.SetAttribute{
				ElementType: types.StringType, Optional: true, Computed: true,
				Default:     setdefault.StaticValue(emptyStringSet()),
				Description: "Assigned interface or group names (`lan`, `opt3`). Empty makes a floating rule.",
			},
			"interface_not": b(false, "Match every interface except these."),
			"direction":     str("in", "in, out or any.", stringvalidator.OneOf("in", "out", "any")),
			"ip_protocol":   str("inet", "inet (IPv4), inet6 or inet46.", stringvalidator.OneOf("inet", "inet6", "inet46")),
			"protocol":      str("any", "any, TCP, UDP, TCP/UDP, ICMP, ... (upper case, as in the UI)."),
			"source": addrSet("`any`, CIDRs, addresses, alias names, or interface networks such as `lan` " +
				"(network) and `lanip` (address)."),
			"source_not":       b(false, "Invert the source (single entry only)."),
			"source_port":      str("", "Port, range (`1000-2000`) or port alias. TCP/UDP only."),
			"destination":      addrSet("Same forms as source."),
			"destination_not":  b(false, "Invert the destination (single entry only)."),
			"destination_port": str("", "Port, range or port alias. TCP/UDP only."),
			"gateway": str("", "Policy routing: send matching traffic to this gateway, e.g. "+
				"`opnsense_gateway.site2.name`."),
			"log":        b(false, "Log packets that match."),
			"state_type": str("keep", "keep, sloppy, modulate, synproxy or none.", stringvalidator.OneOf("keep", "sloppy", "modulate", "synproxy", "none")),
			"categories": schema.SetAttribute{
				ElementType: types.StringType, Optional: true, Computed: true,
				Default:     setdefault.StaticValue(emptyStringSet()),
				Description: "Category UUIDs.",
			},
		},
	}
}

// ValidateConfig mirrors the model checks OPNsense would reject, at plan time.
func (r *firewallRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m firewallRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Protocol.IsUnknown() {
		return
	}
	tcpudp := slices.Contains([]string{"TCP", "UDP", "TCP/UDP"}, m.Protocol.ValueString())
	for _, p := range []struct {
		name string
		v    types.String
	}{{"source_port", m.SourcePort}, {"destination_port", m.DestinationPort}} {
		if !p.v.IsNull() && !p.v.IsUnknown() && p.v.ValueString() != "" && !tcpudp {
			resp.Diagnostics.AddAttributeError(path.Root(p.name), "Port without TCP/UDP",
				"Ports are only valid when protocol is TCP, UDP or TCP/UDP.")
		}
	}
	for _, s := range []struct {
		name string
		set  types.Set
		not  types.Bool
	}{{"source", m.Source, m.SourceNot}, {"destination", m.Destination, m.DestinationNot}} {
		if s.set.IsNull() || s.set.IsUnknown() {
			continue
		}
		var vals []string
		s.set.ElementsAs(ctx, &vals, false)
		if len(vals) > 1 && slices.Contains(vals, "any") {
			resp.Diagnostics.AddAttributeError(path.Root(s.name), "Invalid "+s.name, "`any` cannot be combined with other entries.")
		}
		if s.not.ValueBool() && len(vals) > 1 {
			resp.Diagnostics.AddAttributeError(path.Root(s.name+"_not"), "Invalid inversion",
				"Inverting is only allowed for a single entry.")
		}
	}
}

func (m *firewallRuleModel) toAPI(ctx context.Context) (opnsense.FilterRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	r := opnsense.FilterRule{
		Enabled: opnsense.Bool(m.Enabled.ValueBool()), Sequence: apiInt(m.Sequence),
		Action: opnsense.Option(m.Action.ValueString()), Quick: opnsense.Bool(m.Quick.ValueBool()),
		InterfaceNot: opnsense.Bool(m.InterfaceNot.ValueBool()), Direction: opnsense.Option(m.Direction.ValueString()),
		IPProtocol: opnsense.Option(m.IPProtocol.ValueString()), Protocol: opnsense.Option(m.Protocol.ValueString()),
		SourceNot: opnsense.Bool(m.SourceNot.ValueBool()), SourcePort: m.SourcePort.ValueString(),
		DestinationNot: opnsense.Bool(m.DestinationNot.ValueBool()), DestinationPort: m.DestinationPort.ValueString(),
		Gateway: opnsense.Option(m.Gateway.ValueString()), Log: opnsense.Bool(m.Log.ValueBool()),
		StateType: opnsense.Option(m.StateType.ValueString()), Description: m.Description.ValueString(),
	}
	diags.Append(m.Interfaces.ElementsAs(ctx, (*[]string)(&r.Interface), false)...)
	diags.Append(m.Source.ElementsAs(ctx, (*[]string)(&r.SourceNet), false)...)
	diags.Append(m.Destination.ElementsAs(ctx, (*[]string)(&r.DestinationNet), false)...)
	diags.Append(m.Categories.ElementsAs(ctx, (*[]string)(&r.Categories), false)...)
	return r, diags
}

func (m *firewallRuleModel) fromAPI(ctx context.Context, id string, r *opnsense.FilterRule) diag.Diagnostics {
	var diags, d diag.Diagnostics
	m.ID = types.StringValue(id)
	m.Description = types.StringValue(r.Description)
	if r.Sequence.Valid || !m.Sequence.IsUnknown() {
		m.Sequence = int64Value(r.Sequence)
	}
	m.Enabled = types.BoolValue(bool(r.Enabled))
	m.Action = types.StringValue(string(r.Action))
	m.Quick = types.BoolValue(bool(r.Quick))
	m.Interfaces, d = types.SetValueFrom(ctx, types.StringType, nonNil(r.Interface))
	diags.Append(d...)
	m.InterfaceNot = types.BoolValue(bool(r.InterfaceNot))
	m.Direction = types.StringValue(string(r.Direction))
	m.IPProtocol = types.StringValue(string(r.IPProtocol))
	m.Protocol = types.StringValue(string(r.Protocol))
	m.Source, d = types.SetValueFrom(ctx, types.StringType, nonNil(r.SourceNet))
	diags.Append(d...)
	m.SourceNot = types.BoolValue(bool(r.SourceNot))
	m.SourcePort = types.StringValue(r.SourcePort)
	m.Destination, d = types.SetValueFrom(ctx, types.StringType, nonNil(r.DestinationNet))
	diags.Append(d...)
	m.DestinationNot = types.BoolValue(bool(r.DestinationNot))
	m.DestinationPort = types.StringValue(r.DestinationPort)
	m.Gateway = types.StringValue(string(r.Gateway))
	m.Log = types.BoolValue(bool(r.Log))
	m.StateType = types.StringValue(string(r.StateType))
	m.Categories, d = types.SetValueFrom(ctx, types.StringType, nonNil(r.Categories))
	diags.Append(d...)
	return diags
}

func (m *firewallRuleModel) itemID() string { return m.ID.ValueString() }

// ruleVerifyWait is how long to wait for the API to answer after reloading rules.
var ruleVerifyWait = 15 * time.Second

var firewallRuleCRUD = itemCRUD[opnsense.FilterRule, opnsense.FilterRuleRow, firewallRuleModel, *firewallRuleModel]{
	what: "firewall rule",
	items: func(c *opnsense.Client) *opnsense.ItemController[opnsense.FilterRule, opnsense.FilterRuleRow] {
		return c.Filter.Rules
	},
	apply: func(c *opnsense.Client) func(context.Context) error {
		return func(ctx context.Context) error { return c.Filter.ApplyAndVerify(ctx, ruleVerifyWait) }
	},
}

func (r *firewallRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	firewallRuleCRUD.create(ctx, r.client, req, resp)
}

func (r *firewallRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	firewallRuleCRUD.read(ctx, r.client, req, resp)
}

func (r *firewallRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	firewallRuleCRUD.update(ctx, r.client, req, resp)
}

func (r *firewallRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	firewallRuleCRUD.delete(ctx, r.client, req, resp)
}

// ImportState accepts a UUID or the rule description (unique among API-managed rules).
func (r *firewallRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp, r.client.Filter.Rules, "firewall rule")
}
