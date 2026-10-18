package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Services → Wake on LAN (plugin os-wol): the action that sends the magic packet. Actions
// need Terraform 1.14 or later.

var macAttrRe = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

// opnsense_wol_host is generated (gen/specs/wol.json); macAttrRe is its extra validator.

// ---- action ----

var (
	_ action.ActionWithConfigure      = (*wolWakeAction)(nil)
	_ action.ActionWithValidateConfig = (*wolWakeAction)(nil)
)

// NewWolWakeAction returns the opnsense_wol_wake action.
func NewWolWakeAction() action.Action { return &wolWakeAction{} }

type wolWakeAction struct {
	client *opnsense.Client
}

type wolWakeModel struct {
	HostID    types.String `tfsdk:"host_id"`
	Interface types.String `tfsdk:"interface"`
	MAC       types.String `tfsdk:"mac"`
}

func (a *wolWakeAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wol_wake"
}

func (a *wolWakeAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = actionschema.Schema{
		Description: "Send a Wake on LAN magic packet from the firewall. Give host_id (a saved " +
			"opnsense_wol_host), or interface and mac. Run with `terraform apply -invoke=action.opnsense_wol_wake.<name>`, " +
			"or trigger it from a resource's lifecycle with action_trigger.",
		Attributes: map[string]actionschema.Attribute{
			"host_id":   actionschema.StringAttribute{Optional: true, Description: "ID of an opnsense_wol_host."},
			"interface": actionschema.StringAttribute{Optional: true, Description: "Assigned interface, e.g. `lan`, with mac."},
			"mac":       actionschema.StringAttribute{Optional: true, Description: "MAC address, with interface."},
		},
	}
}

func (a *wolWakeAction) Configure(_ context.Context, req action.ConfigureRequest, resp *action.ConfigureResponse) {
	c, ok := clientFrom(req.ProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	a.client = c
}

func (a *wolWakeAction) ValidateConfig(ctx context.Context, req action.ValidateConfigRequest, resp *action.ValidateConfigResponse) {
	var m wolWakeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	byHost := !m.HostID.IsNull()
	byMAC := !m.Interface.IsNull() || !m.MAC.IsNull()
	switch {
	case byHost && byMAC:
		resp.Diagnostics.AddError("Conflicting arguments", "Give host_id, or interface and mac, not both.")
	case !byHost && (m.Interface.IsNull() || m.MAC.IsNull()):
		resp.Diagnostics.AddError("Missing arguments", "Give host_id, or both interface and mac.")
	case byMAC && !m.MAC.IsUnknown():
		if _, err := opnsense.NormalizeMAC(m.MAC.ValueString()); err != nil {
			resp.Diagnostics.AddError("Invalid MAC address", err.Error())
		}
	}
}

func (a *wolWakeAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var m wolWakeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var err error
	target := m.HostID.ValueString()
	if !m.HostID.IsNull() {
		err = a.client.Wol.Wake(ctx, target)
	} else {
		target = m.MAC.ValueString() + " on " + m.Interface.ValueString()
		err = a.client.Wol.WakeMAC(ctx, m.Interface.ValueString(), m.MAC.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Wake on LAN failed", err.Error())
		return
	}
	if resp.SendProgress != nil {
		resp.SendProgress(action.InvokeProgressEvent{Message: "Magic packet sent to " + target})
	}
}
