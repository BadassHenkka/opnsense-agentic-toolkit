package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// opnsense_unbound_host_override and opnsense_unbound_host_alias are generated
// (gen/specs/unbound.json). This file adds what a spec cannot say: per-record-type required
// fields, and import by name.

var (
	_ resource.ResourceWithValidateConfig = (*genHostOverrideResource)(nil)
	_ resource.ResourceWithValidateConfig = (*genHostAliasResource)(nil)
)

// ValidateConfig catches missing per-type fields at plan time, before OPNsense would.
func (r *genHostOverrideResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m genHostOverrideModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Type.IsUnknown() {
		return
	}
	rr := m.Type.ValueString()
	if m.Type.IsNull() {
		rr = "A"
	}
	// Values that are unknown (computed elsewhere) are fine; only flag ones that are null.
	missingStr := func(v types.String) bool { return v.IsNull() || (!v.IsUnknown() && v.ValueString() == "") }
	need := func(attr string) {
		resp.Diagnostics.AddAttributeError(path.Root(attr), "Missing attribute",
			fmt.Sprintf("%s is required when type is %s.", attr, rr))
	}
	switch rr {
	case "A", "AAAA":
		if missingStr(m.Server) {
			need("server")
		}
	case "MX":
		if missingStr(m.MX) {
			need("mx")
		}
		if m.MXPriority.IsNull() {
			need("mx_priority")
		}
	case "TXT":
		if missingStr(m.TXTData) {
			need("txt_data")
		}
	}
}

// ImportState accepts a UUID, a name, or name/TYPE when the name has several records:
//
//	terraform import opnsense_unbound_host_override.nas nas.home.lan/A
func (r *genHostOverrideResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	if !uuidRe.MatchString(id) {
		name, rr, _ := strings.Cut(req.ID, "/")
		rows, err := r.client.Unbound.FindHostOverrides(ctx, name, strings.ToUpper(rr))
		if err != nil {
			resp.Diagnostics.AddError("Unable to import host override", err.Error())
			return
		}
		switch len(rows) {
		case 0:
			resp.Diagnostics.AddError("Unable to import host override", fmt.Sprintf("no host override matches %q", req.ID))
			return
		case 1:
			id = string(rows[0].UUID)
		default:
			resp.Diagnostics.AddError("Unable to import host override",
				fmt.Sprintf("%q matches %d records; import as %s/TYPE or by UUID", req.ID, len(rows), name))
			return
		}
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

// ValidateConfig requires hostname, domain or both.
func (r *genHostAliasResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m genHostAliasModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Hostname.IsUnknown() || m.Domain.IsUnknown() {
		return
	}
	if m.Hostname.ValueString() == "" && m.Domain.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(path.Root("hostname"), "Missing attribute",
			"Set hostname, domain or both.")
	}
}

// ImportState accepts a UUID or the alias's full name (hostname.domain).
func (r *genHostAliasResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	if !uuidRe.MatchString(id) {
		rows, err := r.client.Unbound.FindHostAliases(ctx, req.ID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to import host alias", err.Error())
			return
		}
		if len(rows) != 1 {
			resp.Diagnostics.AddError("Unable to import host alias",
				fmt.Sprintf("%q matches %d host aliases; import by UUID", req.ID, len(rows)))
			return
		}
		id = string(rows[0].UUID)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
