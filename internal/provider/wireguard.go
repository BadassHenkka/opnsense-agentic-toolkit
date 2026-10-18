package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// The WireGuard resources are generated (gen/specs/wireguard.json). This file adds the
// instance's key handling: the private key is generated locally when not given, and the public
// key is always derived from it (OPNsense does not derive it).

var _ resource.ResourceWithModifyPlan = (*genWireguardInstanceResource)(nil)

// ModifyPlan derives public_key from private_key during planning, so a key change shows the
// new public key in the plan and dependent resources see it.
func (r *genWireguardInstanceResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy
	}
	var priv types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("private_key"), &priv)...)
	if priv.IsUnknown() || priv.IsNull() {
		return // generated during create; public_key stays unknown until then
	}
	pub, err := opnsense.WireguardPublicKey(priv.ValueString())
	if err != nil {
		return // the validator reports it
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("public_key"), pub)...)
}

// hookToAPI generates a private key when none is configured and sets the matching public key.
func (m *genWireguardInstanceModel) hookToAPI(_ context.Context, v *opnsense.WireguardInstance) diag.Diagnostics {
	var diags diag.Diagnostics
	if m.PrivateKey.IsUnknown() || m.PrivateKey.IsNull() || m.PrivateKey.ValueString() == "" {
		priv, _, err := opnsense.WireguardKeyPair()
		if err != nil {
			diags.AddError("Unable to generate a WireGuard key", err.Error())
			return diags
		}
		m.PrivateKey = types.StringValue(priv)
		v.PrivateKey = priv
	}
	pub, err := opnsense.WireguardPublicKey(v.PrivateKey)
	if err != nil {
		diags.AddAttributeError(path.Root("private_key"), "Invalid private key", err.Error())
		return diags
	}
	v.PublicKey = pub
	m.PublicKey = types.StringValue(pub)
	return diags
}

// hookFromAPI trusts the private key over a possibly stale stored public key.
func (m *genWireguardInstanceModel) hookFromAPI(_ context.Context, v *opnsense.WireguardInstance) diag.Diagnostics {
	if pub, err := opnsense.WireguardPublicKey(v.PrivateKey); err == nil {
		m.PublicKey = types.StringValue(pub)
	}
	return nil
}
