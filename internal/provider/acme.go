package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// opnsense_acme_settings, opnsense_acme_account and opnsense_acme_certificate are generated
// (gen/specs/acme.json). Challenge types and automations are hand-written
// (acme_challenge_type_resource.go, acme_automation_resource.go): their provider-specific
// fields are passed through as params.

// lowerCaseRe validates certificate alt names.
var lowerCaseRe = regexp.MustCompile(`^[^A-Z\s]+$`)

var _ resource.ResourceWithValidateConfig = (*genAcmeAccountResource)(nil)

// ValidateConfig requires custom_ca with ca = custom.
func (r *genAcmeAccountResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m genAcmeAccountModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m.CA.ValueString() == "custom" && (m.CustomCA.IsNull() || m.CustomCA.ValueString() == "") && !m.CustomCA.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("custom_ca"), "Missing attribute", "custom_ca is required when ca is custom.")
	}
}
