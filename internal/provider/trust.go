package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Trust (CAs and certificates). OPNsense acts on the volatile `action` field on every add
// and set: `internal` generates a new key and certificate, `reissue` re-signs. So the
// generated resources send the configured method only on create; an update (only the
// description can change in place) re-imports the certificate OPNsense already has
// (`existing` for a CA, `manual` for a certificate), which leaves it untouched.
//
// Creation parameters are write-only: OPNsense does not store them (key type, lifetime) or
// derives them from the certificate. A change replaces the item, except when the state has
// no value yet, which happens after an import: then the configured value is adopted.

const replaceDesc = "Changing this creates a new item (imported items adopt the configured value)."

func replaceOnChangeString() planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
		resp.RequiresReplace = !req.StateValue.IsNull() && !req.PlanValue.IsUnknown()
	}, replaceDesc, replaceDesc)
}

func replaceOnChangeInt64() planmodifier.Int64 {
	return int64planmodifier.RequiresReplaceIf(func(_ context.Context, req planmodifier.Int64Request, resp *int64planmodifier.RequiresReplaceIfFuncResponse) {
		resp.RequiresReplace = !req.StateValue.IsNull() && !req.PlanValue.IsUnknown()
	}, replaceDesc, replaceDesc)
}

func (m *genTrustCAModel) hookToAPI(_ context.Context, v *opnsense.TrustCA) diag.Diagnostics {
	if !m.ID.IsUnknown() && !m.ID.IsNull() {
		v.Action = "existing"
	}
	return nil
}

func (m *genTrustCertModel) hookToAPI(_ context.Context, v *opnsense.TrustCert) diag.Diagnostics {
	if !m.ID.IsUnknown() && !m.ID.IsNull() {
		v.Action, v.CSR = "manual", ""
	}
	return nil
}
