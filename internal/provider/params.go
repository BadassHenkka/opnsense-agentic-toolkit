package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Pass-through params (ACME challenge types and automations) are a map of OPNsense field
// names to values. Terraform manages only the keys in the configuration:
//
//   - read refreshes those keys and ignores every other field, so provider defaults and
//     fields set in the web UI do not show up as drift;
//   - a key removed from the configuration is cleared in OPNsense by sending it empty;
//   - a key OPNsense does not know is an error, because OPNsense would silently drop it.

func paramsAttribute(desc string) schema.MapAttribute {
	return schema.MapAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Sensitive:   true, // holds API tokens and passwords
		Description: desc,
	}
}

// paramsToAPI converts the planned map. Keys present in prior but not in plan are cleared.
func paramsToAPI(ctx context.Context, plan, prior types.Map) (opnsense.Params, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := opnsense.Params{}
	if !prior.IsNull() && !prior.IsUnknown() {
		var old map[string]string
		diags.Append(prior.ElementsAs(ctx, &old, false)...)
		for k := range old {
			out[k] = ""
		}
	}
	if !plan.IsNull() && !plan.IsUnknown() {
		var m map[string]string
		diags.Append(plan.ElementsAs(ctx, &m, false)...)
		for k, v := range m {
			out[k] = v
		}
	}
	return out, diags
}

// paramsFromAPI refreshes the managed keys of current from what OPNsense returned.
func paramsFromAPI(ctx context.Context, current types.Map, api opnsense.Params) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics
	if current.IsNull() || current.IsUnknown() {
		return types.MapNull(types.StringType), nil
	}
	var managed map[string]string
	diags.Append(current.ElementsAs(ctx, &managed, false)...)
	var unknown []string
	for k := range managed {
		v, ok := api[k]
		if !ok {
			unknown = append(unknown, k)
			continue
		}
		managed[k] = v
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		diags.AddAttributeError(path.Root("params"), "Unknown OPNsense fields",
			fmt.Sprintf("OPNsense has no field %s for this object. Check the field names in the web UI "+
				"or with the MCP *_fields tools.", strings.Join(unknown, ", ")))
	}
	m, d := types.MapValueFrom(ctx, types.StringType, managed)
	diags.Append(d...)
	return m, diags
}
