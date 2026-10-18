package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// baseResource holds the API client and implements Configure for every resource.
type baseResource struct {
	client *opnsense.Client
}

func (b *baseResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c, ok := clientFrom(req.ProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	b.client = c
}

func emptyStringSet() types.Set { return types.SetValueMust(types.StringType, []attr.Value{}) }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// int64Value maps an optional OPNsense integer to a nullable Terraform value.
func int64Value(i opnsense.Int) types.Int64 {
	if !i.Valid {
		return types.Int64Null()
	}
	return types.Int64Value(i.Value)
}

// apiInt maps a nullable Terraform integer to an optional OPNsense integer.
func apiInt(v types.Int64) opnsense.Int {
	if v.IsNull() || v.IsUnknown() {
		return opnsense.Int{}
	}
	return opnsense.IntOf(v.ValueInt64())
}

func idAttribute(what string) schema.StringAttribute {
	return schema.StringAttribute{
		Computed:      true,
		Description:   "UUID of the " + what + ".",
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func optionalString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: desc}
}

func enabledAttribute() schema.BoolAttribute {
	return schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)}
}

// importByName accepts a UUID or a unique name.
func importByName[T any, S opnsense.NamedRow](ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse, ic *opnsense.ItemController[T, S], what string) {
	id := req.ID
	if !uuidRe.MatchString(id) {
		var err error
		id, err = opnsense.ResolveByName(ctx, ic, req.ID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to import "+what, err.Error())
			return
		}
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
