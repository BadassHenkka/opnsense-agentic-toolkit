package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// ImportState accepts the identifier (`lan`, `opt3`) or the description (`IOT`).
func (r *genNetworkInterfaceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	as := r.client.Interfaces.Assignments
	id := req.ID
	if _, err := as.Get(ctx, id); err != nil {
		if !errors.Is(err, opnsense.ErrNotFound) {
			resp.Diagnostics.AddError("Unable to import interface", err.Error())
			return
		}
		if id, err = opnsense.ResolveByName(ctx, as, req.ID); err != nil {
			resp.Diagnostics.AddError("Unable to import interface", err.Error())
			return
		}
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
