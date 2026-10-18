package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// settingsModel is a Terraform model backed by a settings section of type T.
type settingsModel[T any] interface {
	toAPI(ctx context.Context) (T, diag.Diagnostics)
	// fromAPI fills the model from the API, including the constant id.
	fromAPI(ctx context.Context, item *T) diag.Diagnostics
}

// settingsCRUD implements a singleton resource over a SettingsController. There is exactly one
// such section per firewall, so Create and Update both write it. Delete calls disable when
// set (e.g. to turn a service off) and otherwise only forgets the resource.
type settingsCRUD[T, M any, PM interface {
	*M
	settingsModel[T]
}] struct {
	what    string
	id      string
	ctl     func(*opnsense.Client) *opnsense.SettingsController[T]
	disable func(*T)
}

func (c settingsCRUD[T, M, PM]) write(ctx context.Context, client *opnsense.Client, plan *M, diags *diag.Diagnostics) {
	v, d := PM(plan).toAPI(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	ctl := c.ctl(client)
	if err := ctl.Set(ctx, v); err != nil {
		diags.AddError("Unable to save "+c.what, err.Error())
		return
	}
	if err := ctl.Apply(ctx); err != nil {
		diags.AddError(c.what+" saved but apply failed", err.Error())
		return
	}
	got, err := ctl.Get(ctx)
	if err != nil {
		diags.AddError("Unable to read "+c.what+" after write", err.Error())
		return
	}
	diags.Append(PM(plan).fromAPI(ctx, got)...)
}

func (c settingsCRUD[T, M, PM]) create(ctx context.Context, client *opnsense.Client, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c.write(ctx, client, &plan, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (c settingsCRUD[T, M, PM]) read(ctx context.Context, client *opnsense.Client, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := c.ctl(client).Get(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read "+c.what, err.Error())
		return
	}
	resp.Diagnostics.Append(PM(&state).fromAPI(ctx, got)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (c settingsCRUD[T, M, PM]) update(ctx context.Context, client *opnsense.Client, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c.write(ctx, client, &plan, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (c settingsCRUD[T, M, PM]) delete(ctx context.Context, client *opnsense.Client, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if c.disable == nil {
		return // settings cannot be removed; the firewall keeps the current values
	}
	ctl := c.ctl(client)
	cur, err := ctl.Get(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read "+c.what, err.Error())
		return
	}
	c.disable(cur)
	if err := ctl.Set(ctx, *cur); err != nil {
		resp.Diagnostics.AddError("Unable to disable "+c.what, err.Error())
		return
	}
	if err := ctl.Apply(ctx); err != nil {
		resp.Diagnostics.AddError(c.what+" disabled but apply failed", err.Error())
	}
}

func (c settingsCRUD[T, M, PM]) importState(ctx context.Context, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), c.id)...)
}
