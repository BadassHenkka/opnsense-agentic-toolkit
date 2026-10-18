package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// itemModel is a Terraform model backed by an OPNsense item of type T.
// Compile-time checks: the hand-written models satisfy the interfaces itemCRUD calls through
// its type parameters (linters do not follow those calls).
var (
	_ itemModel[opnsense.AcmeAutomation]             = (*acmeAutomationModel)(nil)
	_ itemModel[opnsense.AcmeChallengeType]          = (*acmeChallengeTypeModel)(nil)
	_ interface{ setPrior(*acmeAutomationModel) }    = (*acmeAutomationModel)(nil)
	_ interface{ setPrior(*acmeChallengeTypeModel) } = (*acmeChallengeTypeModel)(nil)
)

type itemModel[T any] interface {
	// toAPI converts the planned values to the API model.
	toAPI(ctx context.Context) (T, diag.Diagnostics)
	// fromAPI fills the model (including id) from the API model.
	fromAPI(ctx context.Context, id string, item *T) diag.Diagnostics
	// itemID returns the stored id.
	itemID() string
}

// itemCRUD implements Create/Read/Update/Delete for any resource backed by an ItemController.
// Every write is followed by apply, so each resource converges on its own.
//
// M is the model struct; PM is *M, which must implement itemModel[T]. This is the usual Go
// trick for calling pointer methods on a generic type.
type itemCRUD[T, S, M any, PM interface {
	*M
	itemModel[T]
}] struct {
	what  string // for messages, e.g. "firewall alias"
	items func(*opnsense.Client) *opnsense.ItemController[T, S]
	apply func(*opnsense.Client) func(context.Context) error
}

func (c itemCRUD[T, S, M, PM]) create(ctx context.Context, client *opnsense.Client, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	item, diags := PM(&plan).toAPI(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := c.items(client).Add(ctx, item)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create "+c.what, err.Error())
		return
	}
	// Save the id before applying, so a failed apply leaves a tracked (tainted) resource
	// rather than an orphan in the OPNsense config.
	resp.Diagnostics.Append(PM(&plan).fromAPI(ctx, id, &item)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := c.apply(client)(ctx); err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("%s created but apply failed", c.what), err.Error())
		return
	}
	c.refresh(ctx, client, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (c itemCRUD[T, S, M, PM]) read(ctx context.Context, client *opnsense.Client, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	item, err := c.items(client).Get(ctx, PM(&state).itemID())
	if errors.Is(err, opnsense.ErrNotFound) {
		resp.State.RemoveResource(ctx) // deleted outside Terraform: plan will recreate it
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read "+c.what, err.Error())
		return
	}
	resp.Diagnostics.Append(PM(&state).fromAPI(ctx, PM(&state).itemID(), item)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (c itemCRUD[T, S, M, PM]) update(ctx context.Context, client *opnsense.Client, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Models with pass-through params need the prior state to clear removed keys.
	if p, ok := any(PM(&plan)).(interface{ setPrior(*M) }); ok {
		p.setPrior(&state)
	}
	item, diags := PM(&plan).toAPI(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := PM(&state).itemID()
	if err := c.items(client).Set(ctx, id, item); err != nil {
		resp.Diagnostics.AddError("Unable to update "+c.what, err.Error())
		return
	}
	if err := c.apply(client)(ctx); err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("%s updated but apply failed", c.what), err.Error())
		return
	}
	c.refresh(ctx, client, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (c itemCRUD[T, S, M, PM]) delete(ctx context.Context, client *opnsense.Client, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := c.items(client).Delete(ctx, PM(&state).itemID())
	if errors.Is(err, opnsense.ErrNotFound) {
		return // already gone, e.g. a host alias removed together with its host override
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete "+c.what, err.Error())
		return
	}
	if err := c.apply(client)(ctx); err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("%s deleted but apply failed", c.what), err.Error())
	}
}

// refresh re-reads the item after a write, so state holds what OPNsense actually stored.
func (c itemCRUD[T, S, M, PM]) refresh(ctx context.Context, client *opnsense.Client, id string, m *M, diags *diag.Diagnostics) {
	item, err := c.items(client).Get(ctx, id)
	if err != nil {
		diags.AddError("Unable to read "+c.what+" after write", err.Error())
		return
	}
	diags.Append(PM(m).fromAPI(ctx, id, item)...)
}
