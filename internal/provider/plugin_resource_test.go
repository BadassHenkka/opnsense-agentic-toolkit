package provider

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func pluginPlan(name string, thirdParty bool) pluginModel {
	return pluginModel{ID: types.StringUnknown(), Name: types.StringValue(name),
		AllowThirdParty: types.BoolValue(thirdParty), Version: types.StringUnknown(),
		Repository: types.StringUnknown(), Tier: types.StringUnknown()}
}

func pluginHarness(t *testing.T) (*harness, *opnsensetest.Server) {
	fake := opnsensetest.New(t)
	fake.AddPackage(opnsensetest.FakePackage{Name: "os-adguardhome-maxit", Version: "1.19", Repository: "mimugmail"})
	h := newHarness(t, fake, NewPluginResource())
	h.r.(*pluginResource).client.Firmware.PollInterval = 5 * time.Millisecond
	return h, fake
}

func createDiags(h *harness, plan pluginModel) string {
	resp := resource.CreateResponse{State: h.state()}
	h.r.Create(h.ctx, resource.CreateRequest{Plan: h.plan(plan)}, &resp)
	if !resp.Diagnostics.HasError() {
		return ""
	}
	return resp.Diagnostics.Errors()[0].Detail()
}

func TestPluginResource(t *testing.T) {
	h, fake := pluginHarness(t)

	var got pluginModel
	st, ok := h.create(pluginPlan("os-ddclient", false), &got)
	if !ok || got.Version.ValueString() != "1.27" || got.Tier.ValueString() != "2" || !fake.PackageInstalled("os-ddclient") {
		t.Fatalf("install: %+v", got)
	}

	// Removed outside Terraform: read drops it, so the next apply reinstalls it.
	other := fake.Client(t).Firmware
	other.PollInterval = 5 * time.Millisecond
	if _, err := other.Remove(h.ctx, "os-ddclient"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.read(st, &got); ok {
		t.Fatal("read should drop a removed plugin")
	}

	// Already installed: adopted without a job.
	if _, ok := h.create(pluginPlan("os-acme-client", false), &got); !ok || got.Repository.ValueString() != "OPNsense" {
		t.Fatalf("adopt: %+v", got)
	}

	// Third-party packages need an explicit opt-in.
	if msg := createDiags(h, pluginPlan("os-adguardhome-maxit", false)); !strings.Contains(msg, "allow_third_party") {
		t.Fatalf("third-party without opt-in: %q", msg)
	}
	st, ok = h.create(pluginPlan("os-adguardhome-maxit", true), &got)
	if !ok || got.Tier.ValueString() != "4" || !fake.PackageInstalled("os-adguardhome-maxit") {
		t.Fatalf("third-party with opt-in: %+v", got)
	}
	h.delete(st)
	if fake.PackageInstalled("os-adguardhome-maxit") {
		t.Fatal("delete did not remove the package")
	}

	if msg := createDiags(h, pluginPlan("os-unknown", true)); !strings.Contains(msg, "cannot add repositories") {
		t.Fatalf("unknown package: %q", msg)
	}
}
