package mcpserver_test

import (
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestFirmwareTools(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"firmware"}})
	fake.AddPackage(opnsensetest.FakePackage{Name: "os-adguardhome-maxit", Version: "1.19",
		Comment: "AdGuard Home", Repository: "mimugmail"})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	list := must("firmware_plugin_list", map[string]any{"search": "adguard"})
	plugins := list["plugins"].([]any)
	if len(plugins) != 1 || plugins[0].(map[string]any)["third_party"] != true {
		t.Fatalf("list: %v", list)
	}

	// Third-party needs explicit consent.
	if out, ok := call(t, cs, "firmware_plugin_install", map[string]any{"name": "os-adguardhome-maxit"}); ok ||
		!strings.Contains(out["error"].(string), "allow_third_party") {
		t.Fatalf("third-party without consent: %v", out)
	}
	out := must("firmware_plugin_install", map[string]any{"name": "os-adguardhome-maxit", "allow_third_party": true})
	if out["done"] != true || !fake.PackageInstalled("os-adguardhome-maxit") {
		t.Fatalf("install: %v", out)
	}
	if out := must("firmware_plugin_install", map[string]any{"name": "os-adguardhome-maxit"}); !strings.Contains(out["note"].(string), "already installed") {
		t.Fatalf("reinstall: %v", out)
	}
	must("firmware_plugin_remove", map[string]any{"name": "os-adguardhome-maxit"})
	if fake.PackageInstalled("os-adguardhome-maxit") {
		t.Fatal("not removed")
	}
	if out, ok := call(t, cs, "firmware_plugin_install", map[string]any{"name": "os-nope"}); ok ||
		!strings.Contains(out["error"].(string), "no configured repository") {
		t.Fatalf("unknown: %v", out)
	}

	fake.SetPendingUpdate("opnsense", "26.7.3", "26.7.4", true)
	st := must("firmware_status", map[string]any{"check": true})
	if st["status"] != "update" {
		t.Fatalf("status: %v", st)
	}
	up := must("firmware_update", map[string]any{})
	if up["reboot_required"] != true || !strings.Contains(up["note"].(string), "does not reboot") {
		t.Fatalf("update: %v", up)
	}
}
