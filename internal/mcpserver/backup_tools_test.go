package mcpserver_test

import (
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestBackupAndSnapshotTools(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{Toolsets: []string{"backup"}})
	out, ok := call(t, cs, "backup_list", map[string]any{})
	if !ok || out["total"].(float64) != 2 {
		t.Fatalf("list %v", out)
	}
	first := out["items"].([]any)[0].(map[string]any)
	if first["bytes"].(float64) != 51000 {
		t.Fatalf("item %v", first)
	}
	d, ok := call(t, cs, "backup_diff_get", map[string]any{"newer": "config-1700000200.1.xml", "older": "config-1700000100.2.xml"})
	if !ok || d["changed"] != true || len(d["lines"].([]any)) != 4 {
		t.Fatalf("diff %v", d)
	}
	sn, ok := call(t, cs, "snapshot_list", map[string]any{})
	if !ok || sn["supported"] != true || sn["items"].([]any)[0].(map[string]any)["name"] != "pre-upgrade" {
		t.Fatalf("snapshots %v", sn)
	}
}
