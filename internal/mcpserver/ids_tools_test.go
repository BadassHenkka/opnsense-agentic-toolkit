package mcpserver_test

import (
	"context"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestIDSRulesetList(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"ids"}})
	if err := fake.Client(t).IDS.SetRulesetEnabled(context.Background(), "emerging-scan.rules", true); err != nil {
		t.Fatal(err)
	}
	out, ok := call(t, cs, "ids_ruleset_list", map[string]any{})
	if !ok || out["total"].(float64) != 2 {
		t.Fatalf("list %v", out)
	}
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		if (m["filename"] == "emerging-scan.rules") != m["enabled"].(bool) {
			t.Fatalf("item %v", m)
		}
	}
}
