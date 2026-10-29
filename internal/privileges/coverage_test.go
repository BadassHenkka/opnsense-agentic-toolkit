package privileges_test

import (
	"context"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
	"github.com/smulis/opnsense-agentic-toolkit/internal/provider"
)

// Every tool and resource needs recorded endpoints; a tool no test calls has none. Terraform
// actions (opnsense_wol_wake) are not resources and are not covered.
func TestEveryToolAndResourceHasEndpoints(t *testing.T) {
	tools, err := mcpserver.ListTools(context.Background(), mcpserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools {
		if len(privileges.ToolEndpoints(tool.Name)) == 0 {
			t.Errorf("no test calls tool %s; add it to TestToolEndpoints in internal/mcpserver", tool.Name)
		}
	}
	for _, typ := range provider.ResourceTypes() {
		if len(privileges.ResourceEndpoints(typ)) == 0 {
			t.Errorf("no test calls resource %s", typ)
		}
	}
}
