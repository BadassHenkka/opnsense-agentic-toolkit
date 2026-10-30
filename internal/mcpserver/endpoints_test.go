package mcpserver_test

import (
	"context"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
)

// endpoints records the API endpoints each tool calls; connect adds it to every server.
var endpoints privileges.Recorder

// recordTool files the API calls of each tool call under the tool's name.
func recordTool(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if r, ok := req.(*mcp.CallToolRequest); ok {
			ctx = endpoints.Context(ctx, r.Params.Name)
		}
		return next(ctx, method, req)
	}
}

func TestMain(m *testing.M) {
	os.Exit(endpoints.Main(m.Run, "../privileges/endpoints/mcp.json"))
}

// TestToolEndpoints calls the tools no other test reaches, so their endpoints get recorded.
// Objects that don't exist are enough for most: the tool calls the API before it fails.
func TestToolEndpoints(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{})
	ctx := context.Background()
	c := fake.Client(t)
	missing := []map[string]any{{"name": "missing"}, {"uuid": "00000000-0000-4000-8000-00000000ffff"}}
	for _, name := range []string{
		"acme_account_delete", "acme_account_register", "acme_automation_delete", "acme_automation_get",
		"acme_certificate_revoke", "acme_certificate_run_automations", "acme_challenge_type_delete",
		"caddy_domain_delete", "caddy_handler_delete", "caddy_subdomain_delete", "firewall_rule_delete",
		"routing_gateway_get", "unbound_host_alias_delete", "wireguard_instance_delete",
	} {
		for _, args := range missing {
			call(t, cs, name, args)
		}
	}
	call(t, cs, "acme_automation_fields", map[string]any{})

	// Updates read the object first, so they need one that exists.
	acct, err := c.Acme.Accounts.Add(ctx, opnsense.AcmeAccount{Enabled: true, Name: "le", CA: "letsencrypt", Email: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	call(t, cs, "acme_account_update", map[string]any{"uuid": acct, "description": "x"})
	auto, err := c.Acme.Automations.Add(ctx, opnsense.AcmeAutomation{Enabled: true, Name: "restart", Type: "configd_restart_gui"})
	if err != nil {
		t.Fatal(err)
	}
	call(t, cs, "acme_automation_update", map[string]any{"uuid": auto, "description": "x"})
	gw, err := c.Routing.Gateways.Add(ctx, opnsense.Gateway{Name: "GW_TEST", Interface: "wan", IPProtocol: "inet", Address: "192.0.2.1", Priority: opnsense.IntOf(255), Weight: opnsense.IntOf(1)})
	if err != nil {
		t.Fatal(err)
	}
	call(t, cs, "routing_gateway_update", map[string]any{"uuid": gw, "description": "x"})
}
