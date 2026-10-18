package mcpserver_test

import (
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

func TestCaddyTools(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"caddy"}})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	must("caddy_settings_update", map[string]any{"enabled": true, "acme_email": "me@example.com",
		"dns_provider": "cloudflare", "dns_api_key": "token"})
	st := must("caddy_status", map[string]any{})
	if st["enabled"] != true || st["dns_api_key_set"] != true || strings.Contains(strings.ToLower(st["dns_provider"].(string)), "token") {
		t.Fatalf("status %v", st)
	}
	if _, leaked := st["dns_api_key"]; leaked {
		t.Fatal("status must not return the DNS API key")
	}

	// A plain hostname creates a domain and a handler.
	out := must("caddy_expose", map[string]any{"hostname": "Grafana.example.com", "upstream": "192.168.1.30", "port": 3000})
	if len(out["created"].([]any)) != 2 || out["staged"] != true {
		t.Fatalf("expose: %v", out)
	}
	h, _ := fake.Get("handle", out["handler_uuid"].(string))
	if h["ToDomain"] != "192.168.1.30" || h["ToPort"] != "3000" || h["HttpTls"] != "0" || h["description"] != "grafana.example.com" {
		t.Fatalf("handler stored %v", h)
	}
	// Exposing the same hostname and path again is refused, and nothing is left behind.
	if out, ok := call(t, cs, "caddy_expose", map[string]any{"hostname": "grafana.example.com", "upstream": "x", "port": 1}); ok ||
		!strings.Contains(out["error"].(string), "already has a handler") {
		t.Fatalf("duplicate expose: %v", out)
	}
	// Another path on the same domain reuses it.
	out = must("caddy_expose", map[string]any{"hostname": "grafana.example.com", "path": "/api/*", "strip_path": true,
		"upstream": "192.168.1.31", "port": 8443, "scheme": "https", "insecure_skip_verify": true})
	if len(out["created"].([]any)) != 1 {
		t.Fatalf("second path should only add a handler: %v", out)
	}

	// Under a wildcard domain, a subdomain is created instead. (No MCP tool creates wildcards:
	// they need DNS-01 credentials, which belong in Terraform or the UI.)
	if _, err := fake.Client(t).Caddy.Domains.Add(t.Context(), opnsense.CaddyDomain{Enabled: true,
		Domain: "*.lan.example.com", DisableTLS: opnsense.CaddyDomainHTTPS, DNSChallenge: true}); err != nil {
		t.Fatal(err)
	}
	must("caddy_access_list_create", map[string]any{"name": "lan", "client_ips": []string{"192.168.1.0/24"}, "response_code": 403})
	out = must("caddy_expose", map[string]any{"hostname": "nas.lan.example.com", "upstream": "192.168.1.10", "port": 5000,
		"access_list": "lan"})
	if out["subdomain_uuid"] == nil || !strings.HasPrefix(out["created"].([]any)[0].(string), "subdomain") {
		t.Fatalf("wildcard expose: %v", out)
	}
	if h, _ := fake.Get("handle", out["handler_uuid"].(string)); h["subdomain"] != out["subdomain_uuid"] || h["accesslist"] == "" {
		t.Fatalf("handler under subdomain %v", h)
	}

	must("caddy_handler_update", map[string]any{"name": "nas.lan.example.com", "scheme": "https", "upstreams": []string{"192.168.1.11"}})
	got := must("caddy_handler_get", map[string]any{"name": "nas.lan.example.com"})
	if got["upstream_scheme"] != "https" || got["upstreams"].([]any)[0] != "192.168.1.11" {
		t.Fatalf("handler after update %v", got)
	}

	// Safe delete: the access list is still used.
	if out, ok := call(t, cs, "caddy_access_list_delete", map[string]any{"name": "lan"}); ok || !strings.Contains(out["error"].(string), "in use") {
		t.Fatalf("delete used access list: %v", out)
	}

	must("caddy_apply", map[string]any{})
	if file := must("caddy_caddyfile_get", map[string]any{})["caddyfile"].(string); !strings.Contains(file, "grafana.example.com {") ||
		!strings.Contains(file, "https://192.168.1.31:8443") {
		t.Fatalf("caddyfile:\n%s", file)
	}
	if fake.Applies["caddy/service/reconfigure"] != 1 {
		t.Fatalf("applies %v", fake.Applies)
	}
}
