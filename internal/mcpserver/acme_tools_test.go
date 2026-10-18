package mcpserver_test

import (
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
)

func TestAcmeToolsFlow(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"acme"}})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	// Discovery: providers, then one provider's fields.
	out := must("acme_challenge_type_fields", map[string]any{"method": "dns01", "search": "cf"})
	if opts := out["options"].([]any); len(opts) != 1 || opts[0] != "dns_cf" {
		t.Fatalf("provider search: %v", out)
	}
	out = must("acme_challenge_type_fields", map[string]any{"method": "dns01", "dns_service": "dns_cf"})
	var tokenSecret bool
	for _, f := range out["fields"].([]any) {
		f := f.(map[string]any)
		if f["name"] == "dns_cf_token" {
			tokenSecret = f["secret"] == true
		}
		if !strings.HasPrefix(f["name"].(string), "dns_cf_") {
			t.Errorf("unexpected field %v", f["name"])
		}
	}
	if !tokenSecret {
		t.Fatalf("dns_cf_token missing or not marked secret: %v", out)
	}

	acct := must("acme_account_create", map[string]any{"name": "le-staging", "email": "a@example.com", "ca": "letsencrypt_test"})["uuid"].(string)
	must("acme_challenge_type_create", map[string]any{
		"name": "cloudflare", "dns_service": "dns_cf",
		"params": map[string]any{"dns_cf_token": "s3cret", "dns_cf_account_id": "acc1"},
	})
	must("acme_automation_create", map[string]any{"name": "restart-gui", "type": "configd_restart_gui"})

	// Secrets go in, but never come back out.
	ch := must("acme_challenge_type_get", map[string]any{"name": "cloudflare"})
	params := ch["params"].(map[string]any)
	if params["dns_cf_token"] != "(set, hidden)" || params["dns_cf_account_id"] != "acc1" {
		t.Fatalf("challenge params: %v", params)
	}
	if _, leaked := params["dns_loopia_api"]; leaked {
		t.Fatalf("other providers' defaults should not be listed: %v", params)
	}
	// Partial params update keeps other params.
	must("acme_challenge_type_update", map[string]any{"name": "cloudflare", "params": map[string]any{"dns_cf_zone_id": "z1"}})
	id := ch["uuid"].(string)
	if rec, _ := fake.Get("validation", id); rec["dns_cf_token"] != "s3cret" || rec["dns_cf_zone_id"] != "z1" {
		t.Fatalf("after partial update: %v", rec)
	}

	cert := must("acme_certificate_create", map[string]any{
		"name": "fw.example.com", "alt_names": []string{"vpn.example.com"},
		"account": map[string]any{"name": "le-staging"}, "challenge_type": map[string]any{"name": "cloudflare"},
		"automations": []map[string]any{{"name": "restart-gui"}}, "key_length": "key_ec256",
	})["uuid"].(string)
	got := must("acme_certificate_get", map[string]any{"name": "fw.example.com"})
	if got["account_uuid"] != acct || got["status"] != "pending" || len(got["automation_uuids"].([]any)) != 1 {
		t.Fatalf("certificate: %v", got)
	}

	// Issuing needs the client enabled.
	if out, ok := call(t, cs, "acme_certificate_issue", map[string]any{"uuid": cert}); ok ||
		!strings.Contains(out["error"].(string), "disabled") {
		t.Fatalf("issue while disabled: %v", out)
	}
	must("acme_settings_update", map[string]any{"enabled": true, "environment": "stg"})
	must("acme_apply", map[string]any{})
	if out := must("acme_certificate_issue", map[string]any{"name": "fw.example.com"}); out["started"] != true {
		t.Fatalf("issue: %v", out)
	}
	got = must("acme_certificate_get", map[string]any{"uuid": cert})
	if got["status"] != "ok" || got["last_issued"] == "" || got["cert_ref_id"] == "" {
		t.Fatalf("after issue: %v", got)
	}

	must("acme_certificate_update", map[string]any{"uuid": cert, "alt_names": []string{"vpn.example.com", "www.example.com"}})
	if rec, _ := fake.Get("certificate", cert); rec["altNames"] != "vpn.example.com,www.example.com" || rec["keyLength"] != "key_ec256" {
		t.Fatalf("after update: %v", rec)
	}
	must("acme_certificate_delete", map[string]any{"uuid": cert})
}

func TestAcmeToolErrors(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{Toolsets: []string{"acme"}})
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"acme_challenge_type_create", map[string]any{"name": "x"}, "needs dns_service"},
		{"acme_challenge_type_create", map[string]any{"name": "x", "dns_service": "dns_cf", "params": map[string]any{"dns_cf_tokn": "t"}}, "unknown params dns_cf_tokn"},
		{"acme_account_create", map[string]any{"name": "x", "ca": "custom"}, "custom_ca"},
		{"acme_certificate_create", map[string]any{"name": "a.example.com", "account": map[string]any{"name": "nope"}, "challenge_type": map[string]any{"name": "nope"}}, `no account named "nope"`},
		{"acme_settings_update", map[string]any{"environment": "test"}, "not one of"},
		{"acme_certificate_get", map[string]any{}, "give either uuid or name"},
	} {
		out, ok := call(t, cs, tc.tool, tc.args)
		if ok || !strings.Contains(out["error"].(string), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", tc.tool, tc.want, out)
		}
	}
}
