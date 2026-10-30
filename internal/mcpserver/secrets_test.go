package mcpserver_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// TestNoToolReturnsSecrets seeds a unique marker into every field the specs mark sensitive,
// then calls every list tool, and the get tool that goes with it for each item listed. No
// marker may appear in any result: OPNsense returns most of these fields, so the tools must not.
func TestNoToolReturnsSecrets(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{})
	markers := fake.SeedSecrets("SENTINEL-SECRET-")
	if len(markers) < 20 {
		t.Fatalf("only %d sensitive fields seeded; did the specs lose their sensitive flags?", len(markers))
	}

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range tools.Tools {
		have[tl.Name] = true
	}

	leaks := map[string]string{}
	check := func(tool string, out map[string]any) {
		b, _ := json.Marshal(out)
		for _, m := range markers {
			if strings.Contains(string(b), m) {
				leaks[tool] = m
			}
		}
	}
	calls := 0
	for name := range have {
		switch {
		case strings.HasSuffix(name, "_list"):
			out, ok := call(t, cs, name, map[string]any{})
			if !ok {
				continue
			}
			calls++
			check(name, out)
			getName := strings.TrimSuffix(name, "_list") + "_get"
			items, _ := out["items"].([]any)
			for _, it := range items {
				row, _ := it.(map[string]any)
				if uuid, _ := row["uuid"].(string); uuid != "" && have[getName] {
					if got, ok := call(t, cs, getName, map[string]any{"uuid": uuid}); ok {
						calls++
						check(getName, got)
					}
				}
			}
		case strings.HasSuffix(name, "_settings_get"):
			if out, ok := call(t, cs, name, map[string]any{}); ok {
				calls++
				check(name, out)
			}
		}
	}
	if calls < 40 {
		t.Fatalf("only %d calls made; the test is not exercising the tools", calls)
	}
	for tool, m := range leaks {
		t.Errorf("%s returned the secret %s", tool, m)
	}
}

// TestListsKeepPublicKeys guards against over-redaction: a WireGuard public key is not a secret.
func TestListsKeepPublicKeys(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{Toolsets: []string{"wireguard"}})
	made, ok := call(t, cs, "wireguard_instance_create", map[string]any{
		"name": "wg0", "tunnel_addresses": []string{"10.10.10.1/24"}})
	if !ok {
		t.Fatal(made)
	}
	list, ok := call(t, cs, "wireguard_instance_list", map[string]any{})
	if !ok {
		t.Fatal(list)
	}
	row := list["items"].([]any)[0].(map[string]any)
	if row["pubkey"] == "" || row["pubkey"] != made["public_key"] {
		t.Fatalf("public key missing from the list: %v", row)
	}
	if _, has := row["privkey"]; has {
		t.Fatalf("private key in the list: %v", row)
	}
}

// TestUpdateOnlyHasNoSetFlag: OPNsense reads an update-only password back empty, so a
// password_set flag would always say false, even when a password is stored.
func TestUpdateOnlyHasNoSetFlag(t *testing.T) {
	ctx := context.Background()
	cs, fake := connect(t, mcpserver.Options{})
	c := fake.Client(t)
	if _, err := c.DynDNS.Accounts.Add(ctx, opnsense.DynDNSAccount{
		Enabled: true, Service: "cloudflare", Password: "token", Hostnames: opnsense.CSVList{"home.example.com"},
		Checkip: "web_icanhazip", CheckipTimeout: opnsense.IntOf(10), TTL: opnsense.IntOf(300), Description: "home",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Auth.Users.Add(ctx, opnsense.User{Name: "alice", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	for tool, name := range map[string]string{"dyndns_account_get": "home", "auth_user_get": "alice"} {
		out, ok := call(t, cs, tool, map[string]any{"name": name})
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		if v, has := out["password_set"]; has {
			t.Errorf("%s returned password_set=%v", tool, v)
		}
	}
}
