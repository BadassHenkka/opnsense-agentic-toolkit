package mcpserver_test

import (
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

func TestWireguardToolsFlow(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"wireguard"}})
	must := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		out, ok := call(t, cs, tool, args)
		if !ok {
			t.Fatalf("%s: %v", tool, out)
		}
		return out
	}

	inst := must("wireguard_instance_create", map[string]any{
		"name": "roadwarrior", "tunnel_addresses": []string{"10.10.10.1/24"}, "dns": []string{"10.10.10.1"},
	})
	instID, instPub := inst["uuid"].(string), inst["public_key"].(string)
	rec, _ := fake.Get("server", instID)
	if derived, _ := opnsense.WireguardPublicKey(rec["privkey"]); derived != instPub || rec["port"] != "51820" {
		t.Fatalf("instance keys/port: %v", rec)
	}

	// Generated peer: the response carries a complete client config, the firewall keeps only the public key.
	peer := must("wireguard_peer_create", map[string]any{
		"name": "phone", "instances": []map[string]any{{"name": "roadwarrior"}},
		"tunnel_addresses": []string{"10.10.10.2/32"}, "generate_psk": true,
		"firewall_endpoint": "vpn.example.com:51820",
	})
	cfg := peer["client_config"].(string)
	for _, want := range []string{"PublicKey = " + instPub, "Endpoint = vpn.example.com:51820",
		"DNS = 10.10.10.1", "Address = 10.10.10.2/32", "PresharedKey = ", "PrivateKey = "} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("client config lacks %q:\n%s", want, cfg)
		}
	}
	peerID := peer["uuid"].(string)
	if prec, _ := fake.Get("client", peerID); prec["privkey"] != "" || prec["pubkey"] != peer["public_key"] {
		t.Fatalf("peer stored %v (device private key must not be stored)", prec)
	}

	got := must("wireguard_instance_get", map[string]any{"name": "roadwarrior"})
	peers := got["peers"].([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["name"] != "phone" || got["interface"] != "wg0" {
		t.Fatalf("instance view: %v", got)
	}
	if _, leaked := got["private_key"]; leaked {
		t.Fatal("instance private key exposed")
	}

	p := must("wireguard_peer_get", map[string]any{"name": "phone"})
	if p["preshared_key_set"] != true {
		t.Fatalf("peer view: %v", p)
	}
	if strings.Contains(strings.Join(func() []string {
		var s []string
		for _, v := range p {
			if str, ok := v.(string); ok {
				s = append(s, str)
			}
		}
		return s
	}(), " "), "PrivateKey") {
		t.Fatal("peer view leaks keys")
	}

	// Updating the instance keeps the peer attached.
	must("wireguard_instance_update", map[string]any{"uuid": instID, "listen_port": 51821})
	if list := must("wireguard_peer_list", map[string]any{"instance": map[string]any{"uuid": instID}}); list["total"].(float64) != 1 {
		t.Fatalf("peer list by instance: %v", list)
	}

	// Detach and reattach the peer.
	must("wireguard_peer_update", map[string]any{"name": "phone", "instances": []any{}})
	if rec, _ := fake.Get("server", instID); rec["peers"] != "" {
		t.Fatalf("peer still attached: %v", rec["peers"])
	}
	must("wireguard_peer_update", map[string]any{"name": "phone", "instances": []map[string]any{{"uuid": instID}}})

	must("wireguard_settings_update", map[string]any{"enabled": true})
	must("wireguard_apply", map[string]any{})
	st := must("wireguard_status", map[string]any{"instance": "wg0"})
	if rows := st["rows"].([]any); len(rows) != 2 || rows[1].(map[string]any)["peer-status"] != "online" {
		t.Fatalf("status: %v", st)
	}

	must("wireguard_peer_delete", map[string]any{"name": "phone"})
	if rec, _ := fake.Get("server", instID); rec["peers"] != "" {
		t.Fatalf("deleted peer still attached: %v", rec["peers"])
	}
}

func TestWireguardToolErrors(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{Toolsets: []string{"wireguard"}})
	if out, ok := call(t, cs, "wireguard_instance_create", map[string]any{"name": "a", "tunnel_addresses": []string{"10.0.0.1/24"}}); !ok {
		t.Fatal(out)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"wireguard_instance_create", map[string]any{"name": "b", "tunnel_addresses": []string{"10.0.0.1"}}, "CIDR"},
		{"wireguard_instance_create", map[string]any{"name": "b", "tunnel_addresses": []string{"10.0.0.1/24"}, "private_key": "nope"}, "private_key"},
		{"wireguard_peer_create", map[string]any{"name": "p", "instances": []map[string]any{{"name": "a"}}, "tunnel_addresses": []string{"10.0.0.2/32"}}, "firewall_endpoint"},
		{"wireguard_peer_create", map[string]any{"name": "p", "instances": []map[string]any{{"name": "a"}}, "tunnel_addresses": []string{"10.0.0.2/32"}, "public_key": "bad"}, "public_key"},
		{"wireguard_peer_create", map[string]any{"name": "p", "instances": []map[string]any{{"name": "zz"}}, "tunnel_addresses": []string{"10.0.0.2/32"}, "public_key": "bad"}, `no WireGuard instance named "zz"`},
	} {
		out, ok := call(t, cs, tc.tool, tc.args)
		if ok || !strings.Contains(out["error"].(string), tc.want) {
			t.Errorf("%s %v: want error containing %q, got %v", tc.tool, tc.args, tc.want, out)
		}
	}
}
