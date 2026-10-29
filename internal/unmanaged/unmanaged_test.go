package unmanaged_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
	"github.com/smulis/opnsense-agentic-toolkit/internal/provider"
	"github.com/smulis/opnsense-agentic-toolkit/internal/unmanaged"
)

// stateJSON renders resources like `tofu show -json`, with a secret attribute next to each id.
func stateJSON(t *testing.T, res ...[3]string) string {
	t.Helper()
	var rs []map[string]any
	for _, r := range res {
		rs = append(rs, map[string]any{
			"address": r[0] + "." + r[1], "mode": "managed", "type": r[0], "name": r[1],
			"provider_name": "registry.opentofu.org/smulis/opnsense",
			"values":        map[string]any{"id": r[2], "private_key": "SECRET-" + r[1]},
		})
	}
	b, err := json.Marshal(map[string]any{
		"format_version": "1.0",
		"values": map[string]any{"root_module": map[string]any{
			"resources":     []any{map[string]any{"address": "data.opnsense_x.y", "mode": "data", "type": "opnsense_x", "values": map[string]any{"id": "d"}}},
			"child_modules": []any{map[string]any{"resources": rs}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestFind(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	c := fake.Client(t)
	id := must[string](t)

	managedAlias := id(c.Firewall.Aliases.Add(ctx, opnsense.Alias{Enabled: true, Name: "managed", Type: "host", Content: opnsense.LineList{"10.0.0.1"}}))
	guiAlias := id(c.Firewall.Aliases.Add(ctx, opnsense.Alias{Enabled: true, Name: "gui_added", Type: "host", Content: opnsense.LineList{"10.0.0.2"}}))
	managedRule := id(c.Filter.Rules.Add(ctx, opnsense.FilterRule{Enabled: true, Action: "pass", Description: "managed rule"}))
	guiRule := id(c.Filter.Rules.Add(ctx, opnsense.FilterRule{Enabled: true, Action: "block", Description: "gui\x1b[2J rule"}))
	host := id(c.Unbound.HostOverrides.Add(ctx, opnsense.HostOverride{Enabled: true, Hostname: "nas", Domain: "home.lan", RR: "A", Server: "10.0.0.6"}))
	fwd := id(c.Unbound.Forwards.Add(ctx, opnsense.UnboundForward{Enabled: true, Domain: "corp.example", Server: "10.9.0.1"}))
	dot := id(c.Unbound.DoTs.Add(ctx, opnsense.UnboundDoT{Enabled: true, Server: "9.9.9.9", Verify: "dns.quad9.net"}))

	st, err := unmanaged.ReadState(strings.NewReader(stateJSON(t,
		[3]string{"opnsense_firewall_alias", "managed", managedAlias},
		[3]string{"opnsense_firewall_rule", "managed", managedRule},
		[3]string{"opnsense_unbound_forward", "x", "00000000-0000-4000-8000-0000000000ff"},
		[3]string{"opnsense_unbound_dot", "x", "00000000-0000-4000-8000-0000000000fe"},
		[3]string{"opnsense_firewall_nat_port_forward", "none", "00000000-0000-4000-8000-0000000000fd"},
		[3]string{"opnsense_plugin", "acme", "os-acme-client"},
		[3]string{"opnsense_unbound_settings", "this", "unbound_settings"},
		[3]string{"opnsense_auth_api_key", "ci", "abc"},
	)))
	if err != nil {
		t.Fatal(err)
	}

	rep := unmanaged.Find(ctx, c, st, []string{"opnsense_unbound_host_override"})
	if len(rep.Errors) > 0 {
		t.Fatal(rep.Errors)
	}
	var got []string
	for _, o := range rep.Missing {
		got = append(got, fmt.Sprintf("%s %s %s", o.Type, o.ID, o.Name))
	}
	// Not listed: the built-in aliases, the automatic and legacy rules, the automatic NAT
	// rule, and the installed plugin that is in the state.
	want := []string{
		"opnsense_firewall_alias " + guiAlias + " gui_added",
		"opnsense_firewall_rule " + guiRule + " gui\x1b[2J rule",
		"opnsense_unbound_dot " + dot + " (all domains) -> 9.9.9.9",
		"opnsense_unbound_forward " + fwd + " corp.example -> 10.9.0.1",
		"opnsense_unbound_host_override " + host + " nas.home.lan A",
	}
	if !slices.Equal(got, want) {
		t.Errorf("missing:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(rep.Unchecked, []string{"opnsense_auth_api_key"}) {
		t.Errorf("unchecked %v", rep.Unchecked)
	}
	if !slices.Contains(rep.Checked, "opnsense_unbound_host_override") || slices.Contains(rep.Checked, "opnsense_x") {
		t.Errorf("checked %v", rep.Checked)
	}

	rep = unmanaged.Find(ctx, c, st, []string{"opnsense_nope"})
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error(), "opnsense_nope") {
		t.Errorf("errors %v", rep.Errors)
	}
}

func TestReadState(t *testing.T) {
	// A saved plan has the state under prior_state.
	plan := `{"prior_state":{"values":{"root_module":{"resources":[{"address":"opnsense_vlan.a","mode":"managed","type":"opnsense_vlan","values":{"id":"u1","secret":"s"}}]}}},"planned_values":{"secret":"s"}}`
	st, err := unmanaged.ReadState(strings.NewReader(plan))
	if err != nil || !st.IDs["opnsense_vlan"]["u1"] || !st.Addresses["opnsense_vlan.a"] {
		t.Fatalf("got %+v, %v", st, err)
	}
	// An empty state has no values.
	if st, err := unmanaged.ReadState(strings.NewReader(`{"format_version":"1.0"}`)); err != nil || len(st.IDs) != 0 {
		t.Fatalf("empty: %+v, %v", st, err)
	}
	// Errors never quote the input.
	for _, in := range []string{`{"values": SECRET}`, `{"values":{"root_module":{"resources":[{"values":{"id":12345}}]}}}`, ``} {
		_, err := unmanaged.ReadState(strings.NewReader(in))
		if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "12345") {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// Every type the helper lists must be a resource type of the provider.
func TestTypesAreProviderResources(t *testing.T) {
	p := provider.New("test")()
	have := map[string]bool{}
	for _, f := range p.Resources(context.Background()) {
		var resp resource.MetadataResponse
		f().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "opnsense"}, &resp)
		have[resp.TypeName] = true
	}
	for _, typ := range unmanaged.Types() {
		if !have[typ] {
			t.Errorf("%s is not a provider resource", typ)
		}
	}
}
