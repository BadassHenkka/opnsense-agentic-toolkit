package opnsense_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestFilterRules(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	f := fake.Client(t).Filter

	allowDNS := opnsense.FilterRule{
		Enabled: true, Action: "pass", Quick: true, Interface: opnsense.CSVList{"opt3"}, Direction: "in",
		IPProtocol: "inet", Protocol: "TCP/UDP", SourceNet: opnsense.CSVList{"opt3"},
		DestinationNet: opnsense.CSVList{"192.168.1.1"}, DestinationPort: "53", StateType: "keep",
		Description: "site2: DNS",
	}
	dns, err := f.Rules.Add(ctx, allowDNS)
	if err != nil {
		t.Fatal(err)
	}
	blockAll := allowDNS
	blockAll.Action, blockAll.Protocol, blockAll.DestinationNet, blockAll.DestinationPort = "block", "any", opnsense.CSVList{"lan"}, ""
	blockAll.Description = "site2: block LAN"
	block, err := f.Rules.Add(ctx, blockAll)
	if err != nil {
		t.Fatal(err)
	}

	// Without a sequence, rules are appended (+100 each).
	r1, _ := f.Rules.Get(ctx, dns)
	r2, _ := f.Rules.Get(ctx, block)
	if r1.Sequence != opnsense.IntOf(100) || r2.Sequence != opnsense.IntOf(200) {
		t.Fatalf("sequences %v, %v", r1.Sequence, r2.Sequence)
	}
	if !slices.Equal(r1.Interface, []string{"opt3"}) || r1.Protocol != "TCP/UDP" || r1.DestinationPort != "53" {
		t.Fatalf("decoded %+v", r1)
	}

	// An update keeps the sequence (it is sent back) and does not send audit data.
	r1.Description = "site2: DNS to firewall"
	if err := f.Rules.Set(ctx, dns, *r1); err != nil {
		t.Fatal(err)
	}
	if rec, _ := fake.Get("rule", dns); rec["sequence"] != "100" {
		t.Fatalf("sequence after update: %v", rec["sequence"])
	}

	if err := f.MoveBefore(ctx, block, dns); err != nil {
		t.Fatal(err)
	}
	if r2, _ = f.Rules.Get(ctx, block); r2.Sequence.Value >= 100 {
		t.Fatalf("moved rule sequence %v", r2.Sequence)
	}

	// Search includes automatic rules, but name look-ups only match API-managed rules.
	res, err := f.SearchInterface(ctx, "opt3", "")
	if err != nil || res.Total != 5 {
		t.Fatalf("search: %+v, %v", res, err)
	}
	if _, err := opnsense.ResolveByName(ctx, f.Rules, "Anti-Lockout Rule"); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("legacy rule resolved: %v", err)
	}
	if id, err := opnsense.ResolveByName(ctx, f.Rules, "site2: block LAN"); err != nil || id != block {
		t.Fatalf("resolve = %q, %v", id, err)
	}

	// Validation from the model comes through.
	bad := allowDNS
	bad.Protocol = "any"
	var ve *opnsense.ValidationError
	if _, err := f.Rules.Add(ctx, bad); !errors.As(err, &ve) || ve.Fields["rule.destination_port"] == "" {
		t.Fatalf("port without tcp/udp: %v", err)
	}

	if name, err := f.ResolveInterface(ctx, "wg_site2"); err != nil || name != "opt3" {
		t.Fatalf("ResolveInterface = %q, %v", name, err)
	}
	if err := f.ApplyAndVerify(ctx, time.Second); err != nil {
		t.Fatalf("ApplyAndVerify: %v", err)
	}
}

func TestFilterApplyDetectsLockout(t *testing.T) {
	fake := opnsensetest.New(t)
	fake.LockOutAfter = "firewall/filter/apply"
	err := fake.Client(t).Filter.ApplyAndVerify(context.Background(), time.Second)
	if err == nil || !strings.Contains(err.Error(), "no longer reachable") {
		t.Fatalf("want lockout error, got %v", err)
	}
}

// A field missing from FilterRuleRow silently disappears from firewall_rule_list. Leaving out
// source_not once made inverted rules read as their opposite.
func TestFilterRuleRowHasEveryField(t *testing.T) {
	jsonNames := func(v any) map[string]bool {
		names := map[string]bool{}
		typ := reflect.TypeOf(v)
		for i := range typ.NumField() {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			names[name] = true
		}
		return names
	}
	row := jsonNames(opnsense.FilterRuleRow{})
	for name := range jsonNames(opnsense.FilterRule{}) {
		if !row[name] {
			t.Errorf("FilterRuleRow has no field for %q", name)
		}
	}
}
