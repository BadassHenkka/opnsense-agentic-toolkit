package opnsense_test

import (
	"context"
	"errors"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestHostOverrideLifecycle(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	ub := fake.Client(t).Unbound

	a := opnsense.HostOverride{
		Enabled: true, Hostname: "nas", Domain: "home.lan", RR: "A",
		Server: "10.0.10.6", AddPTR: true, Description: "TrueNAS",
	}
	id, err := ub.HostOverrides.Add(ctx, a)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	rec, _ := fake.Get("host", id)
	if rec["rr"] != "A" || rec["mxprio"] != "" || rec["ttl"] != "" || rec["addptr"] != "1" {
		t.Fatalf("write form %v", rec)
	}

	// Same name, second record type.
	aaaa := a
	aaaa.RR, aaaa.Server = "AAAA", "fd00::6"
	if _, err := ub.HostOverrides.Add(ctx, aaaa); err != nil {
		t.Fatal(err)
	}

	got, err := ub.HostOverrides.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.FQDN() != "nas.home.lan" || got.RR != "A" || got.Server != "10.0.10.6" || got.TTL.Valid {
		t.Fatalf("Get decoded %+v", got)
	}

	got.TTL = opnsense.IntOf(300)
	if err := ub.HostOverrides.Set(ctx, id, *got); err != nil {
		t.Fatal(err)
	}
	if got, _ = ub.HostOverrides.Get(ctx, id); got.TTL != opnsense.IntOf(300) {
		t.Fatalf("ttl = %+v", got.TTL)
	}

	all, err := ub.FindHostOverrides(ctx, "NAS.home.lan.", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("FindHostOverrides(any) = %d rows, %v", len(all), err)
	}
	onlyA, _ := ub.FindHostOverrides(ctx, "nas.home.lan", "A")
	if len(onlyA) != 1 || string(onlyA[0].UUID) != id {
		t.Fatalf("FindHostOverrides(A) = %+v", onlyA)
	}

	// A host alias belongs to the override and disappears with it.
	aliasID, err := ub.HostAliases.Add(ctx, opnsense.HostAlias{
		Enabled: true, Host: opnsense.Option(id), Hostname: "truenas", Domain: "home.lan",
	})
	if err != nil {
		t.Fatalf("add alias: %v", err)
	}
	al, err := ub.HostAliases.Get(ctx, aliasID)
	if err != nil || string(al.Host) != id {
		t.Fatalf("alias Get = %+v, %v (relation should decode to the selected uuid)", al, err)
	}
	if rows, _ := ub.FindHostAliases(ctx, "truenas.home.lan"); len(rows) != 1 {
		t.Fatalf("FindHostAliases = %+v", rows)
	}

	if err := ub.Apply(ctx); err != nil || fake.Applies["unbound/service/reconfigure"] != 1 {
		t.Fatalf("Apply: %v", err)
	}

	if err := ub.HostOverrides.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := ub.HostAliases.Get(ctx, aliasID); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("alias should be deleted with its host, got %v", err)
	}
}

func TestHostOverrideValidation(t *testing.T) {
	ctx := context.Background()
	ub := opnsensetest.New(t).Client(t).Unbound

	_, err := ub.HostOverrides.Add(ctx, opnsense.HostOverride{Domain: "home.lan", RR: "MX", MX: "mail.home.lan"})
	var ve *opnsense.ValidationError
	if !errors.As(err, &ve) || ve.Fields["host.mxprio"] == "" {
		t.Fatalf("want mxprio validation error, got %v", err)
	}

	_, err = ub.HostAliases.Add(ctx, opnsense.HostAlias{Host: "00000000-0000-4000-8000-999999999999", Hostname: "x"})
	if !errors.As(err, &ve) || ve.Fields["alias.host"] == "" {
		t.Fatalf("want alias.host validation error, got %v", err)
	}
}

func TestIntAndTextTypes(t *testing.T) {
	var i opnsense.Int
	for in, want := range map[string]opnsense.Int{`""`: {}, `"25"`: opnsense.IntOf(25), `7`: opnsense.IntOf(7), `null`: {}} {
		if err := i.UnmarshalJSON([]byte(in)); err != nil || i != want {
			t.Errorf("Int(%s) = %+v, %v", in, i, err)
		}
	}
	if b, _ := opnsense.IntOf(10).MarshalJSON(); string(b) != `"10"` {
		t.Errorf("marshal = %s", b)
	}
	var x opnsense.Text
	for in, want := range map[string]string{`"a"`: "a", `5`: "5", `true`: "1", `{"k":1}`: ""} {
		if err := x.UnmarshalJSON([]byte(in)); err != nil || string(x) != want {
			t.Errorf("Text(%s) = %q, %v", in, x, err)
		}
	}
}

func TestHostAliasesOf(t *testing.T) {
	ctx := context.Background()
	ub := opnsensetest.New(t).Client(t).Unbound
	h1, _ := ub.HostOverrides.Add(ctx, opnsense.HostOverride{Hostname: "a", Domain: "lan", RR: "A", Server: "10.0.0.1"})
	h2, _ := ub.HostOverrides.Add(ctx, opnsense.HostOverride{Hostname: "b", Domain: "lan", RR: "A", Server: "10.0.0.2"})
	for _, h := range []string{h1, h1, h2} {
		if _, err := ub.HostAliases.Add(ctx, opnsense.HostAlias{Host: opnsense.Option(h), Hostname: "x" + h[len(h)-2:]}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := ub.HostAliasesOf(ctx, h1)
	if err != nil || len(rows) != 2 {
		t.Fatalf("HostAliasesOf = %d rows, %v", len(rows), err)
	}
}
