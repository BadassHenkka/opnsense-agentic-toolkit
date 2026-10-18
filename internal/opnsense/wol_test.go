package opnsense_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff": "aa:bb:cc:dd:ee:ff", " 001122334455 ": "00:11:22:33:44:55",
	} {
		if got, err := opnsense.NormalizeMAC(in); err != nil || got != want {
			t.Errorf("NormalizeMAC(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "aa:bb:cc", "gg:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"} {
		if _, err := opnsense.NormalizeMAC(bad); err == nil {
			t.Errorf("NormalizeMAC(%q) accepted", bad)
		}
	}
}

func TestWol(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	wol := fake.Client(t).Wol

	nas, err := wol.Hosts.Add(ctx, opnsense.WolHost{Interface: "lan", MAC: "00:11:22:33:44:55", Description: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wol.Wake(ctx, nas); err != nil {
		t.Fatalf("wake: %v", err)
	}
	if err := wol.WakeMAC(ctx, "opt3", "AA-BB-CC-DD-EE-FF"); err != nil {
		t.Fatalf("wake by MAC: %v", err)
	}
	if got := fake.Wakes(); !slices.Equal(got, []string{"lan 00:11:22:33:44:55", "opt3 aa:bb:cc:dd:ee:ff"}) {
		t.Fatalf("wakes %v", got)
	}

	// DHCP interface: the plugin cannot compute a broadcast address.
	if err := wol.WakeMAC(ctx, "wan", "00:11:22:33:44:66"); err == nil || !strings.Contains(err.Error(), "Incorrect IPv4") {
		t.Fatalf("wan wake: %v", err)
	}
	// Unknown interface: the plugin answers with an empty result.
	if err := wol.WakeMAC(ctx, "opt9", "00:11:22:33:44:66"); err == nil || !strings.Contains(err.Error(), "invalid interface") {
		t.Fatalf("bad interface: %v", err)
	}

	if id, err := wol.FindByMAC(ctx, "00-11-22-33-44-55"); err != nil || id != nas {
		t.Fatalf("FindByMAC = %q, %v", id, err)
	}
	if _, err := wol.Hosts.Add(ctx, opnsense.WolHost{Interface: "wan", MAC: "00:11:22:33:44:77", Description: "modem-side"}); err != nil {
		t.Fatal(err)
	}
	res, err := wol.WakeAll(ctx)
	if err != nil || len(res) != 2 || !res[0].OK() || res[1].OK() {
		t.Fatalf("wake all: %+v, %v", res, err)
	}

	// delHost returns an empty body; Delete still reports success, and ErrNotFound after.
	if err := wol.Hosts.Delete(ctx, nas); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := wol.Hosts.Get(ctx, nas); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if _, err := wol.Hosts.Add(ctx, opnsense.WolHost{Interface: "lan", MAC: "nope"}); err == nil {
		t.Fatal("bad MAC accepted")
	}
}
