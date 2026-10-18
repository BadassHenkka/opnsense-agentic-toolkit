package opnsense_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestWireguardKeys(t *testing.T) {
	priv, pub, err := opnsense.WireguardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := opnsense.WireguardPublicKey(priv)
	if err != nil || derived != pub {
		t.Fatalf("derived %q, want %q (%v)", derived, pub, err)
	}
	// RFC 7748 §6.1 test vector (Alice).
	got, err := opnsense.WireguardPublicKey("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=")
	if err != nil || got != "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" {
		t.Fatalf("test vector: %q, %v", got, err)
	}
	if _, err := opnsense.WireguardPublicKey("short"); err == nil {
		t.Fatal("want error for a malformed key")
	}
}

func TestWireguardMembership(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	wg := fake.Client(t).Wireguard

	priv, pub, _ := opnsense.WireguardKeyPair()
	inst := opnsense.WireguardInstance{
		Enabled: true, Name: "home", PrivateKey: priv, PublicKey: pub, Port: opnsense.IntOf(51820),
		TunnelAddress: opnsense.CSVList{"10.10.10.1/24"},
	}
	i1, err := wg.Instances.Add(ctx, inst)
	if err != nil {
		t.Fatal(err)
	}
	inst.Name = "site2site"
	i2, _ := wg.Instances.Add(ctx, inst)

	_, peerPub, _ := opnsense.WireguardKeyPair()
	peer := opnsense.WireguardPeer{
		Enabled: true, Name: "phone", PublicKey: peerPub,
		TunnelAddress: opnsense.CSVList{"10.10.10.2/32"}, Instances: opnsense.CSVList{i1},
	}
	p1, err := wg.Peers.Add(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}

	got, _ := wg.Instances.Get(ctx, i1)
	if !slices.Equal(got.Peers, []string{p1}) || got.Interface != "wg0" || got.Number != "0" {
		t.Fatalf("instance after peer add: %+v", got)
	}

	// An instance update must not drop its peers (peers is read-only in the client).
	got.Port = opnsense.IntOf(51821)
	if err := wg.Instances.Set(ctx, i1, *got); err != nil {
		t.Fatal(err)
	}
	if got, _ = wg.Instances.Get(ctx, i1); len(got.Peers) != 1 {
		t.Fatalf("instance update dropped peers: %+v", got.Peers)
	}

	// The peer reads its instances back; moving it updates both instances.
	p, _ := wg.Peers.Get(ctx, p1)
	if !slices.Equal(p.Instances, []string{i1}) {
		t.Fatalf("peer instances %v", p.Instances)
	}
	p.Instances = opnsense.CSVList{i2}
	if err := wg.Peers.Set(ctx, p1, *p); err != nil {
		t.Fatal(err)
	}
	if a, _ := wg.Instances.Get(ctx, i1); len(a.Peers) != 0 {
		t.Fatalf("old instance still lists the peer: %v", a.Peers)
	}
	if rows, _ := wg.PeersOf(ctx, i2); len(rows) != 1 || string(rows[0].UUID) != p1 {
		t.Fatalf("PeersOf = %+v", rows)
	}

	status, err := wg.Status(ctx)
	if err != nil || len(status) != 3 {
		t.Fatalf("status = %+v, %v", status, err)
	}

	if err := wg.Peers.Delete(ctx, p1); err != nil {
		t.Fatal(err)
	}
	if b, _ := wg.Instances.Get(ctx, i2); len(b.Peers) != 0 {
		t.Fatalf("deleted peer still listed: %v", b.Peers)
	}

	if err := wg.SetEnabled(ctx, true); err != nil || fake.WireguardEnabled() != "1" {
		t.Fatalf("SetEnabled: %v", err)
	}
	if on, _ := wg.Enabled(ctx); !on {
		t.Fatal("Enabled() = false")
	}
	if err := wg.Apply(ctx); err != nil || fake.Applies["wireguard/service/reconfigure"] != 1 {
		t.Fatalf("Apply: %v", err)
	}
}

func TestWireguardPeerConfig(t *testing.T) {
	cfg := opnsense.WireguardPeerConfig{
		PeerPrivateKey: "PRIV", PeerAddresses: []string{"10.10.10.2/32"}, DNS: []string{"10.10.10.1"},
		InstancePublic: "PUB", Endpoint: "vpn.example.com:51820", AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		KeepaliveSeconds: 25,
	}.String()
	for _, want := range []string{"PrivateKey = PRIV", "Address = 10.10.10.2/32", "DNS = 10.10.10.1",
		"Endpoint = vpn.example.com:51820", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "PresharedKey") {
		t.Error("PresharedKey line without a key")
	}
}
