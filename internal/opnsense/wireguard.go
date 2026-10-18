package opnsense

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// VPN → WireGuard (core since 24.1). Three models under /api/wireguard:
//
//	general        settings, one field: enabled                 general/get, general/set
//	server.server  an instance (local interface wgN)            server/{add,get,set,del,search}Server
//	client.client  a peer (remote end)                          client/{add,get,set,del,search}Client
//
// The types, rows and WireguardService are generated (gen/specs/wireguard.json); this file
// adds status, key handling and helpers.
//
// Instance ↔ peer membership is stored only in the instance's "peers" field. A peer's
// "servers" field is volatile: OPNsense computes it from the instances on read, and
// setClient/addClient rewrite the instances' peer lists from it. Posting a peer without
// "servers" therefore detaches it from every instance. In this client the peer owns the
// relation; the instance's peer list is read-only so an instance update cannot drop peers.
//
// Everything is applied with /api/wireguard/service/reconfigure.

// WireguardStatus is one row of `wg show` as OPNsense reports it: an interface or a peer.
type WireguardStatus struct {
	Type      Text `json:"type"` // interface or peer
	Interface Text `json:"if"`
	// Name is the instance or peer name OPNsense matched by public key.
	Name          Text   `json:"name"`
	InstanceName  Text   `json:"ifname"`
	PublicKey     Text   `json:"public-key"`
	Endpoint      Text   `json:"endpoint"`
	AllowedIPs    Text   `json:"allowed-ips"`
	ListenPort    Text   `json:"listen-port"`
	Status        Text   `json:"status"`      // interface: up/down
	PeerStatus    Text   `json:"peer-status"` // peer: online (<5 min), stale, offline
	LastHandshake Text   `json:"latest-handshake-epoch"`
	HandshakeAge  *int64 `json:"latest-handshake-age"`
	RxBytes       int64  `json:"transfer-rx"`
	TxBytes       int64  `json:"transfer-tx"`
}

const wireguardReconfigure = "wireguard/service/reconfigure"

// Apply writes the WireGuard configuration and (re)starts the instances.
func (s *WireguardService) Apply(ctx context.Context) error {
	return s.c.Reconfigure(ctx, wireguardReconfigure)
}

// Enabled reports whether WireGuard is enabled globally.
func (s *WireguardService) Enabled(ctx context.Context) (bool, error) {
	g, err := s.General.Get(ctx)
	if err != nil {
		return false, err
	}
	return bool(g.Enabled), nil
}

// SetEnabled turns WireGuard on or off globally. The change is staged until Apply.
func (s *WireguardService) SetEnabled(ctx context.Context, enabled bool) error {
	return s.General.Set(ctx, WireguardGeneral{Enabled: Bool(enabled)})
}

// PeersOf returns the peers that belong to an instance.
func (s *WireguardService) PeersOf(ctx context.Context, instanceUUID string) ([]WireguardPeerRow, error) {
	res, err := s.Peers.SearchWith(ctx, "", map[string]any{"servers": []string{instanceUUID}})
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// Status returns live interface and peer status (wg show).
func (s *WireguardService) Status(ctx context.Context) ([]WireguardStatus, error) {
	var res SearchResult[WireguardStatus]
	if err := s.c.Get(ctx, "wireguard/service/show", &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// WireguardKeyPair generates a private key and its public key, both base64 encoded.
// Keys are generated locally (X25519), so a private key never travels over the API unless
// it is stored in OPNsense.
func WireguardKeyPair() (private, public string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// WireguardPublicKey derives the public key of a base64 private key.
func WireguardPublicKey(private string) (string, error) {
	raw, err := DecodeWireguardKey(private)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// WireguardPresharedKey generates a random preshared key.
func WireguardPresharedKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// DecodeWireguardKey checks that s is a base64 encoded 32-byte key.
func DecodeWireguardKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("opnsense: not a WireGuard key (want 32 bytes, base64 encoded)")
	}
	return raw, nil
}

// WireguardPeerConfig renders a wg-quick configuration for the remote device of a peer.
type WireguardPeerConfig struct {
	PeerPrivateKey   string
	PeerAddresses    []string // the peer's tunnel addresses
	DNS              []string
	InstancePublic   string
	PresharedKey     string
	Endpoint         string   // host:port of the firewall
	AllowedIPs       []string // what the device routes into the tunnel
	KeepaliveSeconds int64
}

func (c WireguardPeerConfig) String() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PeerPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(c.PeerAddresses, ", "))
	if len(c.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(c.DNS, ", "))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.InstancePublic)
	if c.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(c.AllowedIPs, ", "))
	if c.KeepaliveSeconds > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.KeepaliveSeconds)
	}
	return b.String()
}
