package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const wireguardToolset = "wireguard"

const wireguardStagedNote = "Change saved to the configuration but not active. Call wireguard_apply to activate."

type wgSettingsView struct {
	Enabled bool `json:"enabled"`
}

type wgSettingsIn struct {
	Enabled bool `json:"enabled" jsonschema:"turn WireGuard on or off globally"`
}

type wgStatusIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"only rows of this instance (name or interface, e.g. wg0)"`
}

type wgStatusOut struct {
	Rows []opnsense.WireguardStatus `json:"rows"`
}

type wgPeerRef struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type wgInstanceView struct {
	UUID            string      `json:"uuid"`
	Name            string      `json:"name"`
	Interface       string      `json:"interface" jsonschema:"device name, e.g. wg0; use it in firewall rules"`
	Enabled         bool        `json:"enabled"`
	PublicKey       string      `json:"public_key"`
	ListenPort      *int64      `json:"listen_port,omitempty"`
	MTU             *int64      `json:"mtu,omitempty"`
	TunnelAddresses []string    `json:"tunnel_addresses"`
	DNS             []string    `json:"dns,omitempty"`
	DisableRoutes   bool        `json:"disable_routes"`
	Gateway         string      `json:"gateway,omitempty"`
	Debug           bool        `json:"debug"`
	Peers           []wgPeerRef `json:"peers"`
}

type wgInstanceCreateIn struct {
	Name            string   `json:"name"`
	ListenPort      *int64   `json:"listen_port,omitempty" jsonschema:"UDP port; defaults to 51820. Open it in the WAN firewall rules"`
	TunnelAddresses []string `json:"tunnel_addresses" jsonschema:"instance addresses in CIDR form, e.g. 10.10.10.1/24"`
	DNS             []string `json:"dns,omitempty" jsonschema:"DNS servers for the instance"`
	MTU             *int64   `json:"mtu,omitempty"`
	DisableRoutes   bool     `json:"disable_routes,omitempty" jsonschema:"do not install routes for peers' allowed IPs"`
	Gateway         string   `json:"gateway,omitempty" jsonschema:"gateway IP, used with disable_routes"`
	PrivateKey      string   `json:"private_key,omitempty" jsonschema:"only to import an existing key; omit to generate one"`
	Enabled         *bool    `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type wgInstanceUpdateIn struct {
	NameRef
	NewName         *string   `json:"new_name,omitempty"`
	ListenPort      *int64    `json:"listen_port,omitempty"`
	TunnelAddresses *[]string `json:"tunnel_addresses,omitempty" jsonschema:"replaces the whole list"`
	DNS             *[]string `json:"dns,omitempty" jsonschema:"replaces the whole list"`
	MTU             *int64    `json:"mtu,omitempty"`
	DisableRoutes   *bool     `json:"disable_routes,omitempty"`
	Gateway         *string   `json:"gateway,omitempty"`
	Debug           *bool     `json:"debug,omitempty"`
	Enabled         *bool     `json:"enabled,omitempty"`
	RegenerateKeys  bool      `json:"regenerate_keys,omitempty" jsonschema:"new key pair; every peer device must be given the new public key"`
}

type wgInstanceOut struct {
	UUID      string `json:"uuid"`
	PublicKey string `json:"public_key"`
	Staged    bool   `json:"staged"`
	Note      string `json:"note"`
}

type wgPeerView struct {
	UUID            string      `json:"uuid"`
	Name            string      `json:"name"`
	Enabled         bool        `json:"enabled"`
	PublicKey       string      `json:"public_key"`
	PresharedKeySet bool        `json:"preshared_key_set" jsonschema:"whether a preshared key is stored; it is never shown"`
	TunnelAddresses []string    `json:"tunnel_addresses"`
	EndpointHost    string      `json:"endpoint_host,omitempty"`
	EndpointPort    *int64      `json:"endpoint_port,omitempty"`
	Keepalive       *int64      `json:"keepalive,omitempty"`
	Instances       []wgPeerRef `json:"instances"`
}

type wgPeerListIn struct {
	Search   string   `json:"search,omitempty"`
	Instance *NameRef `json:"instance,omitempty" jsonschema:"only peers of this instance"`
}

type wgPeerCreateIn struct {
	Name            string    `json:"name"`
	Instances       []NameRef `json:"instances" jsonschema:"instances this peer connects to"`
	TunnelAddresses []string  `json:"tunnel_addresses" jsonschema:"the peer's addresses in CIDR form, usually one /32 (and/or /128) inside the instance's network"`
	PublicKey       string    `json:"public_key,omitempty" jsonschema:"the device's public key; omit to generate a key pair and get a ready client config back"`
	PresharedKey    string    `json:"preshared_key,omitempty"`
	GeneratePSK     bool      `json:"generate_psk,omitempty" jsonschema:"generate a preshared key (included in the generated client config)"`
	EndpointHost    string    `json:"endpoint_host,omitempty" jsonschema:"where the peer is reachable, for site-to-site; omit for road warriors"`
	EndpointPort    *int64    `json:"endpoint_port,omitempty"`
	Keepalive       *int64    `json:"keepalive,omitempty" jsonschema:"persistent keepalive in seconds, e.g. 25"`
	Enabled         *bool     `json:"enabled,omitempty" jsonschema:"defaults to true"`

	// Used only to build the client config when the key pair is generated.
	FirewallEndpoint string   `json:"firewall_endpoint,omitempty" jsonschema:"public host:port of the firewall for the client config, e.g. vpn.example.com:51820"`
	ClientAllowedIPs []string `json:"client_allowed_ips,omitempty" jsonschema:"what the device sends through the tunnel; defaults to 0.0.0.0/0, ::/0 (everything)"`
	ClientDNS        []string `json:"client_dns,omitempty" jsonschema:"DNS for the device; defaults to the instance's DNS"`
}

type wgPeerUpdateIn struct {
	NameRef
	NewName         *string    `json:"new_name,omitempty"`
	Instances       *[]NameRef `json:"instances,omitempty" jsonschema:"replaces the whole list"`
	TunnelAddresses *[]string  `json:"tunnel_addresses,omitempty" jsonschema:"replaces the whole list"`
	PublicKey       *string    `json:"public_key,omitempty"`
	PresharedKey    *string    `json:"preshared_key,omitempty" jsonschema:"set, or empty string to remove"`
	GeneratePSK     bool       `json:"generate_psk,omitempty" jsonschema:"replace the preshared key with a new one; it is returned once"`
	EndpointHost    *string    `json:"endpoint_host,omitempty"`
	EndpointPort    *int64     `json:"endpoint_port,omitempty"`
	Keepalive       *int64     `json:"keepalive,omitempty"`
	Enabled         *bool      `json:"enabled,omitempty"`
}

type wgPeerOut struct {
	UUID      string `json:"uuid"`
	PublicKey string `json:"public_key"`
	Staged    bool   `json:"staged"`
	Note      string `json:"note"`
	// ClientConfig is returned once when the key pair or PSK is generated. Nothing else
	// stores the private key.
	ClientConfig string `json:"client_config,omitempty"`
	PresharedKey string `json:"preshared_key,omitempty"`
}

func checkCIDRs(field string, addrs []string) error {
	for _, a := range addrs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(a)); err != nil {
			return fmt.Errorf("%s: %q is not in CIDR form (e.g. 10.10.10.2/32)", field, a)
		}
	}
	return nil
}

func checkKey(field, key string) error {
	if _, err := opnsense.DecodeWireguardKey(key); err != nil {
		return fmt.Errorf("%s: not a WireGuard key (base64, 32 bytes)", field)
	}
	return nil
}

func wireguardTools(c *opnsense.Client) []tool {
	wg := c.Wireguard

	resolveInstances := func(ctx context.Context, refs []NameRef) (opnsense.CSVList, error) {
		var ids opnsense.CSVList
		for _, r := range refs {
			id, err := resolveNamed(ctx, wg.Instances, r, "WireGuard instance")
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, nil
	}
	nameIndex := func(ctx context.Context, list func(context.Context, string) ([]opnsense.NamedRow, error)) map[string]string {
		rows, err := list(ctx, "")
		out := map[string]string{}
		if err == nil {
			for _, r := range rows {
				id, name := r.RowRef()
				out[id] = name
			}
		}
		return out
	}
	instanceNames := func(ctx context.Context) map[string]string {
		return nameIndex(ctx, func(ctx context.Context, q string) ([]opnsense.NamedRow, error) {
			res, err := wg.Instances.Search(ctx, q)
			if err != nil {
				return nil, err
			}
			out := make([]opnsense.NamedRow, len(res.Rows))
			for i, r := range res.Rows {
				out[i] = r
			}
			return out, nil
		})
	}
	peerNames := func(ctx context.Context) map[string]string {
		return nameIndex(ctx, func(ctx context.Context, q string) ([]opnsense.NamedRow, error) {
			res, err := wg.Peers.Search(ctx, q)
			if err != nil {
				return nil, err
			}
			out := make([]opnsense.NamedRow, len(res.Rows))
			for i, r := range res.Rows {
				out[i] = r
			}
			return out, nil
		})
	}
	refs := func(ids []string, names map[string]string) []wgPeerRef {
		out := []wgPeerRef{}
		for _, id := range ids {
			out = append(out, wgPeerRef{UUID: id, Name: names[id]})
		}
		return out
	}

	return []tool{
		{toolset: wireguardToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_settings_get",
				Description: "Show whether WireGuard is enabled globally (VPN → WireGuard → Settings).",
				Annotations: &mcp.ToolAnnotations{Title: "Get WireGuard settings", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, wgSettingsView, error) {
				on, err := wg.Enabled(ctx)
				return nil, wgSettingsView{Enabled: on}, err
			})
		}},
		{toolset: wireguardToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_settings_update",
				Description: "Enable or disable WireGuard globally. Disabling takes every tunnel down after wireguard_apply.",
				Annotations: &mcp.ToolAnnotations{Title: "Update WireGuard settings", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgSettingsIn) (*mcp.CallToolResult, stagedOut, error) {
				if err := wg.SetEnabled(ctx, in.Enabled); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{Staged: true, Note: wireguardStagedNote}, nil
			})
		}},
		{toolset: wireguardToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_status",
				Description: "Live WireGuard status (wg show): interfaces up/down, and per peer its endpoint, last " +
					"handshake, transfer, and peer_status (online = handshake within 5 minutes, stale, offline).",
				Annotations: &mcp.ToolAnnotations{Title: "WireGuard status", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgStatusIn) (*mcp.CallToolResult, wgStatusOut, error) {
				rows, err := wg.Status(ctx)
				if err != nil {
					return nil, wgStatusOut{}, err
				}
				out := []opnsense.WireguardStatus{}
				for _, r := range rows {
					if in.Instance == "" || strings.EqualFold(string(r.InstanceName), in.Instance) ||
						strings.EqualFold(string(r.Interface), in.Instance) {
						out = append(out, r)
					}
				}
				return nil, wgStatusOut{Rows: out}, nil
			})
		}},

		// instances
		listTool(wireguardToolset, "wireguard_instance_list", "List WireGuard instances",
			"List WireGuard instances (local wgN interfaces).", wg.Instances),
		{toolset: wireguardToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_instance_get",
				Description: "Get a WireGuard instance by UUID or name, with its public key, interface and peers. The private key is never shown.",
				Annotations: &mcp.ToolAnnotations{Title: "Get WireGuard instance", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, wgInstanceView, error) {
				id, err := resolveNamed(ctx, wg.Instances, in, "WireGuard instance")
				if err != nil {
					return nil, wgInstanceView{}, err
				}
				w, err := wg.Instances.Get(ctx, id)
				if err != nil {
					return nil, wgInstanceView{}, notFoundAs(err, "WireGuard instance", id)
				}
				return nil, wgInstanceView{
					UUID: id, Name: w.Name, Interface: string(w.Interface), Enabled: bool(w.Enabled),
					PublicKey: w.PublicKey, ListenPort: intPtr(w.Port), MTU: intPtr(w.MTU),
					TunnelAddresses: nonNil([]string(w.TunnelAddress)), DNS: w.DNS, DisableRoutes: bool(w.DisableRoutes),
					Gateway: w.Gateway, Debug: bool(w.Debug), Peers: refs(w.Peers, peerNames(ctx)),
				}, nil
			})
		}},
		{toolset: wireguardToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_instance_create",
				Description: "Create a WireGuard instance. A key pair is generated locally unless private_key is given; " +
					"the public key is returned. Add peers with wireguard_peer_create, then wireguard_apply. Remember a " +
					"WAN rule allowing the UDP port and rules on the new interface.",
				Annotations: &mcp.ToolAnnotations{Title: "Create WireGuard instance", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgInstanceCreateIn) (*mcp.CallToolResult, wgInstanceOut, error) {
				if err := checkCIDRs("tunnel_addresses", in.TunnelAddresses); err != nil {
					return nil, wgInstanceOut{}, err
				}
				priv, pub := in.PrivateKey, ""
				var err error
				if priv == "" {
					priv, pub, err = opnsense.WireguardKeyPair()
				} else {
					pub, err = opnsense.WireguardPublicKey(priv)
				}
				if err != nil {
					return nil, wgInstanceOut{}, fmt.Errorf("private_key: %w", err)
				}
				port := opnsense.IntOf(51820)
				if in.ListenPort != nil {
					port = opnsense.IntOf(*in.ListenPort)
				}
				id, err := wg.Instances.Add(ctx, opnsense.WireguardInstance{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Name: in.Name,
					PrivateKey: priv, PublicKey: pub, Port: port, MTU: toInt(in.MTU), DNS: in.DNS,
					TunnelAddress: in.TunnelAddresses, DisableRoutes: opnsense.Bool(in.DisableRoutes), Gateway: in.Gateway,
				})
				if err != nil {
					return nil, wgInstanceOut{}, err
				}
				return nil, wgInstanceOut{UUID: id, PublicKey: pub, Staged: true, Note: wireguardStagedNote}, nil
			})
		}},
		{toolset: wireguardToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_instance_update",
				Description: "Change a WireGuard instance, by UUID or name; only the fields given change. Peers are " +
					"managed on the peers (wireguard_peer_update instances).",
				Annotations: &mcp.ToolAnnotations{Title: "Update WireGuard instance", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgInstanceUpdateIn) (*mcp.CallToolResult, wgInstanceOut, error) {
				id, err := resolveNamed(ctx, wg.Instances, in.NameRef, "WireGuard instance")
				if err != nil {
					return nil, wgInstanceOut{}, err
				}
				w, err := wg.Instances.Get(ctx, id)
				if err != nil {
					return nil, wgInstanceOut{}, notFoundAs(err, "WireGuard instance", id)
				}
				if in.TunnelAddresses != nil {
					if err := checkCIDRs("tunnel_addresses", *in.TunnelAddresses); err != nil {
						return nil, wgInstanceOut{}, err
					}
				}
				set(&w.Name, in.NewName)
				setAs(&w.Port, in.ListenPort, opnsense.IntOf)
				setAs(&w.TunnelAddress, in.TunnelAddresses, func(v []string) opnsense.CSVList { return v })
				setAs(&w.DNS, in.DNS, func(v []string) opnsense.CSVList { return v })
				setAs(&w.MTU, in.MTU, opnsense.IntOf)
				setAs(&w.DisableRoutes, in.DisableRoutes, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				set(&w.Gateway, in.Gateway)
				setAs(&w.Debug, in.Debug, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				setAs(&w.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				note := wireguardStagedNote
				if in.RegenerateKeys {
					if w.PrivateKey, w.PublicKey, err = opnsense.WireguardKeyPair(); err != nil {
						return nil, wgInstanceOut{}, err
					}
					note += " New key pair: every peer device needs the new public key."
				} else if w.PublicKey == "" && w.PrivateKey != "" {
					w.PublicKey, _ = opnsense.WireguardPublicKey(w.PrivateKey)
				}
				if err := wg.Instances.Set(ctx, id, *w); err != nil {
					return nil, wgInstanceOut{}, err
				}
				return nil, wgInstanceOut{UUID: id, PublicKey: w.PublicKey, Staged: true, Note: note}, nil
			})
		}},
		deleteTool(wireguardToolset, "wireguard_instance_delete", "Delete WireGuard instance", "WireGuard instance",
			" Its tunnel goes down after wireguard_apply; its peers remain but are no longer attached to it.",
			wireguardStagedNote, wg.Instances),

		// peers
		{toolset: wireguardToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_peer_list",
				Description: "List WireGuard peers, optionally only those of one instance.",
				Annotations: &mcp.ToolAnnotations{Title: "List WireGuard peers", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgPeerListIn) (*mcp.CallToolResult, listOut[opnsense.WireguardPeerRow], error) {
				var filters map[string]any
				if in.Instance != nil {
					id, err := resolveNamed(ctx, wg.Instances, *in.Instance, "WireGuard instance")
					if err != nil {
						return nil, listOut[opnsense.WireguardPeerRow]{}, err
					}
					filters = map[string]any{"servers": []string{id}}
				}
				res, err := wg.Peers.SearchWith(ctx, in.Search, filters)
				if err != nil {
					return nil, listOut[opnsense.WireguardPeerRow]{}, err
				}
				return nil, listOut[opnsense.WireguardPeerRow]{Items: nonNil(res.Rows), Total: res.Total}, nil
			})
		}},
		{toolset: wireguardToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_peer_get",
				Description: "Get a WireGuard peer by UUID or name. The preshared key is never shown.",
				Annotations: &mcp.ToolAnnotations{Title: "Get WireGuard peer", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, wgPeerView, error) {
				id, err := resolveNamed(ctx, wg.Peers, in, "WireGuard peer")
				if err != nil {
					return nil, wgPeerView{}, err
				}
				p, err := wg.Peers.Get(ctx, id)
				if err != nil {
					return nil, wgPeerView{}, notFoundAs(err, "WireGuard peer", id)
				}
				return nil, wgPeerView{
					UUID: id, Name: p.Name, Enabled: bool(p.Enabled), PublicKey: p.PublicKey,
					PresharedKeySet: p.PresharedKey != "", TunnelAddresses: nonNil([]string(p.TunnelAddress)),
					EndpointHost: p.EndpointHost, EndpointPort: intPtr(p.EndpointPort), Keepalive: intPtr(p.Keepalive),
					Instances: refs(p.Instances, instanceNames(ctx)),
				}, nil
			})
		}},
		{toolset: wireguardToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_peer_create",
				Description: "Add a WireGuard peer to one or more instances. Give the device's public_key, or omit it to " +
					"generate a key pair: then a complete client config (with the device's private key) is returned " +
					"once, for the user to import (e.g. as a QR code or .conf file). It is not stored anywhere else. " +
					"Not active until wireguard_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Create WireGuard peer", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgPeerCreateIn) (*mcp.CallToolResult, wgPeerOut, error) {
				if len(in.TunnelAddresses) == 0 {
					return nil, wgPeerOut{}, errors.New("tunnel_addresses is required, e.g. [\"10.10.10.2/32\"]")
				}
				if err := checkCIDRs("tunnel_addresses", in.TunnelAddresses); err != nil {
					return nil, wgPeerOut{}, err
				}
				instances, err := resolveInstances(ctx, in.Instances)
				if err != nil {
					return nil, wgPeerOut{}, err
				}
				generate := in.PublicKey == ""
				if generate && in.FirewallEndpoint == "" {
					return nil, wgPeerOut{}, errors.New("to generate the device's keys and config, give firewall_endpoint " +
						"(public host:port of the firewall); or pass the device's public_key")
				}
				if generate && len(instances) != 1 {
					return nil, wgPeerOut{}, errors.New("a generated client config needs exactly one instance")
				}
				if !generate {
					if err := checkKey("public_key", in.PublicKey); err != nil {
						return nil, wgPeerOut{}, err
					}
				}
				psk := in.PresharedKey
				if in.GeneratePSK {
					if psk, err = opnsense.WireguardPresharedKey(); err != nil {
						return nil, wgPeerOut{}, err
					}
				}
				var devicePriv, devicePub = "", in.PublicKey
				if generate {
					if devicePriv, devicePub, err = opnsense.WireguardKeyPair(); err != nil {
						return nil, wgPeerOut{}, err
					}
				}
				peer := opnsense.WireguardPeer{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Name: in.Name, PublicKey: devicePub,
					PresharedKey: psk, TunnelAddress: in.TunnelAddresses, EndpointHost: in.EndpointHost,
					EndpointPort: toInt(in.EndpointPort), Keepalive: toInt(in.Keepalive), Instances: instances,
				}
				out := wgPeerOut{PublicKey: devicePub, Staged: true, Note: wireguardStagedNote}
				if generate {
					inst, err := wg.Instances.Get(ctx, instances[0])
					if err != nil {
						return nil, wgPeerOut{}, err
					}
					dns := in.ClientDNS
					if len(dns) == 0 {
						dns = inst.DNS
					}
					allowed := in.ClientAllowedIPs
					if len(allowed) == 0 {
						allowed = []string{"0.0.0.0/0", "::/0"}
					}
					var keepalive int64 = 25
					if in.Keepalive != nil {
						keepalive = *in.Keepalive
					}
					out.ClientConfig = opnsense.WireguardPeerConfig{
						PeerPrivateKey: devicePriv, PeerAddresses: in.TunnelAddresses, DNS: dns,
						InstancePublic: inst.PublicKey, PresharedKey: psk, Endpoint: in.FirewallEndpoint,
						AllowedIPs: allowed, KeepaliveSeconds: keepalive,
					}.String()
					out.Note += " The client_config contains the device's private key and is shown only now."
				} else if in.GeneratePSK {
					out.PresharedKey = psk
					out.Note += " Configure the same preshared_key on the device; it is shown only now."
				}
				id, err := wg.Peers.Add(ctx, peer)
				if err != nil {
					return nil, wgPeerOut{}, err
				}
				out.UUID = id
				return nil, out, nil
			})
		}},
		{toolset: wireguardToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_peer_update",
				Description: "Change a WireGuard peer, by UUID or name; only the fields given change. instances replaces " +
					"the instance list. Not active until wireguard_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Update WireGuard peer", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wgPeerUpdateIn) (*mcp.CallToolResult, wgPeerOut, error) {
				id, err := resolveNamed(ctx, wg.Peers, in.NameRef, "WireGuard peer")
				if err != nil {
					return nil, wgPeerOut{}, err
				}
				p, err := wg.Peers.Get(ctx, id)
				if err != nil {
					return nil, wgPeerOut{}, notFoundAs(err, "WireGuard peer", id)
				}
				if in.Instances != nil {
					if p.Instances, err = resolveInstances(ctx, *in.Instances); err != nil {
						return nil, wgPeerOut{}, err
					}
				}
				if in.TunnelAddresses != nil {
					if err := checkCIDRs("tunnel_addresses", *in.TunnelAddresses); err != nil {
						return nil, wgPeerOut{}, err
					}
					p.TunnelAddress = *in.TunnelAddresses
				}
				if in.PublicKey != nil {
					if err := checkKey("public_key", *in.PublicKey); err != nil {
						return nil, wgPeerOut{}, err
					}
					p.PublicKey = *in.PublicKey
				}
				out := wgPeerOut{UUID: id, Staged: true, Note: wireguardStagedNote}
				set(&p.PresharedKey, in.PresharedKey)
				if in.GeneratePSK {
					if p.PresharedKey, err = opnsense.WireguardPresharedKey(); err != nil {
						return nil, wgPeerOut{}, err
					}
					out.PresharedKey = p.PresharedKey
					out.Note += " Configure the new preshared_key on the device; it is shown only now."
				}
				set(&p.Name, in.NewName)
				set(&p.EndpointHost, in.EndpointHost)
				setAs(&p.EndpointPort, in.EndpointPort, opnsense.IntOf)
				setAs(&p.Keepalive, in.Keepalive, opnsense.IntOf)
				setAs(&p.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				if err := wg.Peers.Set(ctx, id, *p); err != nil {
					return nil, wgPeerOut{}, err
				}
				out.PublicKey = p.PublicKey
				return nil, out, nil
			})
		}},
		deleteTool(wireguardToolset, "wireguard_peer_delete", "Delete WireGuard peer", "WireGuard peer",
			" It is removed from every instance.", wireguardStagedNote, wg.Peers),

		{toolset: wireguardToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wireguard_apply",
				Description: "Apply WireGuard changes: write the configuration and restart instances. Active tunnels " +
					"reconnect. Confirm with the user before calling.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply WireGuard changes", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, applyOut, error) {
				if err := wg.Apply(ctx); err != nil {
					return nil, applyOut{}, err
				}
				return nil, applyOut{Applied: true}, nil
			})
		}},
	}
}
