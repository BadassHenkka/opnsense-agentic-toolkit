package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const wolToolset = "wol"

type wolHostCreateIn struct {
	Description string `json:"description" jsonschema:"name for the host, e.g. nas; used to wake it later"`
	Interface   string `json:"interface" jsonschema:"interface name (lan) or description (LAN) the host is on; needs a static IPv4 address"`
	MAC         string `json:"mac" jsonschema:"MAC address in any common notation (aa:bb:.., AA-BB-.., aabb.ccdd.eeff)"`
}

type wolHostUpdateIn struct {
	NameRef
	NewDescription *string `json:"new_description,omitempty"`
	Interface      *string `json:"interface,omitempty"`
	MAC            *string `json:"mac,omitempty"`
}

type wolWakeIn struct {
	Host      *NameRef `json:"host,omitempty" jsonschema:"a saved host by uuid or description"`
	MAC       string   `json:"mac,omitempty" jsonschema:"or wake any MAC address: a saved host with this MAC is used if there is one"`
	Interface string   `json:"interface,omitempty" jsonschema:"interface for an unsaved MAC, e.g. lan"`
}

type wolWakeOut struct {
	Sent   bool   `json:"sent"`
	Target string `json:"target"`
	Note   string `json:"note"`
}

type wolWakeAllOut struct {
	Results []opnsense.WakeResult `json:"results"`
}

func wolTools(c *opnsense.Client) []tool {
	wol := c.Wol
	// Interface names are resolved through the firewall's interface list when possible, so
	// "LAN" works as well as "lan". Without that privilege the value is used as given.
	iface := func(ctx context.Context, v string) string {
		if name, err := c.Filter.ResolveInterface(ctx, v); err == nil {
			return name
		}
		return v
	}
	const wakeNote = "Magic packet sent. It is fire-and-forget: the machine usually takes 10–60 s to boot, " +
		"and WoL must be enabled in its BIOS/UEFI and NIC settings."

	return []tool{
		listTool(wolToolset, "wol_host_list", "List Wake on LAN hosts",
			"List saved Wake on LAN hosts (Services → Wake on LAN).", wol.Hosts),
		{toolset: wolToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wol_host_create",
				Description: "Save a host for Wake on LAN. Takes effect immediately (no apply needed).",
				Annotations: &mcp.ToolAnnotations{Title: "Save Wake on LAN host", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wolHostCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				mac, err := opnsense.NormalizeMAC(in.MAC)
				if err != nil {
					return nil, stagedOut{}, err
				}
				if _, err := wol.FindByMAC(ctx, mac); err == nil {
					return nil, stagedOut{}, fmt.Errorf("a host with MAC %s is already saved", mac)
				}
				id, err := wol.Hosts.Add(ctx, opnsense.WolHost{Interface: opnsense.Option(iface(ctx, in.Interface)),
					MAC: mac, Description: in.Description})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Note: "Saved."}, nil
			})
		}},
		{toolset: wolToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wol_host_update",
				Description: "Change a saved Wake on LAN host, by UUID or description.",
				Annotations: &mcp.ToolAnnotations{Title: "Update Wake on LAN host", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wolHostUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, wol.Hosts, in.NameRef, "Wake on LAN host")
				if err != nil {
					return nil, stagedOut{}, err
				}
				h, err := wol.Hosts.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "Wake on LAN host", id)
				}
				if in.MAC != nil {
					if h.MAC, err = opnsense.NormalizeMAC(*in.MAC); err != nil {
						return nil, stagedOut{}, err
					}
				}
				if in.Interface != nil {
					h.Interface = opnsense.Option(iface(ctx, *in.Interface))
				}
				set(&h.Description, in.NewDescription)
				if err := wol.Hosts.Set(ctx, id, *h); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Note: "Saved."}, nil
			})
		}},
		deleteTool(wolToolset, "wol_host_delete", "Delete Wake on LAN host", "Wake on LAN host",
			" Address it by UUID or description.", "Deleted.", wol.Hosts),
		{toolset: wolToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wol_wake",
				Description: "Wake a machine: a saved host by description (e.g. \"nas\"), or any MAC address with its " +
					"interface. Harmless to repeat; no confirmation needed unless the user asked to be asked.",
				Annotations: &mcp.ToolAnnotations{Title: "Wake on LAN", DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in wolWakeIn) (*mcp.CallToolResult, wolWakeOut, error) {
				switch {
				case in.Host != nil:
					id, err := resolveNamed(ctx, wol.Hosts, *in.Host, "Wake on LAN host")
					if err != nil {
						return nil, wolWakeOut{}, err
					}
					if err := wol.Wake(ctx, id); err != nil {
						return nil, wolWakeOut{}, err
					}
					target := in.Host.Name
					if target == "" {
						target = id
					}
					return nil, wolWakeOut{Sent: true, Target: target, Note: wakeNote}, nil
				case in.MAC != "":
					if id, err := wol.FindByMAC(ctx, in.MAC); err == nil {
						if err := wol.Wake(ctx, id); err != nil {
							return nil, wolWakeOut{}, err
						}
						return nil, wolWakeOut{Sent: true, Target: in.MAC, Note: wakeNote}, nil
					} else if !errors.Is(err, opnsense.ErrNotFound) {
						return nil, wolWakeOut{}, err
					}
					if in.Interface == "" {
						return nil, wolWakeOut{}, errors.New("this MAC is not saved; give the interface it is on (e.g. lan)")
					}
					if err := wol.WakeMAC(ctx, iface(ctx, in.Interface), in.MAC); err != nil {
						return nil, wolWakeOut{}, err
					}
					return nil, wolWakeOut{Sent: true, Target: in.MAC, Note: wakeNote}, nil
				default:
					return nil, wolWakeOut{}, errors.New("give host, or mac (plus interface if it is not saved)")
				}
			})
		}},
		{toolset: wolToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "wol_wake_all",
				Description: "Wake every saved host. Confirm with the user first.",
				Annotations: &mcp.ToolAnnotations{Title: "Wake all hosts", DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, wolWakeAllOut, error) {
				res, err := wol.WakeAll(ctx)
				return nil, wolWakeAllOut{Results: nonNil(res)}, err
			})
		}},
	}
}
