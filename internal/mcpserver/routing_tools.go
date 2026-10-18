package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const routingToolset = "routing"

const routingStagedNote = "Change saved to the configuration but not active. Call routing_apply to activate."

type gatewayView struct {
	UUID           string `json:"uuid"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	Interface      string `json:"interface" jsonschema:"assigned interface, e.g. opt3"`
	IPProtocol     string `json:"ip_protocol"`
	Address        string `json:"address,omitempty"`
	Enabled        bool   `json:"enabled"`
	DefaultGateway bool   `json:"default_gateway"`
	FarGateway     bool   `json:"far_gateway"`
	Monitoring     bool   `json:"monitoring"`
	MonitorIP      string `json:"monitor_ip,omitempty"`
	Priority       *int64 `json:"priority,omitempty"`
	Weight         *int64 `json:"weight,omitempty"`
}

type gatewayCreateIn struct {
	Name        string `json:"name" jsonschema:"letters, digits, - and _, at most 32, e.g. WG_SITE2"`
	Interface   string `json:"interface" jsonschema:"assigned interface name (Interfaces → Assignments), e.g. opt3 — not wg0"`
	Address     string `json:"address" jsonschema:"gateway IP, e.g. the remote WireGuard peer's tunnel address"`
	IPProtocol  string `json:"ip_protocol,omitempty" jsonschema:"inet (default) or inet6"`
	FarGateway  *bool  `json:"far_gateway,omitempty" jsonschema:"allow a gateway outside the interface subnet; defaults to true, which a WireGuard peer usually needs"`
	Monitoring  bool   `json:"monitoring,omitempty" jsonschema:"monitor with dpinger"`
	MonitorIP   string `json:"monitor_ip,omitempty"`
	Description string `json:"description,omitempty"`
}

type gatewayUpdateIn struct {
	NameRef
	NewName     *string `json:"new_name,omitempty" jsonschema:"static routes refer to the name; update them too"`
	Interface   *string `json:"interface,omitempty"`
	Address     *string `json:"address,omitempty"`
	FarGateway  *bool   `json:"far_gateway,omitempty"`
	Monitoring  *bool   `json:"monitoring,omitempty"`
	MonitorIP   *string `json:"monitor_ip,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	Description *string `json:"description,omitempty"`
}

type gatewayStatusOut struct {
	Items []opnsense.GatewayStatus `json:"items"`
}

type routeView struct {
	UUID        string `json:"uuid"`
	Network     string `json:"network"`
	Gateway     string `json:"gateway" jsonschema:"gateway name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type routeCreateIn struct {
	Network     string `json:"network" jsonschema:"destination in CIDR notation, e.g. 192.168.50.0/24"`
	Gateway     string `json:"gateway" jsonschema:"gateway name"`
	Description string `json:"description,omitempty"`
}

type routeUpdateIn struct {
	UUID        string  `json:"uuid,omitempty"`
	Name        string  `json:"network_ref,omitempty" jsonschema:"current destination network, to find the route; give this or uuid"`
	Network     *string `json:"network,omitempty" jsonschema:"new destination network"`
	Gateway     *string `json:"gateway,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

func gatewayViewOf(id string, g *opnsense.Gateway) gatewayView {
	return gatewayView{
		UUID: id, Name: g.Name, Description: g.Description, Interface: string(g.Interface),
		IPProtocol: string(g.IPProtocol), Address: g.Address, Enabled: !bool(g.Disabled),
		DefaultGateway: bool(g.DefaultGateway), FarGateway: bool(g.FarGateway), Monitoring: !bool(g.MonitorDisable),
		MonitorIP: g.MonitorIP, Priority: intPtr(g.Priority), Weight: intPtr(g.Weight),
	}
}

func routingTools(c *opnsense.Client) []tool {
	rt := c.Routing
	checkGateway := func(ctx context.Context, name string) error {
		res, err := rt.Gateways.Search(ctx, "")
		if err != nil {
			return err
		}
		for _, r := range res.Rows {
			if string(r.Name) == name {
				return nil
			}
		}
		return fmt.Errorf("no gateway named %q; list them with routing_gateway_list", name)
	}

	return []tool{
		listTool(routingToolset, "routing_gateway_list", "List gateways",
			"List gateways (System → Gateways), including dynamic ones such as WAN_DHCP, with their status.", rt.Gateways),
		{toolset: routingToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_gateway_get",
				Description: "Get a gateway by UUID or name. Dynamic gateways (WAN_DHCP, ...) are only in routing_gateway_list.",
				Annotations: &mcp.ToolAnnotations{Title: "Get gateway", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, gatewayView, error) {
				id, err := resolveNamed(ctx, rt.Gateways, in, "gateway")
				if err != nil {
					return nil, gatewayView{}, err
				}
				g, err := rt.Gateways.Get(ctx, id)
				if err != nil {
					return nil, gatewayView{}, notFoundAs(err, "gateway", id)
				}
				return nil, gatewayViewOf(id, g), nil
			})
		}},
		{toolset: routingToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_gateway_status",
				Description: "Live gateway status from dpinger: online/offline, loss and delay (only for monitored gateways).",
				Annotations: &mcp.ToolAnnotations{Title: "Gateway status", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, gatewayStatusOut, error) {
				items, err := rt.GatewayStatus(ctx)
				return nil, gatewayStatusOut{Items: nonNil(items)}, err
			})
		}},
		{toolset: routingToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_gateway_create",
				Description: "Create a gateway. For WireGuard site-to-site: interface is the assigned WireGuard interface " +
					"(optN), address the remote peer's tunnel IP. Then add a static route with routing_route_create.",
				Annotations: &mcp.ToolAnnotations{Title: "Create gateway", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in gatewayCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				if net.ParseIP(in.Address) == nil {
					return nil, stagedOut{}, fmt.Errorf("address %q is not an IP address", in.Address)
				}
				proto := in.IPProtocol
				if proto == "" {
					proto = "inet"
				}
				if err := checkOneOf("ip_protocol", proto, []string{"inet", "inet6"}); err != nil {
					return nil, stagedOut{}, err
				}
				id, err := rt.Gateways.Add(ctx, opnsense.Gateway{
					Name: in.Name, Description: in.Description, Interface: opnsense.Option(in.Interface),
					IPProtocol: opnsense.Option(proto), Address: in.Address,
					FarGateway:     opnsense.Bool(in.FarGateway == nil || *in.FarGateway),
					MonitorDisable: opnsense.Bool(!in.Monitoring), MonitorIP: in.MonitorIP,
					Priority: opnsense.IntOf(255), Weight: opnsense.IntOf(1),
				})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: routingStagedNote}, nil
			})
		}},
		{toolset: routingToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_gateway_update",
				Description: "Change a gateway, by UUID or name; only the fields given change.",
				Annotations: &mcp.ToolAnnotations{Title: "Update gateway", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in gatewayUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, rt.Gateways, in.NameRef, "gateway")
				if err != nil {
					return nil, stagedOut{}, err
				}
				g, err := rt.Gateways.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "gateway", id)
				}
				if in.Address != nil && net.ParseIP(*in.Address) == nil {
					return nil, stagedOut{}, fmt.Errorf("address %q is not an IP address", *in.Address)
				}
				set(&g.Name, in.NewName)
				setAs(&g.Interface, in.Interface, func(v string) opnsense.Option { return opnsense.Option(v) })
				set(&g.Address, in.Address)
				setAs(&g.FarGateway, in.FarGateway, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				setAs(&g.MonitorDisable, in.Monitoring, func(v bool) opnsense.Bool { return opnsense.Bool(!v) })
				set(&g.MonitorIP, in.MonitorIP)
				setAs(&g.Disabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(!v) })
				set(&g.Description, in.Description)
				if err := rt.Gateways.Set(ctx, id, *g); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: routingStagedNote}, nil
			})
		}},
		deleteTool(routingToolset, "routing_gateway_delete", "Delete gateway", "gateway",
			" OPNsense refuses while a static route, interface or gateway group uses it.", routingStagedNote, rt.Gateways),

		listTool(routingToolset, "routing_gateway_group_list", "List gateway groups",
			"List gateway groups (System → Gateways → Groups): failover and load balancing.", rt.GatewayGroups),
		{toolset: routingToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_gateway_group_get",
				Description: "Get a gateway group by UUID or name, with its gateways per tier.",
				Annotations: &mcp.ToolAnnotations{Title: "Get gateway group", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, gatewayGroupView, error) {
				id, err := resolveNamed(ctx, rt.GatewayGroups, in, "gateway group")
				if err != nil {
					return nil, gatewayGroupView{}, err
				}
				g, err := rt.GatewayGroups.Get(ctx, id)
				if err != nil {
					return nil, gatewayGroupView{}, notFoundAs(err, "gateway group", id)
				}
				tiers := [][]string{[]string(g.Tier1), []string(g.Tier2), []string(g.Tier3), []string(g.Tier4), []string(g.Tier5)}
				return nil, gatewayGroupView{UUID: id, Name: g.Name, Tiers: tiers, Trigger: string(g.Trigger),
					PoolOptions: string(g.PoolOptions), Description: g.Description}, nil
			})
		}},
		listTool(routingToolset, "routing_route_list", "List static routes", "List static routes (System → Routes).", rt.Routes),
		{toolset: routingToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_route_get",
				Description: "Get a static route by UUID or by its destination network (name = network, e.g. 192.168.50.0/24).",
				Annotations: &mcp.ToolAnnotations{Title: "Get static route", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, routeView, error) {
				id, err := resolveNamed(ctx, rt.Routes, in, "static route")
				if err != nil {
					return nil, routeView{}, err
				}
				r, err := rt.Routes.Get(ctx, id)
				if err != nil {
					return nil, routeView{}, notFoundAs(err, "static route", id)
				}
				return nil, routeView{UUID: id, Network: r.Network, Gateway: string(r.Gateway),
					Description: r.Description, Enabled: bool(r.Enabled)}, nil
			})
		}},
		{toolset: routingToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_route_create",
				Description: "Create a static route sending a destination network to a gateway (by name). Remember " +
					"firewall rules on the interfaces involved.",
				Annotations: &mcp.ToolAnnotations{Title: "Create static route", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in routeCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				if _, _, err := net.ParseCIDR(in.Network); err != nil {
					return nil, stagedOut{}, fmt.Errorf("network %q is not in CIDR notation (e.g. 192.168.50.0/24)", in.Network)
				}
				if err := checkGateway(ctx, in.Gateway); err != nil {
					return nil, stagedOut{}, err
				}
				id, err := rt.Routes.Add(ctx, opnsense.Route{Enabled: true, Network: in.Network,
					Gateway: opnsense.Option(in.Gateway), Description: in.Description})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: routingStagedNote}, nil
			})
		}},
		{toolset: routingToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_route_update",
				Description: "Change a static route, found by uuid or network_ref (its current network); only the fields given change.",
				Annotations: &mcp.ToolAnnotations{Title: "Update static route", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in routeUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				if in.UUID == "" && in.Name == "" {
					return nil, stagedOut{}, errors.New("give uuid or network_ref")
				}
				id, err := resolveNamed(ctx, rt.Routes, NameRef{UUID: in.UUID, Name: in.Name}, "static route")
				if err != nil {
					return nil, stagedOut{}, err
				}
				r, err := rt.Routes.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "static route", id)
				}
				if in.Network != nil {
					if _, _, err := net.ParseCIDR(*in.Network); err != nil {
						return nil, stagedOut{}, fmt.Errorf("network %q is not in CIDR notation", *in.Network)
					}
					r.Network = *in.Network
				}
				if in.Gateway != nil {
					if err := checkGateway(ctx, *in.Gateway); err != nil {
						return nil, stagedOut{}, err
					}
					r.Gateway = opnsense.Option(*in.Gateway)
				}
				set(&r.Description, in.Description)
				setAs(&r.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				if err := rt.Routes.Set(ctx, id, *r); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: routingStagedNote}, nil
			})
		}},
		deleteTool(routingToolset, "routing_route_delete", "Delete static route", "static route",
			" Address it by uuid or by its network.", routingStagedNote, rt.Routes),
		{toolset: routingToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "routing_apply",
				Description: "Apply gateway and static route changes (reloads the routing table). A wrong route can cut " +
					"off traffic, including your own access. Confirm with the user before calling.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply routing changes", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, applyOut, error) {
				if err := rt.Apply(ctx); err != nil {
					return nil, applyOut{}, err
				}
				return nil, applyOut{Applied: true}, nil
			})
		}},
	}
}

type gatewayGroupView struct {
	UUID        string     `json:"uuid"`
	Name        string     `json:"name"`
	Tiers       [][]string `json:"tiers" jsonschema:"gateway names per tier, tier 1 first"`
	Trigger     string     `json:"trigger,omitempty"`
	PoolOptions string     `json:"pool_options,omitempty"`
	Description string     `json:"description,omitempty"`
}
