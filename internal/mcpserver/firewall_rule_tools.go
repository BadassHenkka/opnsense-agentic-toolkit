package mcpserver

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const firewallRuleToolset = "firewall_rule"

const firewallRuleStagedNote = "Rule saved to the configuration but not active. Call firewall_rule_apply to load it."

var filterProtocols = []string{"any", "TCP", "UDP", "TCP/UDP", "ICMP", "IPV6-ICMP", "ESP", "AH", "GRE", "IGMP", "OSPF", "CARP"}

type interfaceListOut struct {
	Interfaces []opnsense.InterfaceRef `json:"interfaces"`
}

type ruleListIn struct {
	Interface string `json:"interface,omitempty" jsonschema:"interface name (opt3) or description (WG_SITE2); also lists floating and group rules that apply"`
	Search    string `json:"search,omitempty"`
}

type ruleView struct {
	UUID            string   `json:"uuid"`
	Sequence        *int64   `json:"sequence,omitempty" jsonschema:"evaluation order, lower first"`
	Enabled         bool     `json:"enabled"`
	Action          string   `json:"action"`
	Quick           bool     `json:"quick"`
	Interfaces      []string `json:"interfaces" jsonschema:"empty = floating"`
	InterfaceNot    bool     `json:"interface_not,omitempty"`
	Direction       string   `json:"direction"`
	IPProtocol      string   `json:"ip_protocol"`
	Protocol        string   `json:"protocol"`
	Source          []string `json:"source"`
	SourceNot       bool     `json:"source_not,omitempty"`
	SourcePort      string   `json:"source_port,omitempty"`
	Destination     []string `json:"destination"`
	DestinationNot  bool     `json:"destination_not,omitempty"`
	DestinationPort string   `json:"destination_port,omitempty"`
	Gateway         string   `json:"gateway,omitempty" jsonschema:"policy routing gateway"`
	Log             bool     `json:"log"`
	Description     string   `json:"description"`
}

type ruleCreateIn struct {
	Description     string   `json:"description" jsonschema:"required: rules are found by their description"`
	Action          string   `json:"action,omitempty" jsonschema:"pass (default), block, reject or match"`
	Interfaces      []string `json:"interfaces" jsonschema:"interface names (opt3) or descriptions (WG_SITE2); see firewall_interface_list. Empty = floating rule"`
	Direction       string   `json:"direction,omitempty" jsonschema:"in (default), out or any; rules usually filter traffic entering an interface"`
	IPProtocol      string   `json:"ip_protocol,omitempty" jsonschema:"inet (default), inet6 or inet46"`
	Protocol        string   `json:"protocol,omitempty" jsonschema:"any (default), TCP, UDP, TCP/UDP, ICMP, ..."`
	Source          []string `json:"source,omitempty" jsonschema:"any (default), CIDRs, addresses, alias names, or interface networks like lan / opt3 (net) and lanip (address)"`
	SourceNot       bool     `json:"source_not,omitempty"`
	SourcePort      string   `json:"source_port,omitempty" jsonschema:"port, range (1000-2000) or port alias; TCP/UDP only"`
	Destination     []string `json:"destination,omitempty" jsonschema:"same forms as source"`
	DestinationNot  bool     `json:"destination_not,omitempty"`
	DestinationPort string   `json:"destination_port,omitempty" jsonschema:"port, range or port alias; TCP/UDP only"`
	Gateway         string   `json:"gateway,omitempty" jsonschema:"policy routing: send matching traffic to this gateway (name)"`
	Log             bool     `json:"log,omitempty"`
	Sequence        *int64   `json:"sequence,omitempty" jsonschema:"evaluation order; omit to append at the end"`
	Enabled         bool     `json:"enabled,omitempty" jsonschema:"defaults to false: review, then enable with firewall_rule_update"`
}

type ruleUpdateIn struct {
	NameRef
	NewDescription  *string   `json:"new_description,omitempty"`
	Action          *string   `json:"action,omitempty"`
	Interfaces      *[]string `json:"interfaces,omitempty" jsonschema:"replaces the list"`
	Direction       *string   `json:"direction,omitempty"`
	IPProtocol      *string   `json:"ip_protocol,omitempty"`
	Protocol        *string   `json:"protocol,omitempty"`
	Source          *[]string `json:"source,omitempty"`
	SourceNot       *bool     `json:"source_not,omitempty"`
	SourcePort      *string   `json:"source_port,omitempty"`
	Destination     *[]string `json:"destination,omitempty"`
	DestinationNot  *bool     `json:"destination_not,omitempty"`
	DestinationPort *string   `json:"destination_port,omitempty"`
	Gateway         *string   `json:"gateway,omitempty" jsonschema:"empty string removes policy routing"`
	Log             *bool     `json:"log,omitempty"`
	Sequence        *int64    `json:"sequence,omitempty"`
	Enabled         *bool     `json:"enabled,omitempty"`
}

type ruleMoveIn struct {
	Rule   NameRef `json:"rule" jsonschema:"the rule to move"`
	Before NameRef `json:"before" jsonschema:"the rule it should be evaluated just before"`
}

type ruleApplyOut struct {
	Applied  bool   `json:"applied"`
	Verified bool   `json:"verified" jsonschema:"the API was reachable over a new connection after the reload"`
	Note     string `json:"note,omitempty"`
}

func ruleViewOf(id string, r *opnsense.FilterRule) ruleView {
	return ruleView{
		UUID: id, Sequence: intPtr(r.Sequence), Enabled: bool(r.Enabled), Action: string(r.Action), Quick: bool(r.Quick),
		Interfaces: nonNil([]string(r.Interface)), InterfaceNot: bool(r.InterfaceNot), Direction: string(r.Direction),
		IPProtocol: string(r.IPProtocol), Protocol: string(r.Protocol), Source: nonNil([]string(r.SourceNet)),
		SourceNot: bool(r.SourceNot), SourcePort: r.SourcePort, Destination: nonNil([]string(r.DestinationNet)),
		DestinationNot: bool(r.DestinationNot), DestinationPort: r.DestinationPort, Gateway: string(r.Gateway),
		Log: bool(r.Log), Description: r.Description,
	}
}

// checkRule gives clear errors for the mistakes OPNsense would reject less clearly.
func checkRule(r *opnsense.FilterRule) error {
	if err := checkOneOf("action", string(r.Action), opnsense.FilterActions); err != nil {
		return err
	}
	if err := checkOneOf("direction", string(r.Direction), []string{"in", "out", "any"}); err != nil {
		return err
	}
	if err := checkOneOf("ip_protocol", string(r.IPProtocol), []string{"inet", "inet6", "inet46"}); err != nil {
		return err
	}
	tcpudp := slices.Contains([]string{"TCP", "UDP", "TCP/UDP"}, string(r.Protocol))
	if (r.SourcePort != "" || r.DestinationPort != "") && !tcpudp {
		return errors.New("ports need protocol TCP, UDP or TCP/UDP")
	}
	for name, list := range map[string][]string{"source": r.SourceNet, "destination": r.DestinationNet} {
		if len(list) > 1 && slices.Contains(list, "any") {
			return errors.New(name + ": any cannot be combined with other entries")
		}
	}
	if strings.TrimSpace(r.Description) == "" {
		return errors.New("description is required, so the rule can be found again")
	}
	return nil
}

func firewallRuleTools(c *opnsense.Client) []tool {
	f := c.Filter
	resolveIfaces := func(ctx context.Context, in []string) (opnsense.CSVList, error) {
		var out opnsense.CSVList
		for _, i := range in {
			name, err := f.ResolveInterface(ctx, i)
			if err != nil {
				return nil, err
			}
			out = append(out, name)
		}
		return out, nil
	}
	orAny := func(v []string) opnsense.CSVList {
		if len(v) == 0 {
			return opnsense.CSVList{"any"}
		}
		return v
	}
	def := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}

	return []tool{
		{toolset: firewallRuleToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_interface_list",
				Description: "List interfaces and interface groups rules can use: the name (lan, opt3) and the description shown in the UI.",
				Annotations: &mcp.ToolAnnotations{Title: "List firewall interfaces", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, interfaceListOut, error) {
				list, err := f.Interfaces(ctx)
				return nil, interfaceListOut{Interfaces: nonNil(list)}, err
			})
		}},
		{toolset: firewallRuleToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_rule_list",
				Description: "List firewall rules in evaluation order, optionally for one interface (including floating and " +
					"group rules that apply to it), with hit counters. Rows with legacy set are automatic or legacy rules " +
					"(e.g. the anti-lockout rule) and cannot be changed here.",
				Annotations: &mcp.ToolAnnotations{Title: "List firewall rules", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in ruleListIn) (*mcp.CallToolResult, listOut[opnsense.FilterRuleRow], error) {
				iface := ""
				if in.Interface != "" {
					var err error
					if iface, err = f.ResolveInterface(ctx, in.Interface); err != nil {
						return nil, listOut[opnsense.FilterRuleRow]{}, err
					}
				}
				res, err := f.SearchInterface(ctx, iface, in.Search)
				if err != nil {
					return nil, listOut[opnsense.FilterRuleRow]{}, err
				}
				return nil, listOut[opnsense.FilterRuleRow]{Items: nonNil(res.Rows), Total: res.Total}, nil
			})
		}},
		{toolset: firewallRuleToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_rule_get",
				Description: "Get a firewall rule by UUID or description.",
				Annotations: &mcp.ToolAnnotations{Title: "Get firewall rule", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, ruleView, error) {
				id, err := resolveNamed(ctx, f.Rules, in, "firewall rule")
				if err != nil {
					return nil, ruleView{}, err
				}
				r, err := f.Rules.Get(ctx, id)
				if err != nil {
					return nil, ruleView{}, notFoundAs(err, "firewall rule", id)
				}
				return nil, ruleViewOf(id, r), nil
			})
		}},
		{toolset: firewallRuleToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_rule_create",
				Description: "Create a firewall rule. It is created DISABLED unless enabled is true, and nothing is active " +
					"until firewall_rule_apply. Rules are evaluated in sequence order and the first match wins. Show the " +
					"user the rule and where it lands in firewall_rule_list before enabling it.",
				InputSchema: withEnum[ruleCreateIn]("protocol", filterProtocols),
				Annotations: &mcp.ToolAnnotations{Title: "Create firewall rule", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in ruleCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				ifaces, err := resolveIfaces(ctx, in.Interfaces)
				if err != nil {
					return nil, stagedOut{}, err
				}
				r := opnsense.FilterRule{
					Enabled: opnsense.Bool(in.Enabled), Sequence: toInt(in.Sequence),
					Action: opnsense.Option(def(in.Action, "pass")), Quick: true, Interface: ifaces,
					Direction: opnsense.Option(def(in.Direction, "in")), IPProtocol: opnsense.Option(def(in.IPProtocol, "inet")),
					Protocol: opnsense.Option(def(in.Protocol, "any")), SourceNet: orAny(in.Source), SourceNot: opnsense.Bool(in.SourceNot),
					SourcePort: in.SourcePort, DestinationNet: orAny(in.Destination), DestinationNot: opnsense.Bool(in.DestinationNot),
					DestinationPort: in.DestinationPort, Gateway: opnsense.Option(in.Gateway), Log: opnsense.Bool(in.Log),
					StateType: "keep", Description: in.Description,
				}
				if err := checkRule(&r); err != nil {
					return nil, stagedOut{}, err
				}
				id, err := f.Rules.Add(ctx, r)
				if err != nil {
					return nil, stagedOut{}, err
				}
				note := firewallRuleStagedNote
				if !in.Enabled {
					note = "Rule saved DISABLED. Enable it with firewall_rule_update (enabled: true), then firewall_rule_apply."
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: note}, nil
			})
		}},
		{toolset: firewallRuleToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_rule_update",
				Description: "Change a firewall rule, by UUID or description; only the fields given change. Not active until firewall_rule_apply.",
				InputSchema: withEnum[ruleUpdateIn]("protocol", filterProtocols),
				Annotations: &mcp.ToolAnnotations{Title: "Update firewall rule", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in ruleUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, f.Rules, in.NameRef, "firewall rule")
				if err != nil {
					return nil, stagedOut{}, err
				}
				r, err := f.Rules.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "firewall rule", id)
				}
				if in.Interfaces != nil {
					if r.Interface, err = resolveIfaces(ctx, *in.Interfaces); err != nil {
						return nil, stagedOut{}, err
					}
				}
				opt := func(v string) opnsense.Option { return opnsense.Option(v) }
				b := func(v bool) opnsense.Bool { return opnsense.Bool(v) }
				set(&r.Description, in.NewDescription)
				setAs(&r.Action, in.Action, opt)
				setAs(&r.Direction, in.Direction, opt)
				setAs(&r.IPProtocol, in.IPProtocol, opt)
				setAs(&r.Protocol, in.Protocol, opt)
				setAs(&r.SourceNet, in.Source, orAny)
				setAs(&r.SourceNot, in.SourceNot, b)
				set(&r.SourcePort, in.SourcePort)
				setAs(&r.DestinationNet, in.Destination, orAny)
				setAs(&r.DestinationNot, in.DestinationNot, b)
				set(&r.DestinationPort, in.DestinationPort)
				setAs(&r.Gateway, in.Gateway, opt)
				setAs(&r.Log, in.Log, b)
				setAs(&r.Sequence, in.Sequence, opnsense.IntOf)
				setAs(&r.Enabled, in.Enabled, b)
				if err := checkRule(r); err != nil {
					return nil, stagedOut{}, err
				}
				if err := f.Rules.Set(ctx, id, *r); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: firewallRuleStagedNote}, nil
			})
		}},
		deleteTool(firewallRuleToolset, "firewall_rule_delete", "Delete firewall rule", "firewall rule",
			" Address it by UUID or description.", firewallRuleStagedNote, f.Rules),
		{toolset: firewallRuleToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_rule_move",
				Description: "Move a rule so it is evaluated just before another rule. Order decides which rule matches first.",
				Annotations: &mcp.ToolAnnotations{Title: "Move firewall rule", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in ruleMoveIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, f.Rules, in.Rule, "firewall rule")
				if err != nil {
					return nil, stagedOut{}, err
				}
				target, err := resolveNamed(ctx, f.Rules, in.Before, "firewall rule")
				if err != nil {
					return nil, stagedOut{}, err
				}
				if err := f.MoveBefore(ctx, id, target); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: firewallRuleStagedNote}, nil
			})
		}},
		{toolset: firewallRuleToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firewall_rule_apply",
				Description: "Load all saved firewall rule changes. OPNsense has no automatic rollback: a wrong rule can " +
					"block traffic, including this connection. After loading, the tool checks over a new connection that " +
					"the API is still reachable and reports verified. Always confirm with the user first.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply firewall rules", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ruleApplyOut, error) {
				err := f.ApplyAndVerify(ctx, 5*time.Second)
				if err != nil && strings.Contains(err.Error(), "no longer reachable") {
					return nil, ruleApplyOut{Applied: true, Verified: false,
						Note: "Rules were loaded, but the API stopped answering new connections. Tell the user: fix it " +
							"from the console or a host the anti-lockout rule allows (LAN → web UI)."}, nil
				}
				if err != nil {
					return nil, ruleApplyOut{}, err
				}
				return nil, ruleApplyOut{Applied: true, Verified: true}, nil
			})
		}},
	}
}
