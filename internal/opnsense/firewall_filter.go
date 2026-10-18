package opnsense

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Firewall → Rules (MVC filter rules, /api/firewall/filter).
//
//	{add,get,set,del,search}Rule   key "rule"
//	moveRuleBefore/<uuid>/<target> reorder
//	getInterfaceList               interface keys (lan, opt3) with their descriptions
//	apply                          `filter reload skip_alias`, answers {"status":"OK\n"}
//
// Rules are evaluated in `sequence` order. sequence is an auto-number: a rule added without
// one goes to the end (highest + 100).
//
// searchRule also returns automatic and legacy (pre-MVC) rules, flagged "legacy"; they are
// read-only through this API.
//
// There is no savepoint/rollback in current OPNsense (it was removed from the filter API),
// so ApplyAndVerify checks afterwards that the API is still reachable over a *new*
// connection. Existing keep-alive connections survive in pf's state table and would give
// false confidence.

// FilterActions lists rule actions.
var FilterActions = []string{"pass", "block", "reject", "match"}

// FilterRule is a firewall filter rule.
type FilterRule struct {
	Enabled Bool `json:"enabled"`
	// Sequence orders evaluation. Zero (unset) lets OPNsense append the rule.
	Sequence Int    `json:"sequence,omitzero"`
	Action   Option `json:"action"`
	// Quick: the first matching rule wins (OPNsense's default). Without it the last match wins.
	Quick Bool `json:"quick"`
	// Interface lists assigned interfaces or groups (lan, opt3). Empty means floating.
	Interface    CSVList `json:"interface"`
	InterfaceNot Bool    `json:"interfacenot"`
	Direction    Option  `json:"direction"`  // in, out, any
	IPProtocol   Option  `json:"ipprotocol"` // inet, inet6, inet46
	Protocol     Option  `json:"protocol"`   // any, TCP, UDP, TCP/UDP, ICMP, ...
	// SourceNet and DestinationNet hold "any", networks (CIDR), addresses, aliases or
	// interface networks such as "lan" / "lanip".
	SourceNet       CSVList `json:"source_net"`
	SourceNot       Bool    `json:"source_not"`
	SourcePort      string  `json:"source_port"`
	DestinationNet  CSVList `json:"destination_net"`
	DestinationNot  Bool    `json:"destination_not"`
	DestinationPort string  `json:"destination_port"`
	// Gateway enables policy routing: matching traffic goes to this gateway (by name).
	Gateway     Option  `json:"gateway"`
	Log         Bool    `json:"log"`
	StateType   Option  `json:"statetype"`
	Categories  CSVList `json:"categories"`
	Description string  `json:"description"`
}

func (r *FilterRule) IsZero() bool { return r.Action == "" }

// FilterRuleRow is one row of a rule search. Legacy and automatic rules are included, with
// Legacy set; only MVC rules (Legacy empty) can be changed through the API.
type FilterRuleRow struct {
	UUID            Text `json:"uuid"`
	Enabled         Text `json:"enabled"`
	Sequence        Text `json:"sequence"`
	Action          Text `json:"action"`
	Interface       Text `json:"interface"`
	Direction       Text `json:"direction"`
	IPProtocol      Text `json:"ipprotocol"`
	Protocol        Text `json:"protocol"`
	SourceNet       Text `json:"source_net"`
	SourcePort      Text `json:"source_port"`
	DestinationNet  Text `json:"destination_net"`
	DestinationPort Text `json:"destination_port"`
	Gateway         Text `json:"gateway"`
	Description     Text `json:"description"`
	Legacy          Text `json:"legacy"`
	Evaluations     Text `json:"evaluations"`
	States          Text `json:"states"`
	Packets         Text `json:"packets"`
	Bytes           Text `json:"bytes"`
}

// RowRef uses the description as the name. Legacy rules get no uuid, so they never resolve.
func (r FilterRuleRow) RowRef() (string, string) {
	if r.Legacy != "" && r.Legacy != "0" && r.Legacy != "false" {
		return "", ""
	}
	return string(r.UUID), string(r.Description)
}

// InterfaceRef is an interface or group rules can be attached to.
type InterfaceRef struct {
	Name        string `json:"name"`        // lan, opt3, ...
	Description string `json:"description"` // the label shown in the UI
	Type        string `json:"type"`        // interface or group
}

// FilterService manages firewall filter rules.
type FilterService struct {
	c     *Client
	Rules *ItemController[FilterRule, FilterRuleRow]
}

const filterApply = "firewall/filter/apply"

func newFilterService(c *Client) *FilterService {
	return &FilterService{c: c, Rules: &ItemController[FilterRule, FilterRuleRow]{
		c: c, Base: "firewall/filter", Key: "rule", Suffix: "Rule", ReconfigurePath: filterApply,
	}}
}

// Apply reloads the firewall rules.
func (s *FilterService) Apply(ctx context.Context) error { return s.c.Reconfigure(ctx, filterApply) }

// ApplyAndVerify reloads the rules, then checks over a new connection that the API is still
// reachable. It retries for up to wait (default 10s), since pf reloads take a moment. An error
// after a successful apply means the new rules may have cut off this client: revert them from
// the console or a host the anti-lockout rule still allows.
func (s *FilterService) ApplyAndVerify(ctx context.Context, wait time.Duration) error {
	if err := s.Apply(ctx); err != nil {
		return err
	}
	if err := s.c.VerifyReachable(ctx, wait); err != nil {
		return fmt.Errorf("opnsense: rules applied, but %w; the new rules may block this client", err)
	}
	return nil
}

// MoveBefore moves a rule so it is evaluated right before target.
func (s *FilterService) MoveBefore(ctx context.Context, uuid, target string) error {
	var resp struct {
		Status string `json:"status"`
	}
	path := "firewall/filter/moveRuleBefore/" + url.PathEscape(uuid) + "/" + url.PathEscape(target)
	if err := s.c.Post(ctx, path, nil, &resp); err != nil {
		return err
	}
	if !strings.EqualFold(resp.Status, "ok") {
		return fmt.Errorf("opnsense: move rule: status %q", resp.Status)
	}
	return nil
}

// SearchInterface lists the rules that apply to an interface (including its groups), plus
// floating rules. An empty interface lists all rules.
func (s *FilterService) SearchInterface(ctx context.Context, iface, phrase string) (*SearchResult[FilterRuleRow], error) {
	var filters map[string]any
	if iface != "" {
		filters = map[string]any{"interface": iface}
	}
	return s.Rules.SearchWith(ctx, phrase, filters)
}

// Interfaces lists interfaces and groups rules can use, with their UI descriptions.
func (s *FilterService) Interfaces(ctx context.Context) ([]InterfaceRef, error) {
	var resp map[string]struct {
		Items []struct {
			Value string `json:"value"`
			Label string `json:"label"`
			Type  string `json:"type"`
		} `json:"items"`
	}
	if err := s.c.Get(ctx, "firewall/filter/getInterfaceList", &resp); err != nil {
		return nil, err
	}
	var out []InterfaceRef
	for _, section := range []string{"interfaces", "groups"} {
		for _, it := range resp[section].Items {
			out = append(out, InterfaceRef{Name: it.Value, Description: it.Label, Type: it.Type})
		}
	}
	return out, nil
}

// ResolveInterface maps a name (opt3) or description (WG_SITE2, case-insensitive) to the
// interface key rules and gateways use.
func (s *FilterService) ResolveInterface(ctx context.Context, nameOrDescription string) (string, error) {
	list, err := s.Interfaces(ctx)
	if err != nil {
		return "", err
	}
	for _, i := range list {
		if i.Name == nameOrDescription {
			return i.Name, nil
		}
	}
	for _, i := range list {
		if strings.EqualFold(i.Description, nameOrDescription) {
			return i.Name, nil
		}
	}
	return "", fmt.Errorf("opnsense: no interface or group %q", nameOrDescription)
}
