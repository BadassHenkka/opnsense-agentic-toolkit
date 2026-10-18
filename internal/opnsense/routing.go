package opnsense

import (
	"context"
	"strings"
)

// System → Gateways and System → Routes. Two models, applied with one command:
//
//	routing/settings  gateway_item  {add,get,set,del,search}Gateway  System → Gateways → Configuration
//	routes/routes     route         {add,get,set,del,search}route    System → Routes → Configuration
//
// A static route names its gateway by gateway *name*, not uuid. A gateway's interface is an
// assigned interface (lan, opt3, ...), not a device name such as wg0. Both reconfigure actions
// run `interface routes configure`; Apply uses the routes one because it reports errors.
//
// Typical WireGuard site-to-site use: the peer's allowed IPs contain the remote network, the
// instance has "disable routes" set, wgN is assigned as optN, a gateway points at the peer's
// tunnel address on optN, and a static route sends the remote network to that gateway.

// Gateway, Route, their rows and RoutingService are generated (gen/specs/routing.json).
// For gateways from the gateway search (including dynamic ones such as WAN_DHCP), UUID is the
// gateway name when the gateway is not in the model.

// GatewayStatus is the live state of a gateway (dpinger).
type GatewayStatus struct {
	Name       Text `json:"name"`
	Address    Text `json:"address"`
	Status     Text `json:"status"`            // none, down, loss, delay, ...
	StatusText Text `json:"status_translated"` // Online, Offline, ...
	Loss       Text `json:"loss"`
	Delay      Text `json:"delay"`
	Stddev     Text `json:"stddev"`
	Monitor    Text `json:"monitor"`
}

const routesReconfigure = "routes/routes/reconfigure"

// Apply reconfigures gateways and routes (`interface routes configure`).
func (s *RoutingService) Apply(ctx context.Context) error {
	return s.c.Reconfigure(ctx, routesReconfigure)
}

// GatewayStatus returns the live status of all gateways.
func (s *RoutingService) GatewayStatus(ctx context.Context) ([]GatewayStatus, error) {
	var resp struct {
		Items  []GatewayStatus `json:"items"`
		Status string          `json:"status"`
	}
	if err := s.c.Get(ctx, "routes/gateway/status", &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// GatewayByName returns the uuid of the gateway with this name, or ErrNotFound. Dynamic
// gateways (WAN_DHCP, ...) have no uuid and are also reported as not found.
func (s *RoutingService) GatewayByName(ctx context.Context, name string) (string, error) {
	id, err := ResolveByName(ctx, s.Gateways, name)
	if err != nil {
		return "", err
	}
	if !uuidLike(id) {
		return "", ErrNotFound
	}
	return id, nil
}

func uuidLike(s string) bool { return len(s) == 36 && strings.Count(s, "-") == 4 }
