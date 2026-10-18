package opnsensetest

import (
	"fmt"
	"net"
	"net/http"
	"sort"
)

// Gateways and static routes (collections generated from gen/specs/routing.json). Routes
// reference gateways by name; a gateway in use by a route cannot be deleted
// (SettingsController::delGatewayAction throws a UserException).
func registerRouting(s *Server) {
	gateways := s.collection("routing/settings", "gateway_item")
	routes := s.collection("routes/routes", "route")
	gateways.Fields["interface"] = Field{Kind: Option, Required: true, Choices: static("lan", "wan", "opt1", "opt2", "opt3")}
	gatewayNames := func(*Server) []string {
		names := []string{"WAN_DHCP"} // a dynamic gateway, as on a real firewall
		for _, g := range gateways.items {
			names = append(names, g["name"])
		}
		sort.Strings(names)
		return names
	}
	alsoValidate(gateways, func(_ *Server, self string, r Record) map[string]string {
		v := map[string]string{}
		for id, g := range gateways.items {
			if id != self && g["name"] == r["name"] {
				v["gateway_item.name"] = "A gateway with this name already exists."
			}
		}
		if ip := r["gateway"]; ip != "" && net.ParseIP(ip) == nil {
			v["gateway_item.gateway"] = "A valid gateway IP address must be specified."
		}
		return v
	})

	alsoValidate(routes, func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		if r["network"] != "" {
			if _, _, err := net.ParseCIDR(r["network"]); err != nil {
				v["route.network"] = "Please specify a valid network segment or IP address."
			}
		}
		known := false
		for _, n := range gatewayNames(nil) {
			known = known || n == r["gateway"]
		}
		if r["gateway"] != "" && !known {
			v["route.gateway"] = "Option not in list."
		}
		return v
	})
	gateways.CanDelete = func(_ *Server, uuid string) string {
		name := gateways.items[uuid]["name"]
		var nets []string
		for _, r := range routes.items {
			if r["gateway"] == name {
				nets = append(nets, r["network"])
			}
		}
		if len(nets) > 0 {
			sort.Strings(nets)
			return fmt.Sprintf("Gateway %s cannot be deleted because it is in use on Static Route(s) '%v'", name, nets)
		}
		return ""
	}

	s.reconfigure["routes/routes/reconfigure"] = true
	s.reconfigure["routing/settings/reconfigure"] = true
	s.extra["routes/gateway/status"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		items := []map[string]string{}
		for _, g := range gateways.items {
			items = append(items, map[string]string{"name": g["name"], "address": g["gateway"],
				"status": "none", "status_translated": "Online", "loss": "0.0 %", "delay": "1.2 ms"})
		}
		writeJSON(w, map[string]any{"items": items, "status": "ok"})
	}
}
