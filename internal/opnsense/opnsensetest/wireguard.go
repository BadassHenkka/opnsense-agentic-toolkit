package opnsensetest

import (
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// WireGuard. Membership lives on the instance (server.peers); a peer's "servers" is
// volatile: computed on read, and on write it rewrites the instances' peer lists, exactly
// like ClientController::setClientAction.

func registerWireguard(s *Server) {
	// Collections and general settings are generated (gen/specs/wireguard.json); this adds
	// instance numbering, the device name, and peer membership.
	instances := s.collection("wireguard/server", "server")
	instances.Fields["peers"] = Field{ReadOnly: true, Kind: List, Sep: ","}
	instances.Fields["interface"] = Field{ReadOnly: true, Virtual: func(_ *Server, uuid string) string {
		if r, ok := instances.items[uuid]; ok {
			return "wg" + r["instance"]
		}
		return ""
	}}
	instances.OnWrite = func(_ *Server, uuid string, posted Record) {
		if _, exists := instances.items[uuid]; exists {
			return
		}
		used := map[int]bool{}
		for _, r := range instances.items {
			n, _ := strconv.Atoi(r["instance"])
			used[n] = true
		}
		n := 0
		for used[n] {
			n++
		}
		posted["instance"] = strconv.Itoa(n) // AutoNumberField
	}

	peers := s.collection("wireguard/client", "client")
	peers.Fields["servers"] = Field{Kind: Option, Sep: ",",
		Choices: uuidsOf(instances),
		Virtual: func(_ *Server, uuid string) string {
			var ids []string
			for id, inst := range instances.items {
				if slices.Contains(split(inst["peers"], ","), uuid) {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			return strings.Join(ids, ",")
		}}
	alsoValidate(peers, func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		for _, a := range split(r["tunneladdress"], ",") {
			if !strings.Contains(a, "/") {
				v["client.tunneladdress"] = "A netmask is required."
			}
		}
		return v
	})
	setMembership := func(peer string, want []string) {
		for id, inst := range instances.items {
			list := split(inst["peers"], ",")
			has := slices.Contains(list, peer)
			switch {
			case has && !slices.Contains(want, id):
				list = slices.DeleteFunc(list, func(x string) bool { return x == peer })
			case !has && slices.Contains(want, id):
				list = append(list, peer)
			}
			inst["peers"] = strings.Join(list, ",")
		}
	}
	peers.OnWrite = func(_ *Server, uuid string, posted Record) {
		setMembership(uuid, split(posted["servers"], ",")) // absent = detach from all
		delete(posted, "servers")
	}
	peers.OnDelete = func(_ *Server, uuid string) { setMembership(uuid, nil) }

	s.reconfigure["wireguard/service/reconfigure"] = true

	// service/show: one interface row per instance, one peer row per member peer. Peers of
	// the first instance are "online", others have never shaken hands.
	s.extra["wireguard/service/show"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		rows := []map[string]any{}
		ids := uuidsOf(instances)(s)
		for i, id := range ids {
			inst := instances.items[id]
			ifname := "wg" + inst["instance"]
			rows = append(rows, map[string]any{"type": "interface", "if": ifname, "name": inst["name"],
				"ifname": inst["name"], "public-key": inst["pubkey"], "listen-port": inst["port"], "status": "up",
				"peer-status": "offline", "latest-handshake-age": nil})
			for _, p := range split(inst["peers"], ",") {
				peer := peers.items[p]
				row := map[string]any{"type": "peer", "if": ifname, "ifname": inst["name"], "name": peer["name"],
					"public-key": peer["pubkey"], "allowed-ips": peer["tunneladdress"], "endpoint": "(none)",
					"latest-handshake-age": nil, "peer-status": "offline", "transfer-rx": 0, "transfer-tx": 0}
				if i == 0 {
					row["latest-handshake-age"], row["latest-handshake-epoch"] = 42, "2026-10-17 09:00:00"
					row["peer-status"], row["transfer-rx"], row["transfer-tx"] = "online", 1024, 2048
				}
				rows = append(rows, row)
			}
		}
		writeJSON(w, map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	}
}

// WireguardEnabled returns the stored global enabled flag.
func (s *Server) WireguardEnabled() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settingsRec("wireguard/general/get", "")["enabled"]
}
