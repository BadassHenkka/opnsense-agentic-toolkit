package opnsensetest

import (
	"encoding/json"
	"net/http"
	"regexp"
)

var fakeMACRe = regexp.MustCompile(`^((?:[a-fA-F0-9]{2}:){5}(?:[a-fA-F0-9]{2}))$`)

// Wakes returns "interface mac" for every magic packet sent.
func (s *Server) Wakes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.wakes...)
}

// os-wol. The hosts collection is generated; this adds the plugin's quirks and waking. lan and
// opt3 have static addresses; wan uses DHCP, so waking there fails like on a real firewall.
func registerWol(s *Server) {
	hosts := s.collection("wol/wol", "host")
	hosts.EmptyDelete = true // delHost forgets to return anything
	hosts.Fields["interface"] = Field{Kind: Option, Required: true, Choices: static("lan", "wan", "opt3")}

	wake := func(iface, mac string) map[string]string {
		if iface == "wan" {
			return map[string]string{"status": "error", "error_msg": "Incorrect IPv4 configuration on interface"}
		}
		s.wakes = append(s.wakes, iface+" "+mac)
		return map[string]string{"status": "OK"}
	}
	s.extra["wol/wol/set"] = func(_ *Server, w http.ResponseWriter, r *http.Request, _ string) {
		var body struct {
			UUID string            `json:"uuid"`
			Wake map[string]string `json:"wake"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.UUID != "" {
			h, ok := hosts.items[body.UUID]
			if !ok {
				writeJSON(w, []any{}) // unknown uuid: nothing happens
				return
			}
			writeJSON(w, wake(h["interface"], h["mac"]))
			return
		}
		iface, mac := body.Wake["interface"], body.Wake["mac"]
		if !fakeMACRe.MatchString(mac) || (iface != "lan" && iface != "wan" && iface != "opt3") {
			writeJSON(w, []any{}) // validation failed: the plugin returns an empty result
			return
		}
		writeJSON(w, wake(iface, mac))
	}
	s.extra["wol/wol/wakeall"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		results := []map[string]string{}
		for _, id := range uuidsOf(hosts)(s) {
			h := hosts.items[id]
			res := wake(h["interface"], h["mac"])
			res["mac"] = h["mac"]
			results = append(results, res)
		}
		writeJSON(w, map[string]any{"results": results})
	}
}
