package opnsensetest

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Firewall filter rules, with the validations of models/OPNsense/Firewall/Filter.php that
// matter for clients, plus two read-only automatic rules in search results.
func registerFilter(s *Server) {
	ifaces := []struct{ name, descr, typ string }{
		{"lan", "LAN", "interface"}, {"wan", "WAN", "interface"},
		{"opt3", "WG_SITE2", "interface"}, {"vpn_group", "VPN", "group"},
	}
	ifaceNames := func(*Server) []string {
		var out []string
		for _, i := range ifaces {
			out = append(out, i.name)
		}
		return out
	}

	rules := s.add(&Collection{
		Base: "firewall/filter", Suffix: "Rule", Key: "rule",
		Fields: map[string]Field{
			"enabled":          {Default: "1"},
			"sequence":         {},
			"action":           {Kind: Option, Default: "pass", Choices: static("pass", "block", "reject", "match")},
			"quick":            {Default: "1"},
			"interface":        {Kind: Option, Sep: ",", Choices: ifaceNames},
			"interfacenot":     {Default: "0"},
			"direction":        {Kind: Option, Default: "in", Choices: static("in", "out", "any")},
			"ipprotocol":       {Kind: Option, Default: "inet", Choices: static("inet", "inet6", "inet46")},
			"protocol":         {Kind: Option, Default: "any", Choices: static("any", "TCP", "UDP", "TCP/UDP", "ICMP", "ESP", "GRE")},
			"source_net":       {Kind: List, Sep: ",", Default: "any"},
			"source_not":       {Default: "0"},
			"source_port":      {},
			"destination_net":  {Kind: List, Sep: ",", Default: "any"},
			"destination_not":  {Default: "0"},
			"destination_port": {},
			"gateway":          {Kind: Option, Choices: func(*Server) []string { return []string{"WAN_DHCP", "WG_SITE2"} }},
			"log":              {Default: "0"},
			"statetype":        {Kind: Option, Default: "keep", Choices: static("keep", "sloppy", "modulate", "synproxy", "none")},
			"categories":       {Kind: List, Sep: ","},
			"description":      {},
			"audit":            {ReadOnly: true},
		},
	})
	rules.OnWrite = func(_ *Server, uuid string, posted Record) {
		if _, exists := rules.items[uuid]; exists || posted["sequence"] != "" {
			return
		}
		max := 0
		for _, r := range rules.items {
			if n, _ := strconv.Atoi(r["sequence"]); n > max {
				max = n
			}
		}
		posted["sequence"] = strconv.Itoa(max + 100) // FilterSequenceField: append at the end
	}
	rules.Validate = func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		tcpudp := slices.Contains([]string{"TCP", "UDP", "TCP/UDP"}, r["protocol"])
		if r["source_port"] != "" && !tcpudp {
			v["rule.source_port"] = "Source ports are only valid for tcp or udp type rules."
		}
		if r["destination_port"] != "" && !tcpudp {
			v["rule.destination_port"] = "Destination ports are only valid for tcp or udp type rules."
		}
		for _, f := range []string{"source_net", "destination_net"} {
			nets := split(r[f], ",")
			if len(nets) > 1 && slices.Contains(nets, "any") {
				v["rule."+f] = "Any can not be combined with other aliases"
			}
			not := strings.TrimSuffix(f, "_net") + "_not"
			if r[not] == "1" && len(nets) > 1 {
				v["rule."+f] = "Inverting is only allowed for single targets to avoid mis-interpretations"
			}
		}
		for _, i := range split(r["interface"], ",") {
			if !slices.Contains(ifaceNames(nil), i) {
				v["rule.interface"] = "Option not in list."
			}
		}
		return v
	}
	rules.ExtraRows = func(*Server) []map[string]string {
		return []map[string]string{
			// list_non_mvc_rules.php: the uuid is the pf label, a hash for automatic rules and
			// the rule's uuid for rules from the legacy rules page.
			{"uuid": "bbabcf4bd0a5b8bfbe1b6b2b5d3e2a5e", "legacy": "1", "is_automatic": "1", "action": "pass", "interface": "lan", "description": "Anti-Lockout Rule"},
			{"uuid": "02f4bab031b57d1e30553ce08e0ec131", "legacy": "1", "is_automatic": "1", "action": "block", "interface": "", "description": "Default deny / state violation rule"},
			{"uuid": "8c3e1a6e-6f1d-4d8e-9a7b-2f0c3d4e5f60", "legacy": "1", "is_automatic": "0", "action": "pass", "interface": "lan", "description": "Legacy rule"},
		}
	}

	s.reconfigure["firewall/filter/apply"] = true
	s.reconfigureStatus["firewall/filter/apply"] = "OK\n" // configd output, as the real endpoint returns it

	s.extra["firewall/filter/getInterfaceList"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		out := map[string]any{
			"floating":   map[string]any{"items": []map[string]string{{"value": "__floating", "label": "Floating", "type": "floating"}}},
			"interfaces": map[string]any{"items": []map[string]string{}},
			"groups":     map[string]any{"items": []map[string]string{}},
		}
		for _, i := range ifaces {
			sec := out[i.typ+"s"].(map[string]any)
			sec["items"] = append(sec["items"].([]map[string]string), map[string]string{"value": i.name, "label": i.descr, "type": i.typ})
		}
		writeJSON(w, out)
	}
	s.extra["firewall/filter/moveRuleBefore"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, arg string) {
		uuid, target, _ := strings.Cut(arg, "/")
		r, ok1 := rules.items[uuid]
		t, ok2 := rules.items[target]
		if !ok1 || !ok2 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"errorMessage": fmt.Sprintf("unknown rule %s or %s", uuid, target)})
			return
		}
		tn, _ := strconv.Atoi(t["sequence"])
		r["sequence"] = strconv.Itoa(tn - 1)
		writeJSON(w, map[string]string{"status": "ok"})
	}
}

// registerDNat adds OPNsense's sequence numbering to the generated port forward collection:
// DNatSequenceField is an AutoNumberField, so an empty sequence gets the next free number.
func registerDNat(s *Server) {
	for _, c := range []*Collection{
		s.collection("firewall/d_nat", "rule"),
		s.collection("firewall/source_nat", "rule"),
		s.collection("firewall/one_to_one", "rule"),
		s.collection("firewall/npt", "rule"),
	} {
		autoSequence(c)
	}
	// DNatController::getAutomaticDestinationNatRules adds rules other services generate,
	// with an id that is not a UUID.
	s.collection("firewall/d_nat", "rule").ExtraRows = func(*Server) []map[string]string {
		return []map[string]string{{"uuid": "automatic_ipsec_1", "is_automatic": "1", "interface": "wan", "descr": "IPsec NAT-T"}}
	}
}

// autoSequence numbers rules like OPNsense's sequence fields: an unset sequence becomes the
// next free number on add and keeps its value on edit.
func autoSequence(rules *Collection) {
	rules.Fields["sequence"] = Field{HasRange: true, Min: 1, Max: 999999}
	rules.OnWrite = func(_ *Server, uuid string, posted Record) {
		if posted["sequence"] != "" {
			return
		}
		if old, ok := rules.items[uuid]; ok {
			posted["sequence"] = old["sequence"]
			return
		}
		next := 1
		for _, r := range rules.items {
			if n, err := strconv.Atoi(r["sequence"]); err == nil && n >= next {
				next = n + 1
			}
		}
		posted["sequence"] = strconv.Itoa(next)
	}
}
