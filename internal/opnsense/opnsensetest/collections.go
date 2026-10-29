package opnsensetest

import (
	"net/http"
	"strings"
)

// registerAll declares every API area the fake serves. Add new areas here.
func registerAll(s *Server) {
	registerGenerated(s) // zz_gen_*.go; the functions below add hand-written behaviour
	registerFirewallAlias(s)
	registerUnbound(s)
	registerAcme(s)
	registerWireguard(s)
	registerRouting(s)
	registerFilter(s)
	registerDNat(s)
	registerAssignments(s)
	registerAuth(s)
	registerTrafficShaper(s)
	registerDnsmasq(s)
	registerTrust(s)
	registerIDS(s)
	registerBackup(s)
	registerKea(s)
	registerFirmware(s)
	registerWol(s)
	registerCaddy(s)
}

func required(prefix string, r Record, fields ...string) map[string]string {
	v := map[string]string{}
	for _, f := range fields {
		if r[f] == "" {
			v[prefix+"."+f] = "This field is required."
		}
	}
	return v
}

// Firewall aliases (generated collection). Adds name uniqueness, the real API's option map
// for content, and getAliasUUID.
func registerFirewallAlias(s *Server) {
	aliases := s.collection("firewall/alias", "alias")
	aliases.Fields["content"] = Field{Kind: List, Sep: "\n"}
	alsoValidate(aliases, func(_ *Server, self string, r Record) map[string]string {
		for id, other := range aliases.items {
			if id != self && r["name"] != "" && other["name"] == r["name"] {
				return map[string]string{"alias.name": "An alias with this name already exists."}
			}
		}
		return nil
	})
	s.reconfigure["firewall/alias/reconfigure"] = true
	s.extra["firewall/alias/getAliasUUID"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, name string) {
		for id, a := range aliases.items {
			if a["name"] == name {
				writeJSON(w, map[string]string{"uuid": id})
				return
			}
		}
		writeJSON(w, []any{})
	}
}

// Unbound host overrides and aliases (generated collections). Adds per-type required fields,
// the alias's link to its host, and the cascade delete.
func registerUnbound(s *Server) {
	hosts := s.collection("unbound/settings", "host")
	aliases := s.collection("unbound/settings", "alias")
	alsoValidate(hosts, func(_ *Server, _ string, r Record) map[string]string {
		switch r["rr"] {
		case "A", "AAAA":
			return required("host", r, "server")
		case "MX":
			return required("host", r, "mx", "mxprio")
		case "TXT":
			return required("host", r, "txtdata")
		}
		return nil
	})
	alsoValidate(aliases, func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		if _, ok := hosts.items[r["host"]]; !ok {
			v["alias.host"] = "Option not in list."
		}
		if r["hostname"] == "" && r["domain"] == "" {
			v["alias.hostname"] = "The host field is required if a domain has not been specified."
		}
		return v
	})
	// Blocklist apply downloads the lists; configd answers with its own text.
	s.extra["unbound/service/dnsbl"] = func(s *Server, w http.ResponseWriter, r *http.Request, _ string) {
		s.operations = append(s.operations, "unbound/service/dnsbl")
		writeJSON(w, map[string]string{"status": "OK"})
	}
	// Deleting a host override deletes its aliases, like SettingsController::delHostOverride.
	hosts.OnDelete = func(_ *Server, uuid string) {
		for id, a := range aliases.items {
			if a["host"] == uuid {
				delete(aliases.items, id)
			}
		}
	}
	s.reconfigure["unbound/service/reconfigure"] = true

	// Query forwarding and DNS over TLS servers are one array, dots.dot, told apart by type.
	// Like SettingsController, search lists one type, get returns either, and add and set
	// write the type of the action.
	var shared map[string]Record
	for _, c := range s.collections {
		if c.Base != "unbound/settings" || c.Key != "dot" {
			continue
		}
		if shared == nil {
			shared = c.items
		}
		c.items = shared
		typ := strings.ToLower(c.Suffix)
		f := c.Fields["type"]
		f.Kind, f.Choices = Option, static("dot", "forward")
		c.Fields["type"] = f
		c.OnWrite = func(_ *Server, _ string, posted Record) { posted["type"] = typ }
		c.SearchFilter = func(r Record) bool { return r["type"] == typ }
	}
}
