package opnsensetest

import (
	"net/http"
)

// registerAll declares every API area the fake serves. Add new areas here.
func registerAll(s *Server) {
	registerGenerated(s) // zz_gen_*.go; the functions below add hand-written behaviour
	registerFirewallAlias(s)
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
