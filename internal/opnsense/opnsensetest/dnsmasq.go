package opnsensetest

import (
	"net/http"
	"strconv"
)

// registerDnsmasq numbers domain overrides like OPNsense's AutoNumberField: a new item gets
// the next free sequence, an edit keeps its own.
func registerDnsmasq(s *Server) {
	domains := s.collection("dnsmasq/settings", "domainoverride")
	domains.Fields["sequence"] = Field{HasRange: true, Min: 1, Max: 99999} // assigned on add
	domains.OnWrite = func(_ *Server, uuid string, posted Record) {
		if posted["sequence"] != "" {
			return
		}
		if old, ok := domains.items[uuid]; ok {
			posted["sequence"] = old["sequence"]
			return
		}
		next := 1
		for _, r := range domains.items {
			if n, err := strconv.Atoi(r["sequence"]); err == nil && n >= next {
				next = n + 1
			}
		}
		posted["sequence"] = strconv.Itoa(next)
	}
	// Leases come from dnsmasq's lease file; the fake serves what a test puts in Leases.
	s.extra["dnsmasq/leases/search"] = func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		rows := s.Leases
		if rows == nil {
			rows = []map[string]string{}
		}
		writeJSON(w, map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	}
}

// registerKea serves the Kea lease lists from Server.KeaLeases4/KeaLeases6.
func registerKea(s *Server) {
	serve := func(rows *[]map[string]string) func(*Server, http.ResponseWriter, *http.Request, string) {
		return func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
			out := *rows
			if out == nil {
				out = []map[string]string{}
			}
			writeJSON(w, map[string]any{"rows": out, "rowCount": len(out), "total": len(out), "current": 1})
		}
	}
	s.extra["kea/leases4/search"] = serve(&s.KeaLeases4)
	s.extra["kea/leases6/search"] = serve(&s.KeaLeases6)
}
