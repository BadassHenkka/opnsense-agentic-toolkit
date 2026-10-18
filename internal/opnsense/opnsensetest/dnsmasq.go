package opnsensetest

import (
	"net/http"
)

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
