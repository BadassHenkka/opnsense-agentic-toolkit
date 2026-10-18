package opnsensetest

import (
	"net/http"
	"slices"
	"strings"
)

// registerIDS adds the ruleset endpoints: a fixed catalogue of downloadable rule files whose
// enabled flag can be listed and toggled.
func registerIDS(s *Server) {
	type rs struct{ desc, enabled string }
	files := map[string]*rs{
		"abuse.ch.sslblacklist.rules": {"abuse.ch SSL Blacklist", "0"},
		"emerging-scan.rules":         {"ET open/scan", "0"},
	}
	s.extra["ids/settings/listRulesets"] = func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		rows := []map[string]string{}
		for name, f := range files {
			rows = append(rows, map[string]string{"filename": name, "description": f.desc, "enabled": f.enabled})
		}
		slices.SortFunc(rows, func(a, b map[string]string) int { return strings.Compare(a["filename"], b["filename"]) })
		writeJSON(w, map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	}
	s.extra["ids/settings/toggleRuleset"] = func(s *Server, w http.ResponseWriter, r *http.Request, rest string) {
		name, flag, _ := strings.Cut(rest, "/")
		f, ok := files[name]
		if !ok || r.Method != http.MethodPost || (flag != "0" && flag != "1") {
			writeJSON(w, map[string]string{"status": "error"})
			return
		}
		f.enabled = flag
		writeJSON(w, map[string]string{"status": flag})
	}
}
