package opnsensetest

import (
	"net/http"
	"strings"
)

// registerBackup serves two config backups, a diff between them and a ZFS snapshot list.
func registerBackup(s *Server) {
	s.extra["core/backup/backups"] = func(s *Server, w http.ResponseWriter, _ *http.Request, host string) {
		items := []map[string]any{}
		if host == "this" {
			items = []map[string]any{
				{"id": "config-1700000200.1.xml", "time": "1700000200.1", "time_iso": "2023-11-14T22:16:40+00:00", "description": "/api/firewall/alias/addItem made changes", "username": "root@10.0.0.2 (Local API)", "filesize": 51000},
				{"id": "config-1700000100.2.xml", "time": "1700000100.2", "time_iso": "2023-11-14T22:15:00+00:00", "description": "initial", "username": "root@10.0.0.2", "filesize": 50000},
			}
		}
		writeJSON(w, map[string]any{"items": items})
	}
	s.extra["core/backup/diff"] = func(s *Server, w http.ResponseWriter, _ *http.Request, rest string) {
		parts := strings.Split(rest, "/")
		items := []string{}
		if len(parts) == 3 && parts[0] == "this" {
			items = []string{"--- " + parts[2], "+++ " + parts[1], "@@ -1,1 +1,2 @@", "+<alias/>"}
		}
		writeJSON(w, map[string]any{"items": items})
	}
	s.extra["core/snapshots/isSupported"] = func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, map[string]bool{"supported": true})
	}
	s.extra["core/snapshots/search"] = func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		rows := []map[string]string{{"uuid": "snap-1", "name": "pre-upgrade", "active": "NR", "mountpoint": "/", "created": "2026-10-01 10:00", "size": "1.2G"}}
		writeJSON(w, map[string]any{"rows": rows, "rowCount": 1, "total": 1, "current": 1})
	}
}
