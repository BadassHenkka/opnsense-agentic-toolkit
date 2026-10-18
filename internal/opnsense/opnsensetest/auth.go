package opnsensetest

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// registerAuth adds what auth/user and auth/group do beyond plain CRUD: uid/gid allocation,
// group membership synced from the user's group_memberships, and API keys.
func registerAuth(s *Server) {
	users, groups := s.collection("auth/user", "user"), s.collection("auth/group", "group")
	next := func(c *Collection, field string, start int) string {
		n := start
		for _, r := range c.items {
			if v, err := strconv.Atoi(r[field]); err == nil && v >= n {
				n = v + 1
			}
		}
		return strconv.Itoa(n)
	}
	groups.OnWrite = func(_ *Server, uuid string, posted Record) {
		if _, ok := groups.items[uuid]; !ok {
			posted["gid"], posted["scope"] = next(groups, "gid", 2000), "user"
		}
	}
	users.OnWrite = func(_ *Server, uuid string, posted Record) {
		old, ok := users.items[uuid]
		uid := old["uid"]
		if !ok {
			uid = next(users, "uid", 2000)
			posted["uid"], posted["scope"] = uid, "user"
		}
		gids := strings.Split(posted["group_memberships"], ",")
		for _, g := range groups.items {
			members := slices.DeleteFunc(strings.Split(g["member"], ","), func(m string) bool { return m == "" || m == uid })
			if slices.Contains(gids, g["gid"]) {
				members = append(members, uid)
			}
			g["member"] = strings.Join(members, ",")
		}
	}

	keys := map[string]string{} // key -> username
	s.extra["auth/user/addApiKey"] = func(s *Server, w http.ResponseWriter, r *http.Request, user string) {
		for _, u := range users.items {
			if u["name"] == user && r.Method == http.MethodPost {
				s.nextID++
				key := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("key/%d+%s", s.nextID, user)))
				keys[key] = user
				writeJSON(w, map[string]string{"result": "ok", "key": key, "secret": "secret-" + key, "hostname": "fw.test"})
				return
			}
		}
		writeJSON(w, map[string]string{"result": "failed"})
	}
	s.extra["auth/user/delApiKey"] = func(s *Server, w http.ResponseWriter, r *http.Request, id string) {
		raw, err := base64.StdEncoding.DecodeString(id)
		if _, ok := keys[string(raw)]; err != nil || !ok || r.Method != http.MethodPost {
			writeJSON(w, map[string]string{"result": "not found"})
			return
		}
		delete(keys, string(raw))
		writeJSON(w, map[string]string{"result": "deleted"})
	}
	s.extra["auth/user/searchApiKey"] = func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		rows := []map[string]string{}
		for k, u := range keys {
			rows = append(rows, map[string]string{"username": u, "key": k, "id": base64.StdEncoding.EncodeToString([]byte(k))})
		}
		slices.SortFunc(rows, func(a, b map[string]string) int { return strings.Compare(a["key"], b["key"]) })
		writeJSON(w, map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	}
	// Deleting a user deletes its keys.
	users.OnDelete = func(_ *Server, _ string) {
		for k, u := range keys {
			if !userExists(users, u) {
				delete(keys, k)
			}
		}
	}
}

func userExists(c *Collection, name string) bool {
	for _, u := range c.items {
		if u["name"] == name {
			return true
		}
	}
	return false
}
