package opnsensetest

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
)

// CaddyGeneral returns a copy of the stored Caddy general settings (write form).
func (s *Server) CaddyGeneral() Record { return s.Settings("caddy/general/get", "general") }

func validIPOrNet(v string) bool {
	if net.ParseIP(v) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(v)
	return err == nil
}

// os-caddy: domains, subdomains, handlers and access lists in one model. The controller uses
// safe delete, so an item that another item references cannot be deleted.
func registerCaddy(s *Server) {
	const base = "caddy/reverse_proxy"
	// Collections and general settings are generated (gen/specs/caddy.json); this adds the
	// model's cross-item validation, safe delete, status and the Caddyfile.
	accessLists := s.collection(base, "accesslist")
	domains := s.collection(base, "reverse")
	subdomains := s.collection(base, "subdomain")
	handlers := s.collection(base, "handle")
	domains.Fields["CustomCertificate"] = Field{Kind: Option, Choices: static("64f0c0ffee000", "64f0c0ffee001")}

	in := func(v string, choices ...string) bool {
		for _, c := range choices {
			if v == c {
				return true
			}
		}
		return false
	}
	exists := func(c *Collection, id string) bool { _, ok := c.items[id]; return ok }

	alsoValidate(accessLists, func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		for _, ip := range split(r["clientIps"], ",") {
			if !validIPOrNet(ip) {
				v["accesslist.clientIps"] = "Please enter one or multiple valid IP addresses or networks."
			}
		}
		return v
	})
	alsoValidate(domains, func(_ *Server, self string, r Record) map[string]string {
		v := map[string]string{}
		ports := func(rec Record) []string {
			if rec["FromPort"] == "" {
				return []string{"80", "443"}
			}
			return []string{rec["FromPort"]}
		}
		for id, other := range domains.items {
			if id == self || !strings.EqualFold(other["FromDomain"], r["FromDomain"]) {
				continue
			}
			for _, p := range ports(r) {
				if in(p, ports(other)...) {
					v["reverse.FromDomain"] = fmt.Sprintf("Duplicate entry: The combination of %s and port %s is already used. "+
						"Each combination of domain and port must be unique.", r["FromDomain"], p)
				}
			}
		}
		if !in(r["DisableTls"], "0", "1") {
			v["reverse.DisableTls"] = "Option not in list."
		}
		if r["DisableTls"] == "1" && (r["DnsChallenge"] == "1" || r["CustomCertificate"] != "") {
			v["reverse.DisableTls"] = `TLS cannot be disabled if one of the following options are used: ` +
				`"DNS-01 Challenge", "HTTP-01 Challenge Redirection" and "Custom Certificate"`
		}
		if r["accesslist"] != "" && !exists(accessLists, r["accesslist"]) {
			v["reverse.accesslist"] = "Option not in list."
		}
		return v
	})
	alsoValidate(subdomains, func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		if r["reverse"] != "" && !exists(domains, r["reverse"]) {
			v["subdomain.reverse"] = "Option not in list."
		}
		if r["accesslist"] != "" && !exists(accessLists, r["accesslist"]) {
			v["subdomain.accesslist"] = "Option not in list."
		}
		return v
	})
	alsoValidate(handlers, func(_ *Server, _ string, r Record) map[string]string {
		v := map[string]string{}
		if r["reverse"] != "" && !exists(domains, r["reverse"]) {
			v["handle.reverse"] = "Option not in list."
		}
		if r["subdomain"] != "" && !exists(subdomains, r["subdomain"]) {
			v["handle.subdomain"] = "Option not in list."
		}
		if !in(r["HttpTls"], "0", "1", "2") {
			v["handle.HttpTls"] = "Option not in list."
		}
		if !in(r["HandleDirective"], "reverse_proxy", "redir") {
			v["handle.HandleDirective"] = "Option not in list."
		}
		if !in(r["HandleType"], "handle", "handle_path") {
			v["handle.HandleType"] = "Option not in list."
		}
		for _, f := range []string{"HandlePath", "ToPath"} {
			if r[f] != "" && !strings.HasPrefix(r[f], "/") {
				v["handle."+f] = "Please enter a valid path that starts with '/'."
			}
		}
		return v
	})

	// Safe delete: refuse while another item references the uuid.
	usedBy := func(uuid string, refs map[*Collection][]string) string {
		var users []string
		for c, fields := range refs {
			for id, rec := range c.items {
				for _, f := range fields {
					if in(uuid, split(rec[f], ",")...) {
						users = append(users, fmt.Sprintf("caddy.reverseproxy.%s.%s", c.Key, id))
					}
				}
			}
		}
		if len(users) == 0 {
			return ""
		}
		sort.Strings(users)
		return "Item in use by " + strings.Join(users, ", ")
	}
	domains.CanDelete = func(_ *Server, uuid string) string {
		return usedBy(uuid, map[*Collection][]string{subdomains: {"reverse"}, handlers: {"reverse"}})
	}
	subdomains.CanDelete = func(_ *Server, uuid string) string {
		return usedBy(uuid, map[*Collection][]string{handlers: {"subdomain"}})
	}
	accessLists.CanDelete = func(_ *Server, uuid string) string {
		return usedBy(uuid, map[*Collection][]string{domains: {"accesslist"}, subdomains: {"accesslist"}, handlers: {"accesslist"}})
	}

	s.reconfigure["caddy/service/reconfigure"] = true
	s.extra["caddy/service/status"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		st := "stopped"
		if s.settingsRec("caddy/general/get", "general")["enabled"] == "1" {
			st = "running"
		}
		writeJSON(w, map[string]any{"status": st})
	}

	// A simplified Caddyfile: one site block per enabled domain, one handle per handler.
	s.extra["caddy/diagnostics/caddyfile"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		var b strings.Builder
		for _, id := range uuidsOf(domains)(s) {
			d := domains.items[id]
			if d["enabled"] != "1" {
				continue
			}
			site := d["FromDomain"]
			if d["FromPort"] != "" {
				site += ":" + d["FromPort"]
			}
			if d["DisableTls"] == "1" {
				site = "http://" + site
			}
			fmt.Fprintf(&b, "%s {\n", site)
			for _, hid := range uuidsOf(handlers)(s) {
				h := handlers.items[hid]
				if h["reverse"] != id || h["enabled"] != "1" {
					continue
				}
				scheme := map[string]string{"0": "http", "1": "https", "2": "h2c"}[h["HttpTls"]]
				var ups []string
				for _, u := range split(h["ToDomain"], ",") {
					if h["ToPort"] != "" {
						u += ":" + h["ToPort"]
					}
					ups = append(ups, scheme+"://"+u)
				}
				fmt.Fprintf(&b, "\t%s %s {\n\t\t%s %s\n\t}\n", h["HandleType"], h["HandlePath"],
					h["HandleDirective"], strings.Join(ups, " "))
			}
			b.WriteString("}\n")
		}
		writeJSON(w, map[string]any{"status": "success", "content": b.String()})
	}
}
