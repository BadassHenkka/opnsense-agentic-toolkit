package opnsensetest

import (
	"net/http"
	"sort"
	"strings"
)

// The ACME client plugin. Challenge types and automations really have hundreds of
// provider-specific fields; the fake declares a representative few.

var acmeActions = map[string]string{"add": "add", "get": "get", "set": "update", "del": "del", "search": "search"}

func uuidsOf(c *Collection) func(*Server) []string {
	return func(*Server) []string {
		ids := make([]string, 0, len(c.items))
		for id := range c.items {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids
	}
}

func uniqueName(c *Collection, prefix, self string, r Record) map[string]string {
	v := required(prefix, r, "name")
	for id, other := range c.items {
		if id != self && r["name"] != "" && other["name"] == r["name"] {
			v[prefix+".name"] = "Should be a unique value."
		}
	}
	return v
}

func registerAcme(s *Server) {
	// Settings, accounts and certificates are generated (gen/specs/acme.json); challenge types
	// and automations are declared here with a representative few provider fields.
	accounts := s.collection("acmeclient/accounts", "account")
	alsoValidate(accounts, func(_ *Server, self string, r Record) map[string]string {
		return uniqueName(accounts, "account", self, r)
	})

	challenges := s.add(&Collection{
		Base: "acmeclient/validations", Actions: acmeActions, Key: "validation",
		Fields: map[string]Field{
			"id":                     {},
			"enabled":                {Default: "1"},
			"name":                   {},
			"description":            {},
			"method":                 {Kind: Option, Default: "dns01", Choices: static("http01", "dns01", "tlsalpn01")},
			"http_service":           {Kind: Option, Default: "opnsense", Choices: static("opnsense", "haproxy")},
			"http_opn_autodiscovery": {Default: "1"},
			"http_opn_ipaddresses":   {Kind: List, Sep: ","},
			"dns_service":            {Kind: Option, Default: "dns_freedns", Choices: static("dns_cf", "dns_freedns", "dns_loopia")},
			"dns_sleep":              {Default: "0"},
			"dns_cf_token":           {},
			"dns_cf_account_id":      {},
			"dns_cf_zone_id":         {},
			"dns_cf_email":           {},
			"dns_cf_key":             {},
			"dns_freedns_user":       {},
			"dns_freedns_password":   {},
			"dns_loopia_api":         {Default: "https://api.loopia.se/RPCSERV"},
			"dns_loopia_user":        {},
			"dns_loopia_password":    {},
		},
	})
	challenges.Validate = func(_ *Server, self string, r Record) map[string]string {
		return uniqueName(challenges, "validation", self, r)
	}

	automations := s.add(&Collection{
		Base: "acmeclient/actions", Actions: acmeActions, Key: "action",
		Fields: map[string]Field{
			"id":          {},
			"enabled":     {Default: "1"},
			"name":        {},
			"description": {},
			"type": {Kind: Option, Choices: static(
				"configd_restart_gui", "configd_restart_haproxy", "configd_upload_sftp", "acme_proxmoxve")},
			"sftp_host":               {},
			"sftp_port":               {Default: "22"},
			"sftp_user":               {},
			"acme_proxmoxve_user":     {Default: "root"},
			"acme_proxmoxve_server":   {},
			"acme_proxmoxve_port":     {Default: "8006"},
			"acme_proxmoxve_tokenid":  {Default: "acme"},
			"acme_proxmoxve_tokenkey": {},
			"acme_proxmoxve_nodename": {},
			"acme_proxmoxve_realm":    {Default: "pam"},
		},
	})
	automations.Validate = func(_ *Server, self string, r Record) map[string]string {
		v := uniqueName(automations, "action", self, r)
		for k, msg := range required("action", r, "type") {
			v[k] = msg
		}
		return v
	}

	certificates := s.collection("acmeclient/certificates", "certificate")
	alsoValidate(certificates, func(_ *Server, self string, r Record) map[string]string {
		v := uniqueName(certificates, "certificate", self, r)
		if _, ok := accounts.items[r["account"]]; !ok {
			v["certificate.account"] = "Related item not found."
		}
		if _, ok := challenges.items[r["validationMethod"]]; !ok {
			v["certificate.validationMethod"] = "Related item not found."
		}
		for _, a := range split(r["restartActions"], ",") {
			if _, ok := automations.items[a]; !ok {
				v["certificate.restartActions"] = "Related item not found."
			}
		}
		return v
	})

	s.reconfigure["acmeclient/service/reconfigure"] = true

	// Operations. Real issuing runs in the background; the fake completes it at once.
	op := func(c *Collection, apply func(Record)) func(*Server, http.ResponseWriter, *http.Request, string) {
		return func(s *Server, w http.ResponseWriter, r *http.Request, uuid string) {
			rec, ok := c.items[uuid]
			if !ok || r.Method != http.MethodPost {
				writeJSON(w, map[string]string{"result": "failed"})
				return
			}
			s.operations = append(s.operations, strings.TrimPrefix(r.URL.Path, "/api/"))
			apply(rec)
			writeJSON(w, map[string]string{"response": "OK"})
		}
	}
	s.extra["acmeclient/accounts/register"] = op(accounts, func(r Record) { r["statusCode"] = "200" })
	s.extra["acmeclient/certificates/sign"] = op(certificates, func(r Record) {
		r["statusCode"], r["lastUpdate"], r["certRefId"] = "200", "1760690000", "6710b2f0c1a3e"
	})
	s.extra["acmeclient/certificates/revoke"] = op(certificates, func(r Record) { r["statusCode"] = "250" })
	s.extra["acmeclient/certificates/automation"] = func(s *Server, w http.ResponseWriter, r *http.Request, uuid string) {
		s.operations = append(s.operations, strings.TrimPrefix(r.URL.Path, "/api/"))
		writeJSON(w, map[string]string{"result": "failed"}) // what the real endpoint always says
	}
}
