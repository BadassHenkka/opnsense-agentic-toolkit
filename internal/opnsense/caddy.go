package opnsense

import (
	"context"
	"fmt"
	"strings"
)

// Services → Caddy Web Server (plugin os-caddy). One model, Caddy.xml, mounted at
// //OPNsense/caddy, with a general section and several arrays:
//
//	caddy/general            get, set                           general settings (whole model on get)
//	caddy/reverse_proxy      {add,get,set,del,search}ReverseProxy  key reverse     domains
//	                         {…}Subdomain                          key subdomain   subdomains of a wildcard domain
//	                         {…}Handle                             key handle      handlers: where requests go
//	                         {…}AccessList                         key accesslist  client IP allow/deny lists
//	caddy/service            reconfigure, status                   reconfigure reloads Caddy (no restart)
//	caddy/diagnostics        caddyfile                             the generated Caddyfile
//
// A domain (e.g. app.example.com, or *.example.com) gets a certificate automatically. A
// handler sends a domain's (or subdomain's) requests, optionally only below a path, to one or
// more upstreams. Subdomains exist for wildcard domains, which need the DNS-01 challenge.
//
// The types, rows and CaddyService are generated (gen/specs/caddy.json); this file adds the
// scheme helpers, status, the Caddyfile and lookups.
//
// The controller uses "safe delete": deleting a domain that a handler or subdomain still
// references fails with a UserException. Basic auth users, headers and layer4 routes are generated too;
// layer4 OpenVPN static keys are not modelled.

// Caddy option values. OPNsense stores these as numbers.
const (
	CaddyDomainHTTPS = "0" // DisableTls: serve with TLS (the default)
	CaddyDomainHTTP  = "1" // DisableTls: plain HTTP only

	CaddyUpstreamHTTP  = "0" // HttpTls
	CaddyUpstreamHTTPS = "1"
	CaddyUpstreamH2C   = "2"
)

// caddySchemes maps HttpTls values to scheme names and back.
var caddySchemes = map[string]string{CaddyUpstreamHTTP: "http", CaddyUpstreamHTTPS: "https", CaddyUpstreamH2C: "h2c"}

// CaddyUpstreamSchemes lists the scheme names an upstream accepts.
var CaddyUpstreamSchemes = []string{"http", "https", "h2c"}

// CaddySchemeName returns http, https or h2c for an HttpTls value.
func CaddySchemeName(v Option) string {
	if n, ok := caddySchemes[string(v)]; ok {
		return n
	}
	return string(v)
}

// CaddySchemeValue returns the HttpTls value for a scheme name.
func CaddySchemeValue(name string) (Option, error) {
	for v, n := range caddySchemes {
		if strings.EqualFold(n, name) {
			return Option(v), nil
		}
	}
	return "", fmt.Errorf("opnsense: unknown upstream scheme %q (use http, https or h2c)", name)
}

const (
	caddyReconfigure = "caddy/service/reconfigure"
	caddyProxyBase   = "caddy/reverse_proxy"
)

// Apply regenerates the Caddyfile and reloads Caddy (or stops it when disabled).
func (s *CaddyService) Apply(ctx context.Context) error {
	return s.c.Reconfigure(ctx, caddyReconfigure)
}

// Status returns the service status, e.g. "running" or "stopped".
func (s *CaddyService) Status(ctx context.Context) (string, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := s.c.Get(ctx, "caddy/service/status", &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

// Caddyfile returns the generated Caddyfile, which shows what Caddy actually runs.
func (s *CaddyService) Caddyfile(ctx context.Context) (string, error) {
	var resp struct {
		Status  string `json:"status"`
		Content string `json:"content"`
		Message string `json:"message"`
	}
	if err := s.c.Get(ctx, "caddy/diagnostics/caddyfile", &resp); err != nil {
		return "", err
	}
	if resp.Status != "success" {
		return "", fmt.Errorf("opnsense: caddyfile: %s", resp.Message)
	}
	return resp.Content, nil
}

// FindDomain returns the uuid of the domain with this exact hostname on the default ports,
// or ErrNotFound.
func (s *CaddyService) FindDomain(ctx context.Context, host string) (string, error) {
	res, err := s.Domains.Search(ctx, host)
	if err != nil {
		return "", err
	}
	for _, r := range res.Rows {
		if strings.EqualFold(string(r.Domain), host) && r.Port == "" {
			return string(r.UUID), nil
		}
	}
	return "", ErrNotFound
}

// WildcardFor returns the uuid of a wildcard domain *.parent that covers host (one label
// deeper), or ErrNotFound. host itself must not be a wildcard.
func (s *CaddyService) WildcardFor(ctx context.Context, host string) (string, error) {
	_, parent, ok := strings.Cut(host, ".")
	if !ok || strings.HasPrefix(host, "*") {
		return "", ErrNotFound
	}
	return s.FindDomain(ctx, "*."+parent)
}
