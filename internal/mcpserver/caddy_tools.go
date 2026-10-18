package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const caddyToolset = "caddy"

const caddyStagedNote = "Change saved to the configuration but not active. Call caddy_apply to reload Caddy."

type caddyStatusOut struct {
	Service        string `json:"service" jsonschema:"running or stopped"`
	Enabled        bool   `json:"enabled"`
	HTTPPort       *int64 `json:"http_port,omitempty"`
	HTTPSPort      *int64 `json:"https_port,omitempty"`
	ACMEEmail      string `json:"acme_email,omitempty"`
	AutoHTTPS      string `json:"auto_https,omitempty"`
	DNSProvider    string `json:"dns_provider,omitempty"`
	DNSAPIKeySet   bool   `json:"dns_api_key_set" jsonschema:"the key itself is never returned"`
	LogLevel       string `json:"log_level,omitempty"`
	Domains        int    `json:"domains"`
	Handlers       int    `json:"handlers"`
	InstallPackage string `json:"install_package,omitempty"`
}

type caddySettingsIn struct {
	Enabled     *bool   `json:"enabled,omitempty"`
	HTTPPort    *int64  `json:"http_port,omitempty" jsonschema:"0 resets to the default (80)"`
	HTTPSPort   *int64  `json:"https_port,omitempty" jsonschema:"0 resets to the default (443)"`
	ACMEEmail   *string `json:"acme_email,omitempty"`
	AutoHTTPS   *string `json:"auto_https,omitempty" jsonschema:"empty (on), off, disable_redirects, disable_certs or ignore_loaded_certs"`
	DNSProvider *string `json:"dns_provider,omitempty" jsonschema:"DNS-01 provider, e.g. cloudflare; needed for wildcard domains"`
	DNSAPIKey   *string `json:"dns_api_key,omitempty"`
	LogLevel    *string `json:"log_level,omitempty" jsonschema:"empty (INFO), DEBUG, WARN, ERROR, PANIC or FATAL"`
}

type caddyHandlerView struct {
	UUID                  string   `json:"uuid"`
	DomainUUID            string   `json:"domain_uuid"`
	SubdomainUUID         string   `json:"subdomain_uuid,omitempty"`
	Path                  string   `json:"path,omitempty"`
	StripPath             bool     `json:"strip_path"`
	Directive             string   `json:"directive"`
	Upstreams             []string `json:"upstreams"`
	UpstreamPort          *int64   `json:"upstream_port,omitempty"`
	UpstreamPath          string   `json:"upstream_path,omitempty"`
	UpstreamScheme        string   `json:"upstream_scheme"`
	TLSInsecureSkipVerify bool     `json:"tls_insecure_skip_verify"`
	AccessListUUID        string   `json:"access_list_uuid,omitempty"`
	Description           string   `json:"description,omitempty"`
	Enabled               bool     `json:"enabled"`
}

func caddyHandlerViewOf(id string, h *opnsense.CaddyHandler) caddyHandlerView {
	return caddyHandlerView{
		UUID: id, DomainUUID: string(h.Domain), SubdomainUUID: string(h.Subdomain), Path: h.Path,
		StripPath: h.HandleType == "handle_path", Directive: string(h.Directive), Upstreams: nonNil([]string(h.Upstreams)),
		UpstreamPort: intPtr(h.UpstreamPort), UpstreamPath: h.UpstreamPath,
		UpstreamScheme: opnsense.CaddySchemeName(h.UpstreamScheme), TLSInsecureSkipVerify: bool(h.TLSInsecureSkipVerify),
		AccessListUUID: string(h.AccessList), Description: h.Description, Enabled: bool(h.Enabled),
	}
}

type caddyExposeIn struct {
	Hostname           string `json:"hostname" jsonschema:"public name, e.g. app.example.com"`
	Upstream           string `json:"upstream" jsonschema:"IP or hostname of the service on the LAN, e.g. 192.168.1.20"`
	Port               int64  `json:"port" jsonschema:"service port, e.g. 8080"`
	Scheme             string `json:"scheme,omitempty" jsonschema:"http (default), https or h2c — how Caddy talks to the service"`
	Path               string `json:"path,omitempty" jsonschema:"only requests below this path, e.g. /api/*; empty for all"`
	StripPath          bool   `json:"strip_path,omitempty" jsonschema:"remove the matched path prefix before proxying"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" jsonschema:"accept a self-signed certificate from an https service"`
	AccessList         string `json:"access_list,omitempty" jsonschema:"name of a Caddy access list to restrict clients"`
	Description        string `json:"description,omitempty"`
}

type caddyExposeOut struct {
	DomainUUID    string   `json:"domain_uuid"`
	SubdomainUUID string   `json:"subdomain_uuid,omitempty"`
	HandlerUUID   string   `json:"handler_uuid"`
	Created       []string `json:"created"`
	Staged        bool     `json:"staged"`
	Note          string   `json:"note"`
}

type caddyHandlerUpdateIn struct {
	NameRef
	Upstreams          []string `json:"upstreams,omitempty"`
	Port               *int64   `json:"port,omitempty" jsonschema:"0 clears the port"`
	Scheme             *string  `json:"scheme,omitempty" jsonschema:"http, https or h2c"`
	Path               *string  `json:"path,omitempty"`
	StripPath          *bool    `json:"strip_path,omitempty"`
	InsecureSkipVerify *bool    `json:"insecure_skip_verify,omitempty"`
	AccessList         *string  `json:"access_list,omitempty" jsonschema:"access list name; empty removes it"`
	Enabled            *bool    `json:"enabled,omitempty"`
	Description        *string  `json:"description,omitempty"`
}

type caddyAccessListCreateIn struct {
	Name         string   `json:"name"`
	ClientIPs    []string `json:"client_ips" jsonschema:"IP addresses or networks, e.g. 192.168.1.0/24"`
	Invert       bool     `json:"invert,omitempty" jsonschema:"deny the listed IPs instead of allowing only them"`
	ResponseCode int64    `json:"response_code,omitempty" jsonschema:"HTTP status for refused clients, e.g. 403; 0 closes the connection"`
	Description  string   `json:"description,omitempty"`
}

type caddyfileOut struct {
	Caddyfile string `json:"caddyfile"`
}

func optInt(v int64) opnsense.Int {
	if v == 0 {
		return opnsense.Int{}
	}
	return opnsense.IntOf(v)
}

func caddyTools(c *opnsense.Client) []tool {
	cd := c.Caddy
	accessListID := func(ctx context.Context, name string) (opnsense.Option, error) {
		if name == "" {
			return "", nil
		}
		id, err := resolveNamed(ctx, cd.AccessLists, NameRef{Name: name}, "Caddy access list")
		return opnsense.Option(id), err
	}

	// expose finds or creates the domain (or the subdomain under a matching wildcard) and adds
	// a handler. Items it created are removed again if a later step fails.
	expose := func(ctx context.Context, in caddyExposeIn) (caddyExposeOut, error) {
		var out caddyExposeOut
		host := strings.ToLower(strings.TrimSpace(in.Hostname))
		if host == "" || strings.HasPrefix(host, "*") || in.Upstream == "" {
			return out, errors.New("give hostname (not a wildcard) and upstream")
		}
		scheme, err := opnsense.CaddySchemeValue(cmpOr(in.Scheme, "http"))
		if err != nil {
			return out, err
		}
		acl, err := accessListID(ctx, in.AccessList)
		if err != nil {
			return out, err
		}
		var undo []func()
		rollback := func() {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}

		switch id, err := cd.FindDomain(ctx, host); {
		case err == nil:
			out.DomainUUID = id
		case !errors.Is(err, opnsense.ErrNotFound):
			return out, err
		default:
			wild, werr := cd.WildcardFor(ctx, host)
			switch {
			case werr == nil:
				out.DomainUUID = wild
				sub, serr := opnsense.ResolveByName(ctx, cd.Subdomains, host)
				if errors.Is(serr, opnsense.ErrNotFound) {
					sub, serr = cd.Subdomains.Add(ctx, opnsense.CaddySubdomain{Enabled: true, Domain: opnsense.Option(wild),
						Subdomain: host, Description: in.Description})
					if serr == nil {
						out.Created = append(out.Created, "subdomain "+host)
						undo = append(undo, func() { _ = cd.Subdomains.Delete(context.WithoutCancel(ctx), sub) })
					}
				}
				if serr != nil {
					return out, serr
				}
				out.SubdomainUUID = sub
			case errors.Is(werr, opnsense.ErrNotFound):
				id, err := cd.Domains.Add(ctx, opnsense.CaddyDomain{Enabled: true, Domain: host,
					DisableTLS: opnsense.CaddyDomainHTTPS, Description: in.Description})
				if err != nil {
					return out, err
				}
				out.DomainUUID = id
				out.Created = append(out.Created, "domain "+host)
				undo = append(undo, func() { _ = cd.Domains.Delete(context.WithoutCancel(ctx), id) })
			default:
				return out, werr
			}
		}

		// One handler per domain/subdomain and path.
		res, err := cd.Handlers.Search(ctx, "")
		if err != nil {
			rollback()
			return out, err
		}
		for _, r := range res.Rows {
			h, err := cd.Handlers.Get(ctx, string(r.UUID))
			if err != nil {
				continue
			}
			if string(h.Domain) == out.DomainUUID && string(h.Subdomain) == out.SubdomainUUID && h.Path == in.Path {
				rollback()
				return out, fmt.Errorf("%s%s already has a handler (uuid %s); change it with caddy_handler_update", host, in.Path, r.UUID)
			}
		}

		handleType := "handle"
		if in.StripPath {
			handleType = "handle_path"
		}
		hid, err := cd.Handlers.Add(ctx, opnsense.CaddyHandler{
			Enabled: true, Domain: opnsense.Option(out.DomainUUID), Subdomain: opnsense.Option(out.SubdomainUUID),
			HandleType: opnsense.Option(handleType), Path: in.Path, AccessList: acl, Directive: "reverse_proxy",
			Upstreams: opnsense.CSVList{in.Upstream}, UpstreamPort: optInt(in.Port), UpstreamScheme: scheme,
			TLSInsecureSkipVerify: opnsense.Bool(in.InsecureSkipVerify), Description: cmpOr(in.Description, host+in.Path),
		})
		if err != nil {
			rollback()
			return out, err
		}
		out.HandlerUUID = hid
		out.Created = append(out.Created, "handler "+host+in.Path)
		out.Staged, out.Note = true, caddyStagedNote+" The hostname must resolve to this firewall, and "+
			"Caddy must be enabled (caddy_settings_update) with the web GUI moved off ports 80/443."
		return out, nil
	}

	return []tool{
		{toolset: caddyToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_status",
				Description: "Caddy reverse proxy status and general settings, with the number of domains and handlers.",
				Annotations: &mcp.ToolAnnotations{Title: "Caddy status", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, caddyStatusOut, error) {
				g, err := cd.General.Get(ctx)
				var apiErr *opnsense.APIError
				if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
					return nil, caddyStatusOut{Service: "not installed", InstallPackage: "os-caddy"}, nil
				}
				if err != nil {
					return nil, caddyStatusOut{}, err
				}
				st, err := cd.Status(ctx)
				if err != nil {
					return nil, caddyStatusOut{}, err
				}
				out := caddyStatusOut{Service: st, Enabled: bool(g.Enabled), HTTPPort: intPtr(g.HTTPPort),
					HTTPSPort: intPtr(g.HTTPSPort), ACMEEmail: g.TLSEmail, AutoHTTPS: string(g.TLSAutoHTTPS),
					DNSProvider: string(g.TLSDNSProvider), DNSAPIKeySet: g.TLSDNSAPIKey != "", LogLevel: string(g.LogLevel)}
				if d, err := cd.Domains.Search(ctx, ""); err == nil {
					out.Domains = d.Total
				}
				if h, err := cd.Handlers.Search(ctx, ""); err == nil {
					out.Handlers = h.Total
				}
				return nil, out, nil
			})
		}},
		{toolset: caddyToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_caddyfile_get",
				Description: "The generated Caddyfile: what Caddy actually runs after the last caddy_apply.",
				Annotations: &mcp.ToolAnnotations{Title: "Get Caddyfile", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, caddyfileOut, error) {
				f, err := cd.Caddyfile(ctx)
				return nil, caddyfileOut{Caddyfile: f}, err
			})
		}},
		listTool(caddyToolset, "caddy_domain_list", "List Caddy domains",
			"List Caddy reverse proxy domains (sites), including wildcard domains such as *.example.com.", cd.Domains),
		listTool(caddyToolset, "caddy_subdomain_list", "List Caddy subdomains",
			"List subdomains served under wildcard domains. The reverse column is the parent domain.", cd.Subdomains),
		listTool(caddyToolset, "caddy_handler_list", "List Caddy handlers",
			"List handlers: which domain/subdomain and path go to which upstreams (ToDomain, ToPort).", cd.Handlers),
		listTool(caddyToolset, "caddy_access_list_list", "List Caddy access lists",
			"List access lists (client IP allow/deny lists).", cd.AccessLists),
		{toolset: caddyToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_handler_get",
				Description: "Get a handler by UUID or description, with its upstreams and TLS settings.",
				Annotations: &mcp.ToolAnnotations{Title: "Get Caddy handler", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, caddyHandlerView, error) {
				id, err := resolveNamed(ctx, cd.Handlers, in, "Caddy handler")
				if err != nil {
					return nil, caddyHandlerView{}, err
				}
				h, err := cd.Handlers.Get(ctx, id)
				if err != nil {
					return nil, caddyHandlerView{}, notFoundAs(err, "Caddy handler", id)
				}
				return nil, caddyHandlerViewOf(id, h), nil
			})
		}},
		{toolset: caddyToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_settings_update",
				Description: "Change Caddy's general settings; omitted fields stay as they are. Before enabling, make sure " +
					"the OPNsense web GUI no longer listens on 80/443 (System → Settings → Administration), and allow " +
					"80/443 on WAN with firewall rules if the sites are public.",
				Annotations: &mcp.ToolAnnotations{Title: "Update Caddy settings", DestructiveHint: ptr(false), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in caddySettingsIn) (*mcp.CallToolResult, stagedOut, error) {
				g, err := cd.General.Get(ctx)
				if err != nil {
					return nil, stagedOut{}, err
				}
				setAs(&g.Enabled, in.Enabled, func(b bool) opnsense.Bool { return opnsense.Bool(b) })
				setAs(&g.HTTPPort, in.HTTPPort, optInt)
				setAs(&g.HTTPSPort, in.HTTPSPort, optInt)
				set(&g.TLSEmail, in.ACMEEmail)
				setAs(&g.TLSAutoHTTPS, in.AutoHTTPS, func(s string) opnsense.Option { return opnsense.Option(s) })
				setAs(&g.TLSDNSProvider, in.DNSProvider, func(s string) opnsense.Option { return opnsense.Option(s) })
				set(&g.TLSDNSAPIKey, in.DNSAPIKey)
				setAs(&g.LogLevel, in.LogLevel, func(s string) opnsense.Option { return opnsense.Option(s) })
				if err := cd.General.Set(ctx, *g); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{Staged: true, Note: caddyStagedNote}, nil
			})
		}},
		{toolset: caddyToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_expose",
				Description: "Expose a LAN service at a hostname through Caddy, with an automatic certificate. Reuses an " +
					"existing domain, or a subdomain under a matching wildcard domain (*.example.com), otherwise creates " +
					"the domain; then adds a handler to the upstream. Call caddy_apply afterwards.",
				Annotations: &mcp.ToolAnnotations{Title: "Expose service via Caddy", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in caddyExposeIn) (*mcp.CallToolResult, caddyExposeOut, error) {
				out, err := expose(ctx, in)
				return nil, out, err
			})
		}},
		{toolset: caddyToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_handler_update",
				Description: "Change a handler (by UUID or description): upstreams, port, scheme, path, access list, enabled.",
				Annotations: &mcp.ToolAnnotations{Title: "Update Caddy handler", DestructiveHint: ptr(false), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in caddyHandlerUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, cd.Handlers, in.NameRef, "Caddy handler")
				if err != nil {
					return nil, stagedOut{}, err
				}
				h, err := cd.Handlers.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "Caddy handler", id)
				}
				if len(in.Upstreams) > 0 {
					h.Upstreams = in.Upstreams
				}
				setAs(&h.UpstreamPort, in.Port, optInt)
				if in.Scheme != nil {
					if h.UpstreamScheme, err = opnsense.CaddySchemeValue(*in.Scheme); err != nil {
						return nil, stagedOut{}, err
					}
				}
				set(&h.Path, in.Path)
				if in.StripPath != nil {
					h.HandleType = map[bool]opnsense.Option{true: "handle_path", false: "handle"}[*in.StripPath]
				}
				setAs(&h.TLSInsecureSkipVerify, in.InsecureSkipVerify, func(b bool) opnsense.Bool { return opnsense.Bool(b) })
				if in.AccessList != nil {
					if h.AccessList, err = accessListID(ctx, *in.AccessList); err != nil {
						return nil, stagedOut{}, err
					}
				}
				setAs(&h.Enabled, in.Enabled, func(b bool) opnsense.Bool { return opnsense.Bool(b) })
				set(&h.Description, in.Description)
				if err := cd.Handlers.Set(ctx, id, *h); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: caddyStagedNote}, nil
			})
		}},
		{toolset: caddyToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_access_list_create",
				Description: "Create an access list that allows only the given client IPs (or, inverted, blocks them). " +
					"Attach it with caddy_expose or caddy_handler_update.",
				Annotations: &mcp.ToolAnnotations{Title: "Create Caddy access list", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in caddyAccessListCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := cd.AccessLists.Add(ctx, opnsense.CaddyAccessList{Name: in.Name, ClientIPs: in.ClientIPs,
					Invert: opnsense.Bool(in.Invert), ResponseCode: optInt(in.ResponseCode), RequestMatcher: "client_ip",
					Description: in.Description})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: caddyStagedNote}, nil
			})
		}},
		deleteTool(caddyToolset, "caddy_handler_delete", "Delete Caddy handler", "Caddy handler",
			" The name is the handler's description.", caddyStagedNote, cd.Handlers),
		deleteTool(caddyToolset, "caddy_subdomain_delete", "Delete Caddy subdomain", "Caddy subdomain",
			" Delete its handlers first.", caddyStagedNote, cd.Subdomains),
		deleteTool(caddyToolset, "caddy_domain_delete", "Delete Caddy domain", "Caddy domain",
			" Delete its handlers and subdomains first; OPNsense refuses while they reference it.", caddyStagedNote, cd.Domains),
		deleteTool(caddyToolset, "caddy_access_list_delete", "Delete Caddy access list", "Caddy access list",
			" Detach it from domains and handlers first.", caddyStagedNote, cd.AccessLists),
		{toolset: caddyToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "caddy_apply",
				Description: "Regenerate the Caddyfile and reload Caddy. Sites become reachable (and request certificates) " +
					"or stop being served. Confirm with the user before calling.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply Caddy changes", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, applyOut, error) {
				if err := cd.Apply(ctx); err != nil {
					return nil, applyOut{}, err
				}
				return nil, applyOut{Applied: true}, nil
			})
		}},
	}
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
