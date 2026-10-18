package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const unboundToolset = "unbound"

const unboundStagedNote = "Change saved to the configuration but not active. Call unbound_apply to activate."

// HostOverrideView is how a host override is shown to the model.
type HostOverrideView struct {
	UUID        string `json:"uuid"`
	FQDN        string `json:"fqdn"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	Server      string `json:"server,omitempty"`
	MXPriority  *int64 `json:"mx_priority,omitempty"`
	MX          string `json:"mx,omitempty"`
	TXTData     string `json:"txt_data,omitempty"`
	TTL         *int64 `json:"ttl,omitempty"`
	AddPTR      bool   `json:"add_ptr"`
	Description string `json:"description,omitempty"`
	// Aliases are the extra names that resolve like this override.
	Aliases []HostAliasView `json:"aliases"`
}

// HostAliasView is how a host alias is shown to the model.
type HostAliasView struct {
	UUID        string `json:"uuid"`
	HostUUID    string `json:"host_uuid,omitempty"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

func intPtr(i opnsense.Int) *int64 {
	if !i.Valid {
		return nil
	}
	return &i.Value
}

func toInt(p *int64) opnsense.Int {
	if p == nil {
		return opnsense.Int{}
	}
	return opnsense.IntOf(*p)
}

func hostOverrideView(id string, h *opnsense.HostOverride) HostOverrideView {
	return HostOverrideView{
		UUID: id, FQDN: h.FQDN(), Hostname: h.Hostname, Domain: h.Domain, Type: string(h.RR),
		Enabled: bool(h.Enabled), Server: h.Server, MXPriority: intPtr(h.MXPrio), MX: h.MX,
		TXTData: h.TXTData, TTL: intPtr(h.TTL), AddPTR: bool(h.AddPTR), Description: h.Description,
		Aliases: []HostAliasView{},
	}
}

func hostAliasRowView(r opnsense.HostAliasRow) HostAliasView {
	return HostAliasView{
		UUID: string(r.UUID), Hostname: string(r.Hostname), Domain: string(r.Domain),
		Enabled: r.Enabled == "1", Description: string(r.Description),
	}
}

// HostOverrideRef identifies a host override by UUID, or by name plus an optional type.
type HostOverrideRef struct {
	UUID string `json:"uuid,omitempty" jsonschema:"host override UUID; give this or name"`
	Name string `json:"name,omitempty" jsonschema:"fully qualified name, e.g. nas.home.lan; give this or uuid"`
	Type string `json:"type,omitempty" jsonschema:"record type, needed with name when the name has several records (e.g. A and AAAA)"`
}

func resolveHostOverride(ctx context.Context, c *opnsense.Client, ref HostOverrideRef) (string, error) {
	if ref.UUID != "" {
		return ref.UUID, nil
	}
	if ref.Name == "" {
		return "", errors.New("give either uuid or name")
	}
	rows, err := c.Unbound.FindHostOverrides(ctx, ref.Name, ref.Type)
	if err != nil {
		return "", err
	}
	switch len(rows) {
	case 0:
		if ref.Type != "" {
			return "", fmt.Errorf("no %s host override for %q", ref.Type, ref.Name)
		}
		return "", fmt.Errorf("no host override for %q", ref.Name)
	case 1:
		return string(rows[0].UUID), nil
	default:
		var types []string
		for _, r := range rows {
			types = append(types, fmt.Sprintf("%s (%s)", r.RR, r.UUID))
		}
		return "", fmt.Errorf("%q has several host overrides: %s; give type or uuid", ref.Name, strings.Join(types, ", "))
	}
}

// HostAliasRef identifies a host alias by UUID or name.
type HostAliasRef struct {
	UUID string `json:"uuid,omitempty" jsonschema:"host alias UUID; give this or name"`
	Name string `json:"name,omitempty" jsonschema:"fully qualified alias name; give this or uuid"`
}

func resolveHostAlias(ctx context.Context, c *opnsense.Client, ref HostAliasRef) (string, error) {
	if ref.UUID != "" {
		return ref.UUID, nil
	}
	if ref.Name == "" {
		return "", errors.New("give either uuid or name")
	}
	rows, err := c.Unbound.FindHostAliases(ctx, ref.Name)
	if err != nil {
		return "", err
	}
	switch len(rows) {
	case 0:
		return "", fmt.Errorf("no host alias named %q", ref.Name)
	case 1:
		return string(rows[0].UUID), nil
	default:
		return "", fmt.Errorf("%q matches %d host aliases; give uuid", ref.Name, len(rows))
	}
}

// checkRecord gives clear errors before OPNsense's own field validation does.
func checkRecord(h *opnsense.HostOverride) error {
	switch h.RR {
	case "A", "AAAA":
		if h.Server == "" {
			return fmt.Errorf("type %s needs server (the IP address)", h.RR)
		}
	case "MX":
		if h.MX == "" || !h.MXPrio.Valid {
			return errors.New("type MX needs mx and mx_priority")
		}
	case "TXT":
		if h.TXTData == "" {
			return errors.New("type TXT needs txt_data")
		}
	default:
		return fmt.Errorf("unknown record type %q (use %s)", h.RR, strings.Join(opnsense.HostOverrideTypes, ", "))
	}
	if h.Domain == "" {
		return errors.New("domain is required")
	}
	return nil
}

type hostOverrideListIn struct {
	Search string `json:"search,omitempty" jsonschema:"substring to filter by; empty lists all overrides"`
}

type hostOverrideListOut struct {
	Overrides []opnsense.HostOverrideRow `json:"overrides"`
	Total     int                        `json:"total"`
}

type hostOverrideCreateIn struct {
	Hostname    string `json:"hostname,omitempty" jsonschema:"host part, e.g. nas; empty for the domain itself, * for a wildcard"`
	Domain      string `json:"domain" jsonschema:"domain, e.g. home.lan"`
	Type        string `json:"type,omitempty" jsonschema:"record type; defaults to A"`
	Server      string `json:"server,omitempty" jsonschema:"IP address, required for A and AAAA"`
	MXPriority  *int64 `json:"mx_priority,omitempty" jsonschema:"required for MX"`
	MX          string `json:"mx,omitempty" jsonschema:"mail server host name, required for MX"`
	TXTData     string `json:"txt_data,omitempty" jsonschema:"required for TXT"`
	TTL         *int64 `json:"ttl,omitempty" jsonschema:"TTL in seconds; empty uses the Unbound default"`
	AddPTR      *bool  `json:"add_ptr,omitempty" jsonschema:"also create the reverse (PTR) record; defaults to true"`
	Description string `json:"description,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type hostOverrideUpdateIn struct {
	HostOverrideRef
	NewHostname *string `json:"new_hostname,omitempty"`
	NewDomain   *string `json:"new_domain,omitempty"`
	NewType     *string `json:"new_type,omitempty" jsonschema:"change the record type"`
	Server      *string `json:"server,omitempty"`
	MXPriority  *int64  `json:"mx_priority,omitempty"`
	MX          *string `json:"mx,omitempty"`
	TXTData     *string `json:"txt_data,omitempty"`
	TTL         *int64  `json:"ttl,omitempty" jsonschema:"use 0 or more; to clear, set clear_ttl"`
	ClearTTL    bool    `json:"clear_ttl,omitempty" jsonschema:"remove the TTL so the Unbound default applies"`
	AddPTR      *bool   `json:"add_ptr,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type hostAliasListIn struct {
	Search   string `json:"search,omitempty" jsonschema:"substring to filter by"`
	HostUUID string `json:"host_uuid,omitempty" jsonschema:"only aliases of this host override"`
}

type hostAliasListOut struct {
	Aliases []opnsense.HostAliasRow `json:"aliases"`
	Total   int                     `json:"total"`
}

type hostAliasCreateIn struct {
	Host        HostOverrideRef `json:"host" jsonschema:"the host override this alias points at"`
	Hostname    string          `json:"hostname,omitempty" jsonschema:"alias host part; give hostname, domain or both"`
	Domain      string          `json:"domain,omitempty" jsonschema:"alias domain; give hostname, domain or both"`
	Description string          `json:"description,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type hostAliasUpdateIn struct {
	HostAliasRef
	NewHost     *HostOverrideRef `json:"new_host,omitempty" jsonschema:"move the alias to another host override"`
	NewHostname *string          `json:"new_hostname,omitempty"`
	NewDomain   *string          `json:"new_domain,omitempty"`
	Description *string          `json:"description,omitempty"`
	Enabled     *bool            `json:"enabled,omitempty"`
}

func unboundTools(c *opnsense.Client) []tool {
	return []tool{
		{toolset: unboundToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "unbound_host_override_list",
				Description: "List Unbound DNS host overrides (Services → Unbound DNS → Overrides).",
				Annotations: &mcp.ToolAnnotations{Title: "List DNS host overrides", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostOverrideListIn) (*mcp.CallToolResult, hostOverrideListOut, error) {
				res, err := c.Unbound.HostOverrides.Search(ctx, in.Search)
				if err != nil {
					return nil, hostOverrideListOut{}, err
				}
				return nil, hostOverrideListOut{Overrides: nonNil(res.Rows), Total: res.Total}, nil
			})
		}},

		{toolset: unboundToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "unbound_host_override_get",
				Description: "Get one Unbound host override with its aliases, by UUID or by name (plus type if the name has several records).",
				Annotations: &mcp.ToolAnnotations{Title: "Get DNS host override", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in HostOverrideRef) (*mcp.CallToolResult, HostOverrideView, error) {
				id, err := resolveHostOverride(ctx, c, in)
				if err != nil {
					return nil, HostOverrideView{}, err
				}
				h, err := c.Unbound.HostOverrides.Get(ctx, id)
				if err != nil {
					return nil, HostOverrideView{}, notFoundAs(err, "host override", id)
				}
				v := hostOverrideView(id, h)
				rows, err := c.Unbound.HostAliasesOf(ctx, id)
				if err != nil {
					return nil, HostOverrideView{}, err
				}
				for _, r := range rows {
					a := hostAliasRowView(r)
					a.HostUUID = id
					v.Aliases = append(v.Aliases, a)
				}
				return nil, v, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "unbound_host_override_create",
				Description: "Stage a new Unbound host override (local DNS record). A/AAAA need server, MX needs mx and " +
					"mx_priority, TXT needs txt_data. Not active until unbound_apply runs.",
				InputSchema: withEnum[hostOverrideCreateIn]("type", opnsense.HostOverrideTypes),
				Annotations: &mcp.ToolAnnotations{Title: "Create DNS host override", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostOverrideCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				rr := in.Type
				if rr == "" {
					rr = "A"
				}
				h := opnsense.HostOverride{
					Enabled:  opnsense.Bool(in.Enabled == nil || *in.Enabled),
					Hostname: in.Hostname, Domain: in.Domain, RR: opnsense.Option(rr),
					Server: in.Server, MXPrio: toInt(in.MXPriority), MX: in.MX, TXTData: in.TXTData,
					TTL: toInt(in.TTL), AddPTR: opnsense.Bool(in.AddPTR == nil || *in.AddPTR),
					Description: in.Description,
				}
				if err := checkRecord(&h); err != nil {
					return nil, stagedOut{}, err
				}
				id, err := c.Unbound.HostOverrides.Add(ctx, h)
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: unboundStagedNote}, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "unbound_host_override_update",
				Description: "Stage changes to an Unbound host override, found by UUID or name. Only the fields given change. " +
					"Not active until unbound_apply runs.",
				InputSchema: withEnum[hostOverrideUpdateIn]("new_type", opnsense.HostOverrideTypes),
				Annotations: &mcp.ToolAnnotations{Title: "Update DNS host override", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostOverrideUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveHostOverride(ctx, c, in.HostOverrideRef)
				if err != nil {
					return nil, stagedOut{}, err
				}
				h, err := c.Unbound.HostOverrides.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "host override", id)
				}
				set(&h.Hostname, in.NewHostname)
				set(&h.Domain, in.NewDomain)
				setAs(&h.RR, in.NewType, func(v string) opnsense.Option { return opnsense.Option(v) })
				set(&h.Server, in.Server)
				setAs(&h.MXPrio, in.MXPriority, opnsense.IntOf)
				set(&h.MX, in.MX)
				set(&h.TXTData, in.TXTData)
				setAs(&h.TTL, in.TTL, opnsense.IntOf)
				if in.ClearTTL {
					h.TTL = opnsense.Int{}
				}
				setAs(&h.AddPTR, in.AddPTR, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				set(&h.Description, in.Description)
				setAs(&h.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				if err := checkRecord(h); err != nil {
					return nil, stagedOut{}, err
				}
				if err := c.Unbound.HostOverrides.Set(ctx, id, *h); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: unboundStagedNote}, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "unbound_host_override_delete",
				Description: "Stage deletion of an Unbound host override, found by UUID or name. " +
					"Its host aliases are deleted with it. Not active until unbound_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Delete DNS host override", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in HostOverrideRef) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveHostOverride(ctx, c, in)
				if err != nil {
					return nil, stagedOut{}, err
				}
				if err := c.Unbound.HostOverrides.Delete(ctx, id); err != nil {
					return nil, stagedOut{}, notFoundAs(err, "host override", id)
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: unboundStagedNote}, nil
			})
		}},

		{toolset: unboundToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "unbound_host_alias_list",
				Description: "List Unbound host aliases (extra names for a host override), optionally for one host override.",
				Annotations: &mcp.ToolAnnotations{Title: "List DNS host aliases", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostAliasListIn) (*mcp.CallToolResult, hostAliasListOut, error) {
				var filters map[string]any
				if in.HostUUID != "" {
					filters = map[string]any{"host": in.HostUUID}
				}
				res, err := c.Unbound.HostAliases.SearchWith(ctx, in.Search, filters)
				if err != nil {
					return nil, hostAliasListOut{}, err
				}
				return nil, hostAliasListOut{Aliases: nonNil(res.Rows), Total: res.Total}, nil
			})
		}},

		{toolset: unboundToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "unbound_host_alias_get",
				Description: "Get one Unbound host alias by UUID or by name, with the UUID of the host override it points to.",
				Annotations: &mcp.ToolAnnotations{Title: "Get DNS host alias", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in HostAliasRef) (*mcp.CallToolResult, HostAliasView, error) {
				id, err := resolveHostAlias(ctx, c, in)
				if err != nil {
					return nil, HostAliasView{}, err
				}
				a, err := c.Unbound.HostAliases.Get(ctx, id)
				if err != nil {
					return nil, HostAliasView{}, notFoundAs(err, "host alias", id)
				}
				return nil, HostAliasView{UUID: id, HostUUID: string(a.Host), Hostname: a.Hostname, Domain: a.Domain,
					Enabled: bool(a.Enabled), Description: a.Description}, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "unbound_host_alias_create",
				Description: "Stage a new Unbound host alias: an extra name that resolves like an existing host override. " +
					"Not active until unbound_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Create DNS host alias", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostAliasCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				hostID, err := resolveHostOverride(ctx, c, in.Host)
				if err != nil {
					return nil, stagedOut{}, fmt.Errorf("host: %w", err)
				}
				if in.Hostname == "" && in.Domain == "" {
					return nil, stagedOut{}, errors.New("give hostname, domain or both")
				}
				id, err := c.Unbound.HostAliases.Add(ctx, opnsense.HostAlias{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Host: opnsense.Option(hostID),
					Hostname: in.Hostname, Domain: in.Domain, Description: in.Description,
				})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: unboundStagedNote}, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "unbound_host_alias_update",
				Description: "Stage changes to an Unbound host alias, found by UUID or name. Not active until unbound_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Update DNS host alias", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostAliasUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveHostAlias(ctx, c, in.HostAliasRef)
				if err != nil {
					return nil, stagedOut{}, err
				}
				a, err := c.Unbound.HostAliases.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "host alias", id)
				}
				if in.NewHost != nil {
					hostID, err := resolveHostOverride(ctx, c, *in.NewHost)
					if err != nil {
						return nil, stagedOut{}, fmt.Errorf("new_host: %w", err)
					}
					a.Host = opnsense.Option(hostID)
				}
				set(&a.Hostname, in.NewHostname)
				set(&a.Domain, in.NewDomain)
				set(&a.Description, in.Description)
				setAs(&a.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				if a.Hostname == "" && a.Domain == "" {
					return nil, stagedOut{}, errors.New("an alias needs hostname, domain or both")
				}
				if err := c.Unbound.HostAliases.Set(ctx, id, *a); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: unboundStagedNote}, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "unbound_host_alias_delete",
				Description: "Stage deletion of an Unbound host alias, found by UUID or name. Not active until unbound_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Delete DNS host alias", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in HostAliasRef) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveHostAlias(ctx, c, in)
				if err != nil {
					return nil, stagedOut{}, err
				}
				if err := c.Unbound.HostAliases.Delete(ctx, id); err != nil {
					return nil, stagedOut{}, notFoundAs(err, "host alias", id)
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: unboundStagedNote}, nil
			})
		}},

		{toolset: unboundToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "unbound_apply",
				Description: "Activate all staged Unbound DNS override and alias changes (reloads Unbound). " +
					"Confirm with the user before calling.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply Unbound DNS changes", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, applyOut, error) {
				if err := c.Unbound.Apply(ctx); err != nil {
					return nil, applyOut{}, err
				}
				return nil, applyOut{Applied: true}, nil
			})
		}},
	}
}
