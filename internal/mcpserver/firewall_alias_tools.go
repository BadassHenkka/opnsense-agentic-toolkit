package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const aliasToolset = "firewall_alias"

// AliasView is how an alias is shown to the model.
type AliasView struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	Content     []string `json:"content"`
	Description string   `json:"description,omitempty"`
	Proto       []string `json:"proto,omitempty"`
	Categories  []string `json:"categories,omitempty" jsonschema:"category UUIDs"`
	UpdateFreq  string   `json:"updatefreq,omitempty" jsonschema:"refresh interval in days for url/urltable aliases"`
}

func toView(uuid string, a *opnsense.Alias) AliasView {
	return AliasView{
		UUID: uuid, Name: a.Name, Type: string(a.Type), Enabled: bool(a.Enabled),
		Content: nonNil(a.Content), Description: a.Description, Proto: a.Proto,
		Categories: a.Categories, UpdateFreq: a.UpdateFreq,
	}
}

// AliasRef identifies an alias by UUID or by name.
type AliasRef struct {
	UUID string `json:"uuid,omitempty" jsonschema:"alias UUID; give this or name"`
	Name string `json:"name,omitempty" jsonschema:"alias name; give this or uuid"`
}

func resolve(ctx context.Context, c *opnsense.Client, ref AliasRef) (string, error) {
	switch {
	case ref.UUID != "":
		return ref.UUID, nil
	case ref.Name != "":
		id, err := c.Firewall.AliasUUIDByName(ctx, ref.Name)
		if errors.Is(err, opnsense.ErrNotFound) {
			return "", fmt.Errorf("no alias named %q", ref.Name)
		}
		return id, err
	default:
		return "", errors.New("give either uuid or name")
	}
}

type aliasListIn struct {
	Search string `json:"search,omitempty" jsonschema:"substring to filter by; empty lists all aliases"`
}

type aliasListOut struct {
	Aliases []opnsense.AliasRow `json:"aliases"`
	Total   int                 `json:"total"`
}

type aliasCreateIn struct {
	Name        string   `json:"name" jsonschema:"alias name: letters, digits and underscores, max 32 characters"`
	Type        string   `json:"type" jsonschema:"alias type"`
	Content     []string `json:"content,omitempty" jsonschema:"entries, e.g. IPs, networks, ports, URLs or nested alias names"`
	Description string   `json:"description,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty" jsonschema:"defaults to true"`
	Proto       []string `json:"proto,omitempty" jsonschema:"IPv4 and/or IPv6, for geoip and asn aliases"`
	Categories  []string `json:"categories,omitempty" jsonschema:"category UUIDs"`
	UpdateFreq  string   `json:"updatefreq,omitempty" jsonschema:"refresh interval in days for url/urltable aliases"`
}

type aliasUpdateIn struct {
	AliasRef
	NewName     *string   `json:"new_name,omitempty" jsonschema:"rename the alias"`
	Type        *string   `json:"type,omitempty"`
	Content     *[]string `json:"content,omitempty" jsonschema:"replaces the whole content list"`
	Description *string   `json:"description,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
	Proto       *[]string `json:"proto,omitempty"`
	Categories  *[]string `json:"categories,omitempty"`
	UpdateFreq  *string   `json:"updatefreq,omitempty"`
}

type stagedOut struct {
	UUID   string `json:"uuid,omitempty"`
	Staged bool   `json:"staged"`
	Note   string `json:"note"`
}

const stagedNote = "Change saved to the configuration but not active. Call firewall_alias_apply to activate."

type applyOut struct {
	Applied bool `json:"applied"`
}

func aliasTools(c *opnsense.Client) []tool {
	return []tool{
		{toolset: aliasToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "firewall_alias_list",
				Description: "List firewall aliases, optionally filtered by a search phrase.",
				Annotations: &mcp.ToolAnnotations{Title: "List firewall aliases", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in aliasListIn) (*mcp.CallToolResult, aliasListOut, error) {
				res, err := c.Firewall.Aliases.Search(ctx, in.Search)
				if err != nil {
					return nil, aliasListOut{}, err
				}
				rows := res.Rows
				if rows == nil {
					rows = []opnsense.AliasRow{}
				}
				return nil, aliasListOut{Aliases: rows, Total: res.Total}, nil
			})
		}},

		{toolset: aliasToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "firewall_alias_get",
				Description: "Get one firewall alias with its full content, by UUID or name.",
				Annotations: &mcp.ToolAnnotations{Title: "Get firewall alias", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in AliasRef) (*mcp.CallToolResult, AliasView, error) {
				id, err := resolve(ctx, c, in)
				if err != nil {
					return nil, AliasView{}, err
				}
				a, err := c.Firewall.Aliases.Get(ctx, id)
				if err != nil {
					return nil, AliasView{}, notFound(err, id)
				}
				return nil, toView(id, a), nil
			})
		}},

		{toolset: aliasToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "firewall_alias_create",
				Description: "Stage a new firewall alias. It is not active until firewall_alias_apply runs. " +
					"Types: " + strings.Join(opnsense.AliasTypes, ", ") + ".",
				InputSchema: withEnum[aliasCreateIn]("type", opnsense.AliasTypes),
				Annotations: &mcp.ToolAnnotations{Title: "Create firewall alias", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in aliasCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				if !slices.Contains(opnsense.AliasTypes, in.Type) {
					return nil, stagedOut{}, fmt.Errorf("unknown alias type %q", in.Type)
				}
				a := opnsense.Alias{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled),
					Name:    in.Name, Type: opnsense.Option(in.Type), Content: in.Content,
					Description: in.Description, Proto: in.Proto, Categories: in.Categories,
					UpdateFreq: in.UpdateFreq,
				}
				id, err := c.Firewall.Aliases.Add(ctx, a)
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: stagedNote}, nil
			})
		}},

		{toolset: aliasToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "firewall_alias_update",
				Description: "Stage changes to an existing firewall alias, by UUID or name. Only the fields given " +
					"are changed; content replaces the whole list. Not active until firewall_alias_apply runs.",
				InputSchema: withEnum[aliasUpdateIn]("type", opnsense.AliasTypes),
				Annotations: &mcp.ToolAnnotations{Title: "Update firewall alias", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in aliasUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolve(ctx, c, in.AliasRef)
				if err != nil {
					return nil, stagedOut{}, err
				}
				a, err := c.Firewall.Aliases.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFound(err, id)
				}
				if in.Type != nil && !slices.Contains(opnsense.AliasTypes, *in.Type) {
					return nil, stagedOut{}, fmt.Errorf("unknown alias type %q", *in.Type)
				}
				set(&a.Name, in.NewName)
				setAs(&a.Type, in.Type, func(v string) opnsense.Option { return opnsense.Option(v) })
				setAs(&a.Content, in.Content, func(v []string) opnsense.LineList { return v })
				set(&a.Description, in.Description)
				setAs(&a.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				setAs(&a.Proto, in.Proto, func(v []string) opnsense.CSVList { return v })
				setAs(&a.Categories, in.Categories, func(v []string) opnsense.CSVList { return v })
				set(&a.UpdateFreq, in.UpdateFreq)
				if err := c.Firewall.Aliases.Set(ctx, id, *a); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: stagedNote}, nil
			})
		}},

		{toolset: aliasToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "firewall_alias_delete",
				Description: "Stage deletion of a firewall alias, by UUID or name. Fails while a rule still uses it. " +
					"Not active until firewall_alias_apply runs.",
				Annotations: &mcp.ToolAnnotations{Title: "Delete firewall alias", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in AliasRef) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolve(ctx, c, in)
				if err != nil {
					return nil, stagedOut{}, err
				}
				if err := c.Firewall.Aliases.Delete(ctx, id); err != nil {
					return nil, stagedOut{}, notFound(err, id)
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: stagedNote}, nil
			})
		}},

		{toolset: aliasToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name: "firewall_alias_apply",
				Description: "Activate all staged firewall alias changes (reloads the alias tables). " +
					"Confirm with the user before calling.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply firewall alias changes", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, applyOut, error) {
				if err := c.Firewall.Aliases.Apply(ctx); err != nil {
					return nil, applyOut{}, err
				}
				return nil, applyOut{Applied: true}, nil
			})
		}},
	}
}

func notFound(err error, id string) error { return notFoundAs(err, "alias", id) }
