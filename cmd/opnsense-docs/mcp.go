package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// toolDoc is one MCP tool as a client sees it.
type toolDoc struct {
	Name        string
	Toolset     string
	Title       string
	Description string
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	Params      []paramDoc
}

type paramDoc struct {
	Name        string
	Type        string
	Required    bool
	Description string
	Enum        []string
}

// connectTools starts a server with opts and returns the tools a client lists. Registering a
// tool makes no API call, so a client that points nowhere is enough.
func connectTools(ctx context.Context, opts mcpserver.Options) ([]*mcp.Tool, error) {
	c, err := opnsense.NewClient(opnsense.Config{URL: "https://opnsense.invalid", APIKey: "docs", APISecret: "docs"})
	if err != nil {
		return nil, err
	}
	srv, err := mcpserver.New(c, opts)
	if err != nil {
		return nil, err
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "opnsense-docs"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	var tools []*mcp.Tool
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}
	return tools, nil
}

// collectTools lists every tool with its toolset. The protocol does not say which toolset a
// tool belongs to, so each toolset is registered on its own.
func collectTools(ctx context.Context) ([]toolDoc, error) {
	var docs []toolDoc
	seen := map[string]bool{}
	for _, ts := range mcpserver.Toolsets() {
		tools, err := connectTools(ctx, mcpserver.Options{Toolsets: []string{ts}})
		if err != nil {
			return nil, err
		}
		for _, t := range tools {
			if seen[t.Name] {
				continue // a generated area that joins a hand-written toolset
			}
			seen[t.Name] = true
			d := toolDoc{Name: t.Name, Toolset: ts, Description: t.Description, ReadOnly: true}
			if a := t.Annotations; a != nil {
				d.Title, d.ReadOnly, d.Idempotent = a.Title, a.ReadOnlyHint, a.IdempotentHint
				d.Destructive = !a.ReadOnlyHint && (a.DestructiveHint == nil || *a.DestructiveHint)
			}
			d.Params = params(t.InputSchema)
			docs = append(docs, d)
		}
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].Name < docs[j].Name })
	return docs, nil
}

// params reads the properties of a tool's JSON input schema.
func params(schema any) []paramDoc {
	// The client delivers the schema as decoded JSON, but go through JSON anyway so the
	// shape does not depend on that.
	b, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	var s struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Type        any                 `json:"type"`
			Description string              `json:"description"`
			Enum        []any               `json:"enum"`
			Items       *struct{ Type any } `json:"items"`
		} `json:"properties"`
	}
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	req := map[string]bool{}
	for _, r := range s.Required {
		req[r] = true
	}
	var out []paramDoc
	for name, p := range s.Properties {
		pd := paramDoc{Name: name, Required: req[name], Description: p.Description, Type: jsonType(p.Type)}
		if p.Items != nil && pd.Type == "array" {
			pd.Type = "array of " + jsonType(p.Items.Type)
		}
		for _, e := range p.Enum {
			pd.Enum = append(pd.Enum, fmt.Sprint(e))
		}
		out = append(out, pd)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Required != out[j].Required {
			return out[i].Required
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// jsonType names a schema type; "type": ["null", "boolean"] means an optional boolean.
func jsonType(t any) string {
	switch t := t.(type) {
	case string:
		return t
	case []any:
		for _, x := range t {
			if s, _ := x.(string); s != "null" {
				return s
			}
		}
	}
	return "any"
}

func (d toolDoc) kind() string {
	switch {
	case d.ReadOnly:
		return "Read-only"
	case d.Destructive:
		return "Changes the configuration; can overwrite or delete"
	}
	return "Changes the configuration"
}

func exampleArgs(d toolDoc) string {
	args := map[string]any{}
	for _, p := range d.Params {
		if !p.Required {
			continue
		}
		switch {
		case len(p.Enum) > 0:
			args[p.Name] = p.Enum[0]
		case p.Type == "integer" || p.Type == "number":
			args[p.Name] = 1
		case p.Type == "boolean":
			args[p.Name] = true
		case strings.HasPrefix(p.Type, "array"):
			args[p.Name] = []string{"example"}
		case p.Name == "uuid":
			args[p.Name] = "0a1b2c3d-0000-0000-0000-000000000000"
		default:
			args[p.Name] = "example"
		}
	}
	b, _ := json.MarshalIndent(args, "", "  ")
	return string(b)
}

func toolMarkdown(d toolDoc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", d.Name, d.Description)
	fmt.Fprintf(&b, "Toolset: `%s`. %s.", d.Toolset, d.kind())
	if d.Idempotent {
		b.WriteString(" Safe to repeat.")
	}
	b.WriteString("\n\n")
	if !d.ReadOnly {
		b.WriteString("Not registered when the server runs with `--read-only`.\n\n")
	}
	b.WriteString("## Parameters\n\n")
	if len(d.Params) == 0 {
		b.WriteString("None.\n\n")
	}
	for _, p := range d.Params {
		req := "optional"
		if p.Required {
			req = "required"
		}
		fmt.Fprintf(&b, "- `%s` (%s, %s) %s", p.Name, p.Type, req, p.Description)
		if len(p.Enum) > 0 {
			if p.Description != "" && !strings.HasSuffix(p.Description, ".") {
				b.WriteString(".")
			}
			b.WriteString(" One of: `" + strings.Join(p.Enum, "`, `") + "`.")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Example call\n\n```json\n" + exampleArgs(d) + "\n```\n")
	return b.String()
}

func toolHTML(d toolDoc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<h1>%s</h1>\n<p>%s</p>\n", html.EscapeString(d.Name), htmlText(d.Description))
	fmt.Fprintf(&b, "<p class=\"meta\">Toolset: <a href=\"../toolsets/%s.html\"><code>%s</code></a>. %s.", d.Toolset, d.Toolset, d.kind())
	if d.Idempotent {
		b.WriteString(" Safe to repeat.")
	}
	b.WriteString("</p>\n")
	if !d.ReadOnly {
		b.WriteString("<p>Not registered when the server runs with <code>--read-only</code>.</p>\n")
	}
	b.WriteString("<h2>Parameters</h2>\n")
	if len(d.Params) == 0 {
		b.WriteString("<p>None.</p>\n")
	} else {
		b.WriteString("<dl>\n")
		for _, p := range d.Params {
			req := "optional"
			if p.Required {
				req = "required"
			}
			fmt.Fprintf(&b, "<dt id=\"%s\"><code>%s</code><span class=\"tag\">%s, %s</span></dt>\n<dd>%s", p.Name, p.Name, html.EscapeString(p.Type), req, htmlText(p.Description))
			if len(p.Enum) > 0 {
				b.WriteString("<br><span class=\"meta\">One of: <code>" + html.EscapeString(strings.Join(p.Enum, "</code>, <code>")) + "</code>.</span>")
			}
			b.WriteString("</dd>\n")
		}
		b.WriteString("</dl>\n")
	}
	b.WriteString("<h2>Example call</h2>\n<pre><code>" + html.EscapeString(exampleArgs(d)) + "</code></pre>\n")
	return b.String()
}

// writeMCP writes the MCP reference under out and returns the number of tool pages.
func writeMCP(out string) (int, error) {
	tools, err := collectTools(context.Background())
	if err != nil {
		return 0, err
	}
	for _, d := range []string{"tools", "toolsets"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return 0, err
		}
	}
	byToolset := map[string][]toolDoc{}
	var full, llms strings.Builder
	full.WriteString("# MCP tool reference\n\nTools of the `mcp-opnsense` server. Every tool below is registered unless the server runs with `--read-only` (read-only tools stay) or `--toolsets` leaves its toolset out.\n")
	llms.WriteString("# MCP tool reference\n\n")
	for _, d := range tools {
		byToolset[d.Toolset] = append(byToolset[d.Toolset], d)
		if err := os.WriteFile(filepath.Join(out, "tools", d.Name+".md"), []byte(toolMarkdown(d)), 0o644); err != nil {
			return 0, err
		}
		if err := os.WriteFile(filepath.Join(out, "tools", d.Name+".html"),
			[]byte(htmlPage(d.Name, toolHTML(d), "../../../", "MCP tools", "docs/mcp/index.html")), 0o644); err != nil {
			return 0, err
		}
		full.WriteString("\n\n---\n\n" + toolMarkdown(d))
	}

	names := make([]string, 0, len(byToolset))
	for ts := range byToolset {
		names = append(names, ts)
	}
	sort.Strings(names)

	var idx strings.Builder
	read, write := 0, 0
	for _, d := range tools {
		if d.ReadOnly {
			read++
		} else {
			write++
		}
	}
	fmt.Fprintf(&idx, "<h1 style=\"font-family:inherit\">MCP tool reference</h1>\n"+
		"<p>%d tools in %d toolsets, served by <code>mcp-opnsense</code>: %d read-only and %d that change the configuration. "+
		"Run the server with <code>--read-only</code> to register only the read-only ones, or with <code>--toolsets a,b</code> to register only some toolsets.</p>\n",
		len(tools), len(names), read, write)
	idx.WriteString("<h2>Toolsets</h2>\n<table>\n<tr><th>Toolset</th><th>Tools</th><th>Read-only</th></tr>\n")
	for _, ts := range names {
		ro := 0
		for _, d := range byToolset[ts] {
			if d.ReadOnly {
				ro++
			}
		}
		fmt.Fprintf(&idx, "<tr><td><a href=\"toolsets/%s.html\"><code>%s</code></a></td><td>%d</td><td>%d</td></tr>\n", ts, ts, len(byToolset[ts]), ro)

		var tb strings.Builder
		fmt.Fprintf(&tb, "<h1>%s</h1>\n<p>%d tools, %d of them read-only. Enable with <code>--toolsets %s</code>.</p>\n<table>\n", ts, len(byToolset[ts]), ro, ts)
		fmt.Fprintf(&llms, "## %s\n\n", ts)
		for _, d := range byToolset[ts] {
			fmt.Fprintf(&tb, "<tr><td><a href=\"../tools/%s.html\"><code>%s</code></a></td><td>%s</td></tr>\n", d.Name, d.Name, htmlText(firstSentence(d.Description)))
			fmt.Fprintf(&llms, "- [%s](https://smulis.github.io/opnsense-agentic-toolkit/docs/mcp/tools/%s.md): %s\n", d.Name, d.Name, firstSentence(d.Description))
		}
		tb.WriteString("</table>\n")
		llms.WriteString("\n")
		if err := os.WriteFile(filepath.Join(out, "toolsets", ts+".html"),
			[]byte(htmlPage(ts+" toolset", tb.String(), "../../../", "MCP tools", "docs/mcp/index.html")), 0o644); err != nil {
			return 0, err
		}
	}
	idx.WriteString("</table>\n")
	if err := os.WriteFile(filepath.Join(out, "index.html"),
		[]byte(htmlPage("MCP tool reference", idx.String(), "../../", "MCP tools", "docs/mcp/index.html")), 0o644); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(out, "llms-index.md"), []byte(llms.String()), 0o644); err != nil {
		return 0, err
	}
	return len(tools), os.WriteFile(filepath.Join(out, "reference.md"), []byte(full.String()), 0o644)
}
