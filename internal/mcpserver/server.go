// Package mcpserver exposes the OPNsense client as MCP tools.
package mcpserver

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Options controls which tools the server registers.
type Options struct {
	// Version is reported to the client.
	Version string
	// ReadOnly registers only tools that do not change OPNsense. It wins over Toolsets.
	ReadOnly bool
	// Toolsets limits registration to these toolsets. Empty or "all" means every toolset.
	Toolsets []string
}

// tool is one MCP tool plus the metadata used to decide whether to register it.
type tool struct {
	toolset  string
	readOnly bool
	register func(*mcp.Server)
}

// toolsets returns every tool this server knows, grouped by toolset.
// Add a new resource by writing its <area>_tools.go file and appending it here.
func allTools(c *opnsense.Client) []tool {
	var tools []tool
	tools = append(tools, aliasTools(c)...)
	tools = append(tools, unboundTools(c)...)
	tools = append(tools, acmeTools(c)...)
	tools = append(tools, wireguardTools(c)...)
	tools = append(tools, routingTools(c)...)
	tools = append(tools, firmwareTools(c)...)
	tools = append(tools, generatedTools(c)...) // zz_gen_*.go, read-only
	return tools
}

// toolsetNames lists every toolset. TestToolsetNames checks it matches the tools.
var toolsetNames = append([]string{aliasToolset, unboundToolset, acmeToolset, wireguardToolset, routingToolset, firmwareToolset}, generatedToolsets...)

// Toolsets lists the toolset names, for --help output.
func Toolsets() []string {
	names := slices.Clone(toolsetNames)
	sort.Strings(names)
	return slices.Compact(names) // generated tools may join a hand-written toolset (unbound)
}

// New builds an MCP server with the tools selected by opts.
func New(c *opnsense.Client, opts Options) (*mcp.Server, error) {
	tools := allTools(c)

	want := map[string]bool{}
	for _, ts := range opts.Toolsets {
		if ts = strings.TrimSpace(ts); ts != "" {
			want[ts] = true
		}
	}
	all := len(want) == 0 || want["all"]
	if !all {
		known := Toolsets()
		for ts := range want {
			if !slices.Contains(known, ts) {
				return nil, fmt.Errorf("unknown toolset %q (known: %s)", ts, strings.Join(known, ", "))
			}
		}
	}

	version := opts.Version
	if version == "" {
		version = "dev"
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "opnsense", Version: version}, &mcp.ServerOptions{
		Instructions: instructions(opts.ReadOnly),
	})
	for _, t := range tools {
		if opts.ReadOnly && !t.readOnly {
			continue
		}
		if !all && !want[t.toolset] {
			continue
		}
		t.register(s)
	}
	return s, nil
}

func instructions(readOnly bool) string {
	const story = "Explore freely, but the desired state of the firewall lives in Terraform: " +
		"propose lasting changes as Terraform resources for the user to plan, review and apply. "
	if readOnly {
		return story + "This server is read-only, so use it to inspect the current state."
	}
	return story +
		"Create, update and delete tools exist only for short-lived trial changes that verify an idea; " +
		"they stage changes in the configuration and nothing takes effect until the matching *_apply tool runs. " +
		"Get the user's confirmation before applying, and undo every trial change afterwards " +
		"(check with backup_diff_get) so it does not collide with the Terraform-managed state."
}
