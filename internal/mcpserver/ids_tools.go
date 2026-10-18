package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

type idsRulesetView struct {
	Filename    string `json:"filename"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type idsRulesetListOut struct {
	Items []idsRulesetView `json:"items"`
	Total int              `json:"total"`
}

// idsTools adds the ruleset listing to the generated ids toolset.
func idsTools(c *opnsense.Client) []tool {
	return []tool{{toolset: genIDSToolset, readOnly: true, register: func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{Name: "ids_ruleset_list",
			Description: "List the downloadable IDS rule files and whether each is enabled (Services → Intrusion Detection → Download).",
			Annotations: &mcp.ToolAnnotations{Title: "List IDS rulesets", ReadOnlyHint: true},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, idsRulesetListOut, error) {
			rs, err := c.IDS.Rulesets(ctx)
			if err != nil {
				return nil, idsRulesetListOut{}, err
			}
			out := idsRulesetListOut{Items: []idsRulesetView{}, Total: len(rs)}
			for _, r := range rs {
				out.Items = append(out.Items, idsRulesetView{Filename: r.Filename, Description: r.Description, Enabled: bool(r.Enabled)})
			}
			return nil, out, nil
		})
	}}}
}
