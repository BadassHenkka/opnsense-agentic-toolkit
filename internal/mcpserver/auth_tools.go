package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

type apiKeyView struct {
	Username string `json:"username"`
	Key      string `json:"key"`
}

type apiKeyListOut struct {
	Items []apiKeyView `json:"items"`
	Total int          `json:"total"`
}

// authTools adds the API key listing to the generated auth toolset. Secrets are stored hashed
// and never returned.
func authTools(c *opnsense.Client) []tool {
	return []tool{{toolset: genAuthToolset, readOnly: true, register: func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{Name: "auth_api_key_list",
			Description: "List API keys and the user each belongs to (System → Access → Users). Secrets are never shown.",
			Annotations: &mcp.ToolAnnotations{Title: "List API keys", ReadOnlyHint: true},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, apiKeyListOut, error) {
			keys, err := c.Auth.APIKeys(ctx)
			if err != nil {
				return nil, apiKeyListOut{}, err
			}
			out := apiKeyListOut{Items: []apiKeyView{}, Total: len(keys)}
			for _, k := range keys {
				out.Items = append(out.Items, apiKeyView{Username: k.Username, Key: k.Key})
			}
			return nil, out, nil
		})
	}}}
}
