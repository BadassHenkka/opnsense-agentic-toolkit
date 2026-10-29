package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// ListTools returns the tools a server built with opts offers, as a client lists them.
// Registering a tool makes no API call, so it needs no firewall.
func ListTools(ctx context.Context, opts Options) ([]*mcp.Tool, error) {
	c, err := opnsense.NewClient(opnsense.Config{URL: "https://opnsense.invalid", APIKey: "list", APISecret: "list"})
	if err != nil {
		return nil, err
	}
	srv, err := New(c, opts)
	if err != nil {
		return nil, err
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "list"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cs.Close() }()
	var tools []*mcp.Tool
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}
	return tools, nil
}
