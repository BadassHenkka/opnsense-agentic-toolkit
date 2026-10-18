package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

type dnsmasqLeaseOut struct {
	Items []opnsense.DnsmasqLease `json:"items"`
	Total int                     `json:"total"`
}

// dnsmasqTools adds the lease list to the generated dnsmasq toolset.
func dnsmasqTools(c *opnsense.Client) []tool {
	return []tool{{toolset: genDnsmasqToolset, readOnly: true, register: func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{Name: "dnsmasq_lease_list",
			Description: "List current Dnsmasq DHCP leases (Services → Dnsmasq DNS & DHCP → Leases): address, host name, MAC, interface and whether a static host reserves it. Use it to find devices before adding a dnsmasq_host.",
			Annotations: &mcp.ToolAnnotations{Title: "List DHCP leases", ReadOnlyHint: true},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, dnsmasqLeaseOut, error) {
			rows, err := c.Dnsmasq.Leases(ctx, in.Search)
			if err != nil {
				return nil, dnsmasqLeaseOut{}, err
			}
			if rows == nil {
				rows = []opnsense.DnsmasqLease{}
			}
			return nil, dnsmasqLeaseOut{Items: rows, Total: len(rows)}, nil
		})
	}}}
}
