package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

type keaLeaseOut struct {
	Items []opnsense.KeaLease `json:"items"`
	Total int                 `json:"total"`
}

// keaTools adds the lease lists to the generated kea toolset.
func keaTools(c *opnsense.Client) []tool {
	lease := func(name, title, desc string, ipv6 bool) tool {
		return tool{toolset: genKeaToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: name, Description: desc,
				Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, keaLeaseOut, error) {
				rows, err := c.Kea.Leases(ctx, ipv6, in.Search)
				if err != nil {
					return nil, keaLeaseOut{}, err
				}
				if rows == nil {
					rows = []opnsense.KeaLease{}
				}
				return nil, keaLeaseOut{Items: rows, Total: len(rows)}, nil
			})
		}}
	}
	return []tool{
		lease("kea_lease4_list", "List Kea DHCPv4 leases", "List current Kea DHCPv4 leases (Services → Kea DHCP → Leases). Use it to find devices before adding a kea_dhcp4_reservation.", false),
		lease("kea_lease6_list", "List Kea DHCPv6 leases", "List current Kea DHCPv6 leases (Services → Kea DHCP → Leases).", true),
	}
}
