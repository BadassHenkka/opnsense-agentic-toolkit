package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const backupToolset = "backup"

type backupView struct {
	ID          string `json:"id"`
	TimeISO     string `json:"time"`
	Description string `json:"description"`
	Username    string `json:"user"`
	Bytes       int64  `json:"bytes"`
}

type backupListOut struct {
	Items []backupView `json:"items"`
	Total int          `json:"total"`
}

type backupDiffIn struct {
	Newer string `json:"newer" jsonschema:"backup id of the newer config, e.g. config-1700000200.1.xml (from backup_list)"`
	Older string `json:"older" jsonschema:"backup id of the older config to compare against"`
}

type backupDiffOut struct {
	Lines   []string `json:"lines"`
	Changed bool     `json:"changed"`
}

type snapshotView struct {
	Name       string `json:"name"`
	Active     string `json:"active"`
	Mountpoint string `json:"mountpoint"`
	Created    string `json:"created"`
	Size       string `json:"size"`
}

type snapshotListOut struct {
	Supported bool           `json:"supported"`
	Items     []snapshotView `json:"items"`
}

// backupTools reads config revisions and ZFS snapshots. Reverting or downloading a backup and
// creating snapshots are not offered: the files hold every secret, and changes belong in Terraform.
func backupTools(c *opnsense.Client) []tool {
	return []tool{
		{toolset: backupToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "backup_list",
				Description: "List the saved config.xml revisions, newest first, with the change description and the user or API call that made it (System → Configuration → Backups).",
				Annotations: &mcp.ToolAnnotations{Title: "List config backups", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, backupListOut, error) {
				items, err := c.Backup.List(ctx)
				if err != nil {
					return nil, backupListOut{}, err
				}
				out := backupListOut{Items: []backupView{}, Total: len(items)}
				for _, b := range items {
					out.Items = append(out.Items, backupView{ID: b.ID, TimeISO: b.TimeISO, Description: b.Description, Username: b.Username, Bytes: b.Filesize.Value})
				}
				return nil, out, nil
			})
		}},
		{toolset: backupToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "backup_diff_get",
				Description: "Unified diff between two config backups, e.g. to see exactly what a change did. Use ids from backup_list. Values of credential elements (keys, passwords, tokens) are shown as (set, hidden).",
				Annotations: &mcp.ToolAnnotations{Title: "Diff config backups", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in backupDiffIn) (*mcp.CallToolResult, backupDiffOut, error) {
				lines, err := c.Backup.Diff(ctx, in.Newer, in.Older)
				if err != nil {
					return nil, backupDiffOut{}, err
				}
				if lines == nil {
					lines = []string{}
				}
				lines = redactDiff(lines)
				return nil, backupDiffOut{Lines: lines, Changed: len(lines) > 0}, nil
			})
		}},
		{toolset: backupToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "snapshot_list",
				Description: "List ZFS boot environment snapshots (System → Snapshots). `supported` is false when the firewall does not run on ZFS.",
				Annotations: &mcp.ToolAnnotations{Title: "List snapshots", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, snapshotListOut, error) {
				ok, err := c.Backup.SnapshotsSupported(ctx)
				if err != nil {
					return nil, snapshotListOut{}, err
				}
				out := snapshotListOut{Supported: ok, Items: []snapshotView{}}
				if !ok {
					return nil, out, nil
				}
				snaps, err := c.Backup.Snapshots(ctx)
				if err != nil {
					return nil, snapshotListOut{}, err
				}
				for _, sn := range snaps {
					out.Items = append(out.Items, snapshotView{Name: sn.Name, Active: sn.Active, Mountpoint: sn.Mountpoint, Created: sn.Created, Size: sn.Size})
				}
				return nil, out, nil
			})
		}},
	}
}
