package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const firmwareToolset = "firmware"

// firmwareJobTimeout bounds one package job started from a tool call.
const firmwareJobTimeout = 15 * time.Minute

type firmwareStatusIn struct {
	Check bool `json:"check,omitempty" jsonschema:"ask the update mirror first (takes a few seconds); otherwise return the last result"`
}

type pluginListIn struct {
	Search        string `json:"search,omitempty" jsonschema:"substring of the name or description"`
	InstalledOnly bool   `json:"installed_only,omitempty"`
}

type pluginView struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Comment    string `json:"description"`
	Installed  bool   `json:"installed"`
	Repository string `json:"repository"`
	Tier       string `json:"tier" jsonschema:"1 core team … 3 community; 4 third-party/unknown"`
	ThirdParty bool   `json:"third_party"`
}

type pluginListOut struct {
	ProductVersion string       `json:"product_version"`
	Plugins        []pluginView `json:"plugins"`
}

type pluginInstallIn struct {
	Name            string `json:"name" jsonschema:"plugin package name, e.g. os-ddclient"`
	AllowThirdParty bool   `json:"allow_third_party,omitempty" jsonschema:"required for tier 4 packages from non-OPNsense repositories; only with the user's explicit consent"`
}

type pluginNameIn struct {
	Name string `json:"name"`
}

type jobOut struct {
	Done           bool   `json:"done"`
	RebootRequired bool   `json:"reboot_required"`
	LogTail        string `json:"log_tail"`
	Note           string `json:"note,omitempty"`
}

func pluginViewOf(p opnsense.Package) pluginView {
	return pluginView{Name: string(p.Name), Version: string(p.Version), Comment: string(p.Comment),
		Installed: p.IsInstalled(), Repository: string(p.Repository), Tier: string(p.Tier), ThirdParty: p.ThirdParty()}
}

func firmwareTools(c *opnsense.Client) []tool {
	fw := c.Firmware
	run := func(ctx context.Context, job func(context.Context) (*opnsense.JobResult, error)) (jobOut, error) {
		jobCtx, cancel := context.WithTimeout(ctx, firmwareJobTimeout)
		defer cancel()
		res, err := job(jobCtx)
		if err != nil {
			if errors.Is(err, opnsense.ErrFirmwareBusy) {
				return jobOut{}, errors.New("another package job is running on the firewall; try again when it finishes")
			}
			return jobOut{}, err
		}
		out := jobOut{Done: true, RebootRequired: res.Reboot, LogTail: opnsense.LastLines(res.Log, 6)}
		if res.Reboot {
			out.Note = "A reboot is required to finish. This server does not reboot; ask the user to reboot from " +
				"the web UI (Power → Reboot) at a convenient time."
		}
		return out, nil
	}

	return []tool{
		{toolset: firmwareToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firmware_status",
				Description: "Firmware update status: current and latest version, pending package updates, whether a " +
					"reboot would be needed, and any major upgrade on offer.",
				Annotations: &mcp.ToolAnnotations{Title: "Firmware status", ReadOnlyHint: true, OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in firmwareStatusIn) (*mcp.CallToolResult, *opnsense.FirmwareStatus, error) {
				st, err := fw.Status(ctx, in.Check)
				return nil, st, err
			})
		}},
		{toolset: firmwareToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firmware_plugin_list",
				Description: "List plugins available from the configured repositories and which are installed, with their " +
					"support tier. Tier 4 / third_party packages come from repositories the OPNsense team does not review.",
				Annotations: &mcp.ToolAnnotations{Title: "List plugins", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in pluginListIn) (*mcp.CallToolResult, pluginListOut, error) {
				info, err := fw.Info(ctx)
				if err != nil {
					return nil, pluginListOut{}, err
				}
				q := strings.ToLower(in.Search)
				out := pluginListOut{ProductVersion: string(info.ProductVersion), Plugins: []pluginView{}}
				for _, p := range info.Plugins {
					if in.InstalledOnly && !p.IsInstalled() {
						continue
					}
					if q != "" && !strings.Contains(strings.ToLower(string(p.Name)+" "+string(p.Comment)), q) {
						continue
					}
					out.Plugins = append(out.Plugins, pluginViewOf(p))
				}
				return nil, out, nil
			})
		}},
		{toolset: firmwareToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firmware_plugin_install",
				Description: "Install a plugin and wait for the package job (can take minutes). Confirm with the user " +
					"first. Third-party (tier 4) packages are refused unless allow_third_party is set, which needs the " +
					"user's explicit consent. Packages from repositories that are not configured cannot be installed; " +
					"adding a repository is a shell step on the firewall.",
				Annotations: &mcp.ToolAnnotations{Title: "Install plugin", DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in pluginInstallIn) (*mcp.CallToolResult, jobOut, error) {
				p, err := fw.Find(ctx, in.Name)
				if errors.Is(err, opnsense.ErrNotFound) {
					return nil, jobOut{}, fmt.Errorf("no configured repository provides %q; check the name with "+
						"firmware_plugin_list, or add the repository on the firewall first", in.Name)
				}
				if err != nil {
					return nil, jobOut{}, err
				}
				if p.IsInstalled() {
					return nil, jobOut{Done: true, Note: string(p.Name) + " " + string(p.Version) + " is already installed."}, nil
				}
				if p.ThirdParty() && !in.AllowThirdParty {
					return nil, jobOut{}, fmt.Errorf("%s comes from the third-party %q repository (tier 4, not reviewed by "+
						"OPNsense); ask the user, then retry with allow_third_party", in.Name, p.Repository)
				}
				out, err := run(ctx, func(ctx context.Context) (*opnsense.JobResult, error) { return fw.Install(ctx, in.Name) })
				if err == nil && out.Note == "" {
					out.Note = "Installed. The plugin's settings are under its own menu in the web UI."
				}
				return nil, out, err
			})
		}},
		{toolset: firmwareToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firmware_plugin_remove",
				Description: "Remove a plugin and wait for the package job. Its service stops; its configuration stays " +
					"in config.xml. Confirm with the user first.",
				Annotations: &mcp.ToolAnnotations{Title: "Remove plugin", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in pluginNameIn) (*mcp.CallToolResult, jobOut, error) {
				p, err := fw.Find(ctx, in.Name)
				if errors.Is(err, opnsense.ErrNotFound) || (err == nil && !p.IsInstalled()) {
					return nil, jobOut{Done: true, Note: in.Name + " is not installed."}, nil
				}
				if err != nil {
					return nil, jobOut{}, err
				}
				out, err := run(ctx, func(ctx context.Context) (*opnsense.JobResult, error) { return fw.Remove(ctx, in.Name) })
				return nil, out, err
			})
		}},
		{toolset: firmwareToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "firmware_update",
				Description: "Install pending minor updates (same major version) and wait for the job. Never reboots; " +
					"reports reboot_required. Major upgrades are not done here. Confirm with the user first: services " +
					"restart during the update.",
				Annotations: &mcp.ToolAnnotations{Title: "Update firmware", DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, jobOut, error) {
				out, err := run(ctx, fw.Update)
				return nil, out, err
			})
		}},
	}
}
