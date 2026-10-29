// Command mcp-opnsense is a local MCP server (stdio) for an OPNsense firewall.
//
// `mcp-opnsense privileges [-read-only] [-toolsets ...]` prints the OPNsense privileges the
// selected tools need, for setting up a least-privilege API user.
//
// Configuration comes from the environment:
//
//	OPNSENSE_URL         https://opnsense.lan
//	OPNSENSE_API_KEY     API key of a dedicated, least-privilege user
//	OPNSENSE_API_SECRET  API secret
//	OPNSENSE_CA_FILE     optional PEM bundle for a self-signed certificate
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/buildinfo"
	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
)

// version is set at build time with -ldflags "-X main.version=..."; main falls back to the
// module version (buildinfo.Version).
var version = "dev"

func main() {
	version = buildinfo.Version(version)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-opnsense:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "privileges" {
		return runPrivileges(os.Args[2:])
	}
	readOnly := flag.Bool("read-only", envBool("OPNSENSE_MCP_READ_ONLY"), "register only tools that do not change OPNsense")
	toolsets := flag.String("toolsets", envOr("OPNSENSE_MCP_TOOLSETS", "all"),
		"comma-separated toolsets to enable ("+strings.Join(mcpserver.Toolsets(), ", ")+", all)")
	showVersion := flag.Bool("version", false, "print version and exit")
	check := flag.Bool("check", false, "test the configuration and connection, print a report and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	if *check {
		return runCheck()
	}

	// stdout carries the MCP protocol, so logs must go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	client, err := opnsense.NewClient(opnsense.ConfigFromEnv())
	if err != nil {
		return err
	}
	client.SetUserAgent("mcp-opnsense/" + version)

	srv, err := mcpserver.New(client, mcpserver.Options{
		Version:  version,
		ReadOnly: *readOnly,
		Toolsets: strings.Split(*toolsets, ","),
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting", "version", version, "read_only", *readOnly, "toolsets", *toolsets)
	return srv.Run(ctx, &mcp.StdioTransport{})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

// runCheck prints a setup report. It is the first thing to run after configuring credentials.
func runCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	failed := false
	for _, c := range opnsense.Diagnose(ctx, opnsense.ConfigFromEnv()) {
		tag := map[opnsense.CheckStatus]string{opnsense.CheckOK: "ok  ", opnsense.CheckWarn: "warn", opnsense.CheckFail: "FAIL"}[c.Status]
		fmt.Printf("[%s] %-13s %s\n", tag, c.Name, c.Detail)
		if c.Hint != "" && c.Status != opnsense.CheckOK {
			fmt.Printf("       -> %s\n", c.Hint)
		}
		failed = failed || c.Status == opnsense.CheckFail
	}
	if failed {
		return errors.New("setup check failed")
	}
	fmt.Println("\nSetup looks good. Register the server with your MCP client (see README).")
	return nil
}

// runPrivileges prints the privileges the tools selected by the flags need.
func runPrivileges(args []string) error {
	fs := flag.NewFlagSet("mcp-opnsense privileges", flag.ExitOnError)
	readOnly := fs.Bool("read-only", envBool("OPNSENSE_MCP_READ_ONLY"), "only the tools that do not change OPNsense")
	toolsets := fs.String("toolsets", envOr("OPNSENSE_MCP_TOOLSETS", "all"), "comma-separated toolsets ("+strings.Join(mcpserver.Toolsets(), ", ")+", all)")
	verbose := fs.Bool("v", false, "also list the endpoints each privilege is needed for")
	_ = fs.Parse(args)

	tools, err := mcpserver.ListTools(context.Background(), mcpserver.Options{ReadOnly: *readOnly, Toolsets: strings.Split(*toolsets, ",")})
	if err != nil {
		return err
	}
	var endpoints []string
	for _, t := range tools {
		endpoints = append(endpoints, privileges.ToolEndpoints(t.Name)...)
	}
	fmt.Printf("Privileges for %d tools (toolsets %s, read-only %v):\n\n", len(tools), *toolsets, *readOnly)
	return privileges.Write(os.Stdout, privileges.For(endpoints), *verbose)
}
