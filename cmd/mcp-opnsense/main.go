// Command mcp-opnsense is a local MCP server (stdio) for an OPNsense firewall.
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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-opnsense:", err)
		os.Exit(1)
	}
}

func run() error {
	readOnly := flag.Bool("read-only", envBool("OPNSENSE_MCP_READ_ONLY"), "register only tools that do not change OPNsense")
	toolsets := flag.String("toolsets", envOr("OPNSENSE_MCP_TOOLSETS", "all"),
		"comma-separated toolsets to enable ("+strings.Join(mcpserver.Toolsets(), ", ")+", all)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
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
