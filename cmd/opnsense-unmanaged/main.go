// Command opnsense-unmanaged lists live OPNsense objects that are not in an OpenTofu or
// Terraform state. A plan only compares the resources it manages, so a rule someone added in
// the web UI never shows up there.
//
//	tofu show -json | opnsense-unmanaged
//	opnsense-unmanaged -import state.json >> imports.tf
//
// It checks every opnsense_* resource type in the state, plus the types given with -types.
// It reads only the type, address and id of each resource, never other attribute values, and
// makes only read calls to OPNsense. Built-in and automatic objects (the bogons alias,
// interface network aliases, the anti-lockout rule, automatic NAT rules) are left out.
//
// The connection settings come from the same OPNSENSE_* environment variables as
// mcp-opnsense.
//
// Exit status: 0 when every live object is in the state, 1 when some are not, 2 on errors.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"github.com/smulis/opnsense-agentic-toolkit/internal/buildinfo"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/unmanaged"
)

// version is set at build time with -ldflags "-X main.version=..."; main falls back to the
// module version (buildinfo.Version).
var version = "dev"

func main() {
	version = buildinfo.Version(version)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("opnsense-unmanaged", flag.ContinueOnError)
	fs.SetOutput(stderr)
	types := fs.String("types", "", "comma-separated resource types to check as well, e.g. opnsense_firewall_rule")
	imports := fs.Bool("import", false, "print import blocks instead of one line per object")
	listTypes := fs.Bool("list-types", false, "print the resource types it can check and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: tofu show -json | opnsense-unmanaged [flags] [state.json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *showVersion:
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	case *listTypes:
		_, _ = fmt.Fprintln(stdout, strings.Join(unmanaged.Types(), "\n"))
		return 0
	case fs.NArg() > 1:
		fs.Usage()
		return 2
	}

	in := stdin
	if fs.NArg() == 1 && fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "opnsense-unmanaged:", err)
			return 2
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	st, err := unmanaged.ReadState(in)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "opnsense-unmanaged:", err)
		return 2
	}

	client, err := opnsense.NewClient(opnsense.ConfigFromEnv())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "opnsense-unmanaged:", err)
		return 2
	}
	client.SetUserAgent("opnsense-unmanaged/" + version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var extra []string
	for _, t := range strings.Split(*types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			extra = append(extra, t)
		}
	}
	rep := unmanaged.Find(ctx, client, st, extra)
	return report(rep, st, *imports, stdout, stderr)
}

func report(rep unmanaged.Report, st *unmanaged.State, imports bool, stdout, stderr io.Writer) int {
	if len(rep.Checked) == 0 && len(rep.Errors) == 0 {
		_, _ = fmt.Fprintln(stderr, "opnsense-unmanaged: no opnsense_* resources in the state and no -types; nothing to check")
	}
	for _, t := range rep.Unchecked {
		_, _ = fmt.Fprintf(stderr, "opnsense-unmanaged: not checked: %s has no list call\n", t)
	}
	labels := map[string]bool{}
	for a := range st.Addresses {
		labels[a] = true
	}
	for _, o := range rep.Missing {
		if imports {
			printImport(stdout, o, labels)
		} else {
			_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\n", o.Type, clean(o.ID), clean(o.Name))
		}
	}
	for _, err := range rep.Errors {
		_, _ = fmt.Fprintln(stderr, "opnsense-unmanaged:", err)
	}
	switch {
	case len(rep.Errors) > 0:
		return 2
	case len(rep.Missing) > 0:
		return 1
	}
	return 0
}

// clean makes text from the firewall safe to print: names and descriptions are free text that
// anyone with web UI access sets, so control characters are replaced.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}

var (
	safeID   = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	nonIdent = regexp.MustCompile(`[^a-z0-9]+`)
)

// printImport writes an import block with a resource name derived from the object's name.
func printImport(w io.Writer, o unmanaged.Object, used map[string]bool) {
	if !safeID.MatchString(o.ID) {
		// Every id OPNsense hands out matches; anything else stays out of generated code.
		_, _ = fmt.Fprintf(w, "# %s: skipped, unexpected id %q\n\n", o.Type, clean(o.ID))
		return
	}
	short := strings.TrimPrefix(o.Type, "opnsense_")
	label := strings.Trim(nonIdent.ReplaceAllString(strings.ToLower(o.Name), "_"), "_")
	if label == "" {
		label = short + "_" + nonIdent.ReplaceAllString(strings.ToLower(o.ID), "_")
		label = label[:min(len(label), len(short)+9)]
	}
	if label[0] >= '0' && label[0] <= '9' {
		label = short + "_" + label
	}
	base := label
	for n := 2; used[o.Type+"."+label]; n++ {
		label = fmt.Sprintf("%s_%d", base, n)
	}
	used[o.Type+"."+label] = true
	if o.Name != "" {
		_, _ = fmt.Fprintf(w, "# %s\n", clean(o.Name))
	}
	_, _ = fmt.Fprintf(w, "import {\n  to = %s.%s\n  id = %q\n}\n\n", o.Type, label, o.ID)
}
