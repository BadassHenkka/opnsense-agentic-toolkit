// Command opnsense-gen generates client, fake, Terraform and MCP code for OPNsense API areas
// from gen/specs/*.json and the pinned model XML files in gen/models.
//
//	go run ./cmd/opnsense-gen            regenerate (run from the repository root)
//	go run ./cmd/opnsense-gen -check     fail if generated files are out of date
//	go run ./cmd/opnsense-gen -fetch     download the model XML the specs reference
//	go run ./cmd/opnsense-gen -verify    check the specs against the upstream API controllers
//
// Generated files are named zz_gen_*.go and must not be edited by hand.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "only check that generated files are up to date")
	fetch := flag.Bool("fetch", false, "download model XML referenced by the specs (see gen/models/REFS)")
	verify := flag.Bool("verify", false, "check the specs against the PHP API controllers at the pinned refs (network)")
	flag.Parse()

	if *verify {
		problems, err := verifyUpstream(*root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "opnsense-gen:", err)
			os.Exit(1)
		}
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "opnsense-gen: verify:", p)
		}
		if len(problems) > 0 {
			os.Exit(1)
		}
		fmt.Println("opnsense-gen: every spec matches the upstream controllers")
		return
	}

	if *fetch {
		if err := fetchModels(*root); err != nil {
			fmt.Fprintln(os.Stderr, "opnsense-gen:", err)
			os.Exit(1)
		}
		return
	}
	files, err := generate(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opnsense-gen:", err)
		os.Exit(1)
	}
	stale, err := writeFiles(*root, files, *check)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opnsense-gen:", err)
		os.Exit(1)
	}
	if *check && len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "opnsense-gen: out of date: %s\nrun: task gen\n", strings.Join(stale, ", "))
		os.Exit(1)
	}
}

// generate returns every generated file, keyed by path relative to root.
func generate(root string) (map[string][]byte, error) {
	areas, err := loadSpecs(filepath.Join(root, "gen", "specs"), filepath.Join(root, "gen", "models"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, a := range areas {
		out["internal/opnsense/zz_gen_"+a.Name+".go"] = emitClient(a)
		out["internal/opnsense/opnsensetest/zz_gen_"+a.Name+".go"] = emitFake(a)
		out["internal/provider/zz_gen_"+a.Name+".go"] = emitProvider(a)
		out["internal/provider/zz_gen_"+a.Name+"_test.go"] = emitProviderTest(a)
		out["internal/mcpserver/zz_gen_"+a.Name+".go"] = emitMCP(a)
	}
	out["internal/opnsense/zz_gen_index.go"] = emitClientIndex(areas)
	out["internal/opnsense/opnsensetest/zz_gen_index.go"] = emitFakeIndex(areas)
	out["internal/provider/zz_gen_index.go"] = emitProviderIndex(areas)
	out["internal/mcpserver/zz_gen_index.go"] = emitMCPIndex(areas)
	out["internal/mcpserver/zz_gen_tools_test.go"] = emitMCPTest(areas)
	out["internal/provider/zz_gen_helpers_test.go"] = emitProviderTestHelpers()
	out["internal/unmanaged/zz_gen_listers.go"] = emitUnmanaged(areas)

	files := map[string][]byte{}
	for name, src := range out {
		b, err := format.Source([]byte(src))
		if err != nil {
			return nil, fmt.Errorf("%s: %w\n%s", name, err, numbered(src))
		}
		files[name] = b
	}
	return files, nil
}

// writeFiles writes changed files and removes stale zz_gen files. With check, it only
// reports what would change.
func writeFiles(root string, files map[string][]byte, check bool) ([]string, error) {
	var stale []string
	for name, b := range files {
		p := filepath.Join(root, name)
		old, err := os.ReadFile(p)
		if err == nil && bytes.Equal(old, b) {
			continue
		}
		stale = append(stale, name)
		if !check {
			if err := os.WriteFile(p, b, 0o644); err != nil {
				return nil, err
			}
		}
	}
	for _, dir := range []string{"internal/opnsense", "internal/opnsense/opnsensetest", "internal/provider", "internal/mcpserver", "internal/unmanaged"} {
		existing, _ := filepath.Glob(filepath.Join(root, dir, "zz_gen_*.go"))
		for _, p := range existing {
			rel, _ := filepath.Rel(root, p)
			if _, ok := files[filepath.ToSlash(rel)]; ok {
				continue
			}
			stale = append(stale, rel+" (removed)")
			if !check {
				if err := os.Remove(p); err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Strings(stale)
	return stale, nil
}

func numbered(src string) string {
	var b strings.Builder
	for i, l := range strings.Split(src, "\n") {
		fmt.Fprintf(&b, "%4d %s\n", i+1, l)
	}
	return b.String()
}

// w accumulates generated source.
type w struct {
	strings.Builder
	imports map[string]string // path -> alias ("" for none)
}

func newW() *w { return &w{imports: map[string]string{}} }

func (b *w) p(format string, args ...any) {
	_, _ = fmt.Fprintf(b, format, args...)
	b.WriteByte('\n')
}

func (b *w) use(path string) { b.imports[path] = "" }

// file renders a complete Go file with header, package clause and imports.
func (b *w) file(pkg, spec string) string {
	var h strings.Builder
	fmt.Fprintf(&h, "// Code generated by opnsense-gen from %s; DO NOT EDIT.\n\n", spec)
	fmt.Fprintf(&h, "package %s\n\n", pkg)
	if len(b.imports) > 0 {
		// Three groups, as in the hand-written code: standard library, third party, this module.
		groups := make([][]string, 3)
		for p := range b.imports {
			switch {
			case strings.HasPrefix(p, modulePath+"/"):
				groups[2] = append(groups[2], p)
			case strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
				groups[1] = append(groups[1], p)
			default:
				groups[0] = append(groups[0], p)
			}
		}
		h.WriteString("import (\n")
		first := true
		for _, g := range groups {
			if len(g) == 0 {
				continue
			}
			if !first {
				h.WriteString("\n")
			}
			first = false
			sort.Strings(g)
			for _, p := range g {
				fmt.Fprintf(&h, "\t%q\n", p)
			}
		}
		h.WriteString(")\n\n")
	}
	return h.String() + b.String()
}

func quoteList(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, ", ")
}
