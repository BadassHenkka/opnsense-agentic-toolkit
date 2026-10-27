// Package buildinfo reports the version a binary was built from.
package buildinfo

import "runtime/debug"

// Version returns set when the build stamped it with -ldflags "-X main.version=..." (task
// build does). Otherwise it returns the module version Go records in the binary: the tag or
// pseudo-version for `go install .../cmd/mcp-opnsense@<ref>`, and since Go 1.24 also for
// `go build` in a git checkout. It returns "dev" when neither is known.
func Version(set string) string {
	module := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		module = bi.Main.Version
	}
	return version(set, module)
}

func version(set, module string) string {
	switch {
	case set != "" && set != "dev":
		return set
	case module != "" && module != "(devel)":
		return module
	}
	return "dev"
}
