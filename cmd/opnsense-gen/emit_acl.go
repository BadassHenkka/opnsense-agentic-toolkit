package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// aclEntry is one privilege of an ACL.xml file: the element name is its key.
type aclEntry struct {
	XMLName  xml.Name
	Name     string   `xml:"name"`
	Patterns []string `xml:"patterns>pattern"`
}

// loadACLs reads every ACL.xml under modelDir. OPNsense loads the module directories in
// alphabetical order and a later entry with the same key replaces an earlier one; core and
// plugin modules share one directory on the firewall, so they are sorted together.
func loadACLs(modelDir string) ([]aclEntry, map[string]string, error) {
	var files []string
	err := filepath.WalkDir(modelDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "ACL.xml" && filepath.Base(filepath.Dir(p)) == "ACL" {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	module := func(p string) string { return filepath.Base(filepath.Dir(filepath.Dir(p))) }
	sort.Slice(files, func(i, j int) bool { return module(files[i]) < module(files[j]) })
	byKey := map[string]aclEntry{}
	source := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		var doc struct {
			Entries []aclEntry `xml:",any"`
		}
		if err := xml.Unmarshal(b, &doc); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		rel, _ := filepath.Rel(modelDir, f)
		for _, e := range doc.Entries {
			if e.Name == "" {
				continue // OPNsense skips entries without a name
			}
			byKey[e.XMLName.Local] = e
			source[e.XMLName.Local] = filepath.ToSlash(rel)
		}
	}
	var out []aclEntry
	for _, e := range byKey {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].XMLName.Local < out[j].XMLName.Local })
	return out, source, nil
}

// emitACL writes the privileges that grant API paths, from the pinned ACL.xml files. Web UI
// patterns are left out: an API key cannot open the web UI.
func emitACL(entries []aclEntry, source map[string]string) string {
	b := newW()
	b.p("// acl lists every privilege with API patterns, from the ACL.xml files in gen/models.")
	b.p("var acl = []Privilege{")
	for _, e := range entries {
		var api []string
		for _, p := range e.Patterns {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "api/") || p == "*" {
				api = append(api, p)
			}
		}
		if len(api) == 0 {
			continue
		}
		b.p("\t{Key: %q, Name: %q, Source: %q, Patterns: []string{%s}},", e.XMLName.Local, strings.TrimSpace(e.Name), source[e.XMLName.Local], quoteList(api))
	}
	b.p("}")
	return b.file("privileges", "gen/models/**/ACL/ACL.xml")
}
