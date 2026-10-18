package provider

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// TestExampleAttributes keeps examples/terraform/main.tf in step with the schemas: every
// resource type must exist and every top-level attribute must be in its schema. It is a light
// parser (top-level `name =` lines at two spaces), not HCL, which is enough for the example.
func TestExampleAttributes(t *testing.T) {
	src, err := os.ReadFile("../../examples/terraform/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	schemas := map[string]map[string]bool{}
	for _, f := range (&opnsenseProvider{}).Resources(ctx) {
		r := f()
		var md resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "opnsense"}, &md)
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		attrs := map[string]bool{}
		for name := range sr.Schema.Attributes {
			attrs[name] = true
		}
		for name := range sr.Schema.Blocks {
			attrs[name] = true
		}
		schemas[md.TypeName] = attrs
	}
	meta := map[string]bool{"depends_on": true, "count": true, "for_each": true, "provider": true, "lifecycle": true}
	block := regexp.MustCompile(`^resource "([a-z0-9_]+)" "([a-z0-9_]+)" \{`)
	attr := regexp.MustCompile(`^  ([a-z0-9_]+)\s*=`)
	var typ, name string
	for i, line := range strings.Split(string(src), "\n") {
		if m := block.FindStringSubmatch(line); m != nil {
			typ, name = m[1], m[2]
			if schemas[typ] == nil {
				t.Errorf("line %d: unknown resource type %s", i+1, typ)
			}
			continue
		}
		if strings.HasPrefix(line, "}") {
			typ = ""
			continue
		}
		if m := attr.FindStringSubmatch(line); m != nil && typ != "" && schemas[typ] != nil && !meta[m[1]] && !schemas[typ][m[1]] {
			t.Errorf("line %d: %s.%s has no attribute %q", i+1, typ, name, m[1])
		}
	}
}

// TestDocsResourceNames checks that every opnsense_* resource the README and the skill
// mention exists (brace lists such as opnsense_trust_{ca,cert} are expanded; a trailing *
// matches a prefix).
func TestDocsResourceNames(t *testing.T) {
	ctx := context.Background()
	p := &opnsenseProvider{}
	known := map[string]bool{}
	for _, f := range p.Resources(ctx) {
		var md resource.MetadataResponse
		f().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "opnsense"}, &md)
		known[md.TypeName] = true
	}
	for _, f := range p.Actions(ctx) {
		var md action.MetadataResponse
		f().Metadata(ctx, action.MetadataRequest{ProviderTypeName: "opnsense"}, &md)
		known[md.TypeName] = true
	}
	tok := regexp.MustCompile("`(opnsense_[a-z0-9_{},*]+)`")
	for _, doc := range []string{"../../README.md", "../../.claude/skills/opnsense-iac/SKILL.md"} {
		src, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range tok.FindAllStringSubmatch(string(src), -1) {
			for _, name := range expandBraces(m[1]) {
				if !knownName(known, name) {
					t.Errorf("%s mentions %s, which the provider does not have", doc, name)
				}
			}
		}
	}
}

func knownName(known map[string]bool, name string) bool {
	if prefix, ok := strings.CutSuffix(name, "*"); ok {
		for k := range known {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
		return false
	}
	return known[name]
}

// expandBraces expands a{b,c}d into abd and acd, recursively.
func expandBraces(s string) []string {
	i := strings.Index(s, "{")
	j := strings.Index(s, "}")
	if i < 0 || j < i {
		return []string{s}
	}
	var out []string
	for _, alt := range strings.Split(s[i+1:j], ",") {
		out = append(out, expandBraces(s[:i]+alt+s[j+1:])...)
	}
	return out
}
