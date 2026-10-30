package main

import (
	"fmt"
	"sort"
	"strings"
)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fakeField renders an opnsensetest.Field literal.
func fakeField(f *Field) string {
	var parts []string
	switch {
	case f.Computed:
		parts = append(parts, "ReadOnly: true")
	case f.Kind == kOption || f.Kind == kOptions:
		parts = append(parts, "Kind: Option", "Choices: static("+quoteList(f.Choices)+")")
		if f.Kind == kOptions {
			parts = append(parts, fmt.Sprintf("Sep: %q", f.Sep))
		}
	case f.Kind == kRef || f.Kind == kRefs:
		// Dynamic lists: render the stored value(s) as the selected options.
		parts = append(parts, "Kind: List", fmt.Sprintf("Sep: %q", f.Sep))
	}
	if f.Sensitive {
		parts = append(parts, "Sensitive: true")
	}
	if f.UpdateOnly {
		parts = append(parts, "UpdateOnly: true")
	}
	if f.APIRequired && !f.Computed {
		parts = append(parts, "Required: true")
	}
	if f.XMLHasDefault {
		parts = append(parts, fmt.Sprintf("Default: %q", f.XMLDefault))
	}
	if f.HasRange {
		parts = append(parts, "HasRange: true", fmt.Sprintf("Min: %d, Max: %d", f.Min, f.Max))
	}
	if f.Mask != "" {
		parts = append(parts, fmt.Sprintf("Mask: %q", f.Mask))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func fakeFields(b *w, o *Object) {
	b.p("map[string]Field{")
	for _, f := range o.Fields {
		b.p("\t%q: %s,", f.XML, fakeField(f))
	}
	b.WriteString("}")
}

func emitFake(a *Area) string {
	b := newW()
	b.p("func registerGen%s(s *Server) {", a.Service)
	reconf := map[string]bool{}
	for _, o := range a.Items {
		b.p("\t{ // %s", o.Resource)
		b.p("\t\tc := s.add(&Collection{Base: %q, Suffix: %q, Key: %q,", o.Base, o.Suffix, o.Key)
		if len(o.Actions) > 0 {
			var parts []string
			for _, verb := range sortedKeys(o.Actions) {
				parts = append(parts, fmt.Sprintf("%q: %q", verb, o.Actions[verb]))
			}
			b.p("\t\t\tActions: map[string]string{%s},", strings.Join(parts, ", "))
		}
		b.WriteString("\t\t\tFields: ")
		fakeFields(b, o)
		b.p(",\n\t\t})")
		b.p("\t\tc.Validate = func(s *Server, self string, r Record) map[string]string {")
		b.p("\t\t\tv := checkFields(s, %q, c.Fields, r)", o.Key)
		for _, f := range o.Fields {
			if f.Unique {
				with := ""
				if len(f.UniqueWith) > 0 {
					with = ", " + quoteList(f.UniqueWith)
				}
				b.p("\t\t\tcheckUnique(c, self, r, v, %q, %q%s)", o.Key, f.XML, with)
			}
		}
		b.p("\t\t\treturn v")
		b.p("\t\t}")
		var computed []*Field
		for _, f := range o.Fields {
			if f.Computed && f.FakeValue != "" {
				computed = append(computed, f)
			}
		}
		if len(computed) == 1 {
			b.p("\t\tc.OnWrite = computedOnAdd(c, %q, %q)", computed[0].XML, computed[0].FakeValue)
		} else if len(computed) > 1 {
			b.p("\t\tc.OnWrite = func(s *Server, uuid string, posted Record) {")
			for _, f := range computed {
				b.p("\t\t\tcomputedOnAdd(c, %q, %q)(s, uuid, posted)", f.XML, f.FakeValue)
			}
			b.p("\t\t}")
		}
		b.p("\t}")
		if o.Reconfigure != "" {
			reconf[o.Reconfigure] = true
		}
	}
	for _, o := range a.Settings {
		b.p("\t// %s", o.Resource)
		_, _ = fmt.Fprintf(b, "\ts.addSettings(%q, %q, %q, %q, ", o.Get, o.Set, o.Path[0], settingsSection(o))
		fakeFields(b, o)
		b.p(", nil)")
		if o.Reconfigure != "" {
			reconf[o.Reconfigure] = true
		}
	}
	for _, p := range sortedKeys(reconf) {
		b.p("\ts.reconfigure[%q] = true", p)
	}
	b.p("}")
	return b.file("opnsensetest", a.Spec)
}

func emitFakeIndex(areas []*Area) string {
	b := newW()
	b.p("func registerGenerated(s *Server) {")
	for _, a := range areas {
		b.p("\tregisterGen%s(s)", a.Service)
	}
	b.p("}")
	return b.file("opnsensetest", "gen/specs")
}

// settingsSection is the second path element, or "" when the fields sit directly below the root.
func settingsSection(o *Object) string { return strings.Join(o.Path[1:], ".") }
