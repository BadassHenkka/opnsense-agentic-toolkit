package main

import (
	"fmt"
	"strings"
)

const modulePath = "github.com/smulis/opnsense-agentic-toolkit"

// clientType is the Go type a field has in the shared client.
func clientType(f *Field) string {
	if f.Computed {
		if f.isList() {
			return "ReadOnlyList"
		}
		return "ReadOnly"
	}
	switch f.Kind {
	case kBool:
		return "Bool"
	case kInt:
		return "Int"
	case kOption, kRef:
		return "Option"
	case kOptions, kRefs:
		return "CSVList"
	case kList:
		if f.Sep == "\n" {
			return "LineList"
		}
		return "CSVList"
	default:
		return "string"
	}
}

func objectDoc(o *Object) string {
	what := "array " + o.Node
	if o.Settings {
		what = "section " + o.Node
	}
	return fmt.Sprintf("model %s, %s", o.Model, what)
}

func emitClient(a *Area) string {
	b := newW()
	for _, o := range append(append([]*Object{}, a.Items...), a.Settings...) {
		b.p("// %s: %s", o.Go, oneLine(o.Description))
		b.p("// (%s).", objectDoc(o))
		if len(o.Skipped) > 0 {
			b.p("// Not generated: %s.", strings.Join(o.Skipped, ", "))
		}
		b.p("type %s struct {", o.Go)
		seen := map[string]bool{}
		var containers []string
		for _, f := range o.Fields {
			if f.Container != "" {
				if !seen[f.Container] {
					seen[f.Container] = true
					containers = append(containers, f.Container)
					b.p("\t%s %s%s `json:%q`", f.ContainerGo, o.Go, f.ContainerGo, f.Container)
				}
				continue
			}
			tag := f.XML
			if f.Computed {
				tag += ",omitzero"
			}
			b.p("\t%s %s `json:%q`", f.Go, clientType(f), tag)
		}
		b.p("}")
		b.p("")
		for _, c := range containers {
			b.p("// %s%s is the %s part of a %s.", o.Go, camel(c), c, o.Go)
			b.p("type %s%s struct {", o.Go, camel(c))
			for _, f := range o.Fields {
				if f.Container != c {
					continue
				}
				tag := strings.TrimPrefix(f.XML, c+".")
				if f.Computed {
					tag += ",omitzero"
				}
				b.p("\t%s %s `json:%q`", f.Go, clientType(f), tag)
			}
			b.p("}")
			b.p("")
		}
		if o.Settings {
			continue
		}
		// IsZero lets Get report a blank default item (some versions answer an unknown uuid
		// with one) as not found.
		if zf := zeroField(o); zf != nil {
			b.p("func (v *%s) IsZero() bool { return v.%s == \"\" }", o.Go, zf.GoPath())
			b.p("")
		}
		b.p("// %sRow is one row of a %s search; values are display text.", o.Go, o.Resource)
		b.p("type %sRow struct {", o.Go)
		b.p("\tUUID Text `json:\"uuid\"`")
		for _, f := range o.Fields {
			if f.Container == "" {
				b.p("\t%s Text `json:%q`", f.Go, f.XML)
			}
		}
		b.p("}")
		b.p("")
		name := "\"\""
		if o.NameField != "" {
			name = "string(r." + o.field(o.NameField).Go + ")"
		}
		b.p("func (r %sRow) RowRef() (string, string) { return string(r.UUID), %s }", o.Go, name)
		b.p("")
	}

	b.p("// %sService manages %s.", a.Service, a.Title)
	b.p("type %sService struct {", a.Service)
	b.p("\tc *Client")
	if a.Embed != "" {
		b.p("\t*%s", a.Embed)
	}
	for _, o := range a.Items {
		b.p("\t%s *ItemController[%s, %sRow]", o.Plural, o.Go, o.Go)
	}
	for _, o := range a.Settings {
		b.p("\t%s *SettingsController[%s]", o.Plural, o.Go)
	}
	b.p("}")
	b.p("")
	b.p("func new%sService(c *Client) *%sService {", a.Service, a.Service)
	b.p("\treturn &%sService{", a.Service)
	b.p("\t\tc: c,")
	if a.Embed != "" {
		b.p("\t\t%s: new%s(c),", a.Embed, strings.ToUpper(a.Embed[:1])+a.Embed[1:])
	}
	for _, o := range a.Items {
		actions := "nil"
		if len(o.Actions) > 0 {
			var parts []string
			for _, verb := range sortedKeys(o.Actions) {
				parts = append(parts, fmt.Sprintf("%q: %q", verb, o.Actions[verb]))
			}
			actions = "map[string]string{" + strings.Join(parts, ", ") + "}"
		}
		b.p("\t\t%s: NewItemController[%s, %sRow](c, %q, %q, %q, %s, %q),", o.Plural, o.Go, o.Go,
			o.Base, o.Key, o.Suffix, actions, o.Reconfigure)
	}
	for _, o := range a.Settings {
		b.p("\t\t%s: NewSettingsController[%s](c, %q, %q, []string{%s}, %q),", o.Plural, o.Go,
			o.Get, o.Set, quoteList(o.Path), o.Reconfigure)
	}
	b.p("\t}")
	b.p("}")
	return b.file("opnsense", a.Spec)
}

func emitClientIndex(areas []*Area) string {
	b := newW()
	b.p("// generatedServices holds every generated area; Client embeds it.")
	b.p("type generatedServices struct {")
	for _, a := range areas {
		b.p("\t// %s manages %s.", a.Service, a.Title)
		b.p("\t%s *%sService", a.Service, a.Service)
	}
	b.p("}")
	b.p("")
	b.p("func (c *Client) initGenerated() {")
	for _, a := range areas {
		b.p("\tc.%s = new%sService(c)", a.Service, a.Service)
	}
	b.p("}")
	return b.file("opnsense", "gen/specs")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// zeroField picks the field whose emptiness marks a blank item.
func zeroField(o *Object) *Field {
	switch o.ZeroField {
	case "-":
		return nil
	case "":
		for _, f := range o.Fields {
			if f.APIRequired && !f.Computed && (f.Kind == kString || f.Kind == kOption || f.Kind == kRef) && !f.HasDefault {
				return f
			}
		}
		return nil
	}
	f := o.field(o.ZeroField)
	if f.isList() || f.Kind == kBool || f.Kind == kInt {
		return nil
	}
	return f
}
