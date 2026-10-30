package main

import (
	"fmt"
	"strings"
)

// MCP: generated areas get read-only tools only. Changes go through Terraform (see the
// opnsense-agentic-toolkit skill); hand-written areas keep their write tools.

func viewType(f *Field) string {
	switch {
	case f.Sensitive:
		return "bool"
	case f.isList():
		return "[]string"
	case f.Computed:
		return "string"
	case f.TFKind() == "bool":
		return "bool"
	case f.Kind == kInt:
		return "*int64"
	default:
		return "string"
	}
}

func viewTag(f *Field) string {
	name := f.Attr
	if f.Sensitive {
		name += "_set"
	}
	switch viewType(f) {
	case "bool":
		return name
	default:
		return name + ",omitempty"
	}
}

// viewExpr renders a field the way Terraform spells it (inverted booleans, renamed values).
func viewExpr(f *Field) string {
	v := "v." + f.GoPath()
	switch {
	case f.Sensitive:
		return v + ` != ""`
	case f.isList():
		src := "nonNil([]string(" + v + "))"
		if len(f.Values) > 0 {
			src = "genMapValues(" + src + ", " + mapLiteral(f, false) + ")"
		}
		return src
	case f.Computed:
		return "string(" + v + ")"
	case f.AsTrue != "":
		return fmt.Sprintf("string(%s) == %q", v, f.AsTrue)
	case f.Kind == kBool && f.Invert:
		return "!bool(" + v + ")"
	case f.Kind == kBool:
		return "bool(" + v + ")"
	case f.Kind == kInt:
		return "intPtr(" + v + ")"
	}
	val := v
	if f.Kind == kOption || f.Kind == kRef {
		val = "string(" + v + ")"
	}
	if len(f.Values) > 0 {
		val = "genMapValue(" + val + ", " + mapLiteral(f, false) + ")"
	}
	return val
}

// viewFields are the fields a get tool shows. Update-only fields read back empty, so the
// view cannot even say whether one is set.
func viewFields(o *Object) []*Field {
	var out []*Field
	for _, f := range o.Fields {
		if !f.UpdateOnly {
			out = append(out, f)
		}
	}
	return out
}

func emitView(b *w, o *Object) {
	view := "gen" + o.Go + "View"
	b.p("type %s struct {", view)
	if !o.Settings {
		b.p("\tUUID string `json:\"uuid\"`")
	}
	for _, f := range viewFields(o) {
		name := tfGo(f)
		if f.Sensitive {
			name += "Set"
		}
		desc := ""
		if f.Sensitive {
			desc = " jsonschema:\"whether a value is set; the value is never returned\""
		}
		b.p("\t%s %s `json:%q%s`", name, viewType(f), viewTag(f), desc)
	}
	b.p("}")
	b.p("")
	if o.Settings {
		b.p("func gen%sViewOf(v *opnsense.%s) %s {", o.Go, o.Go, view)
		b.p("\treturn %s{", view)
	} else {
		b.p("func gen%sViewOf(id string, v *opnsense.%s) %s {", o.Go, o.Go, view)
		b.p("\treturn %s{", view)
		b.p("\t\tUUID: id,")
	}
	for _, f := range viewFields(o) {
		name := tfGo(f)
		if f.Sensitive {
			name += "Set"
		}
		b.p("\t\t%s: %s,", name, viewExpr(f))
	}
	b.p("\t}")
	b.p("}")
	b.p("")
}

func emitMCP(a *Area) string {
	b := newW()
	if !a.hasMCP() {
		return b.file("mcpserver", a.Spec) + "// No generated MCP tools: hand-written tools cover this area.\n"
	}
	b.use("context")
	b.use("github.com/modelcontextprotocol/go-sdk/mcp")
	b.use(modulePath + "/internal/opnsense")
	toolset := "gen" + a.Service + "Toolset"
	b.p("const %s = %q", toolset, a.Name)
	b.p("")
	for _, o := range a.objects() {
		if o.mcp() {
			emitView(b, o)
		}
	}
	b.p("func gen%sTools(c *opnsense.Client) []tool {", a.Service)
	b.p("\tsvc := c.%s", a.Service)
	b.p("\treturn []tool{")
	for _, o := range a.Items {
		if !o.mcp() {
			continue
		}
		what := strings.ReplaceAll(o.Resource, "_", " ")
		desc := oneLine(o.Description)
		b.p("\t\tlistTool(%s, %q, %q, %q, svc.%s),", toolset, o.Resource+"_list", "List "+pluralize(what),
			"List "+pluralize(what)+". "+desc+" Read-only: change them with Terraform (opnsense_"+o.Resource+").", o.Plural)
		by := "UUID"
		if o.NameField != "" {
			by += " or " + o.field(o.NameField).Attr
		}
		b.p("\t\t{toolset: %s, readOnly: true, register: func(s *mcp.Server) {", toolset)
		b.p("\t\t\tmcp.AddTool(s, &mcp.Tool{Name: %q,", o.Resource+"_get")
		b.p("\t\t\t\tDescription: %q,", fmt.Sprintf("Get a %s by %s.", what, by))
		b.p("\t\t\t\tAnnotations: &mcp.ToolAnnotations{Title: %q, ReadOnlyHint: true},", "Get "+what)
		b.p("\t\t\t}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, gen%sView, error) {", o.Go)
		b.p("\t\t\t\tid, err := resolveNamed(ctx, svc.%s, in, %q)", o.Plural, what)
		b.p("\t\t\t\tif err != nil {")
		b.p("\t\t\t\t\treturn nil, gen%sView{}, err", o.Go)
		b.p("\t\t\t\t}")
		b.p("\t\t\t\tv, err := svc.%s.Get(ctx, id)", o.Plural)
		b.p("\t\t\t\tif err != nil {")
		b.p("\t\t\t\t\treturn nil, gen%sView{}, notFoundAs(err, %q, id)", o.Go, what)
		b.p("\t\t\t\t}")
		b.p("\t\t\t\treturn nil, gen%sViewOf(id, v), nil", o.Go)
		b.p("\t\t\t})")
		b.p("\t\t}},")
	}
	for _, o := range a.Settings {
		if !o.mcp() {
			continue
		}
		what := strings.ReplaceAll(o.Resource, "_", " ")
		b.p("\t\t{toolset: %s, readOnly: true, register: func(s *mcp.Server) {", toolset)
		b.p("\t\t\tmcp.AddTool(s, &mcp.Tool{Name: %q,", o.Resource+"_get")
		b.p("\t\t\t\tDescription: %q,", "Get the "+what+". "+oneLine(o.Description)+
			" Read-only: change them with Terraform (opnsense_"+o.Resource+").")
		b.p("\t\t\t\tAnnotations: &mcp.ToolAnnotations{Title: %q, ReadOnlyHint: true},", "Get "+what)
		b.p("\t\t\t}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, gen%sView, error) {", o.Go)
		b.p("\t\t\t\tv, err := svc.%s.Get(ctx)", o.Plural)
		b.p("\t\t\t\tif err != nil {")
		b.p("\t\t\t\t\treturn nil, gen%sView{}, err", o.Go)
		b.p("\t\t\t\t}")
		b.p("\t\t\t\treturn nil, gen%sViewOf(v), nil", o.Go)
		b.p("\t\t\t})")
		b.p("\t\t}},")
	}
	b.p("\t}")
	b.p("}")
	return b.file("mcpserver", a.Spec)
}

func emitMCPIndex(areas []*Area) string {
	b := newW()
	b.use(modulePath + "/internal/opnsense")
	b.p("// generatedTools returns the read-only tools of every generated area.")
	b.p("func generatedTools(c *opnsense.Client) []tool {")
	b.p("\tvar tools []tool")
	for _, a := range areas {
		if a.hasMCP() {
			b.p("\ttools = append(tools, gen%sTools(c)...)", a.Service)
		}
	}
	b.p("\treturn tools")
	b.p("}")
	b.p("")
	var names []string
	for _, a := range areas {
		if a.hasMCP() {
			names = append(names, "gen"+a.Service+"Toolset")
		}
	}
	b.p("func genMapValue(v string, m map[string]string) string {")
	b.p("\tif x, ok := m[v]; ok {")
	b.p("\t\treturn x")
	b.p("\t}")
	b.p("\treturn v")
	b.p("}")
	b.p("")
	b.p("func genMapValues(vs []string, m map[string]string) []string {")
	b.p("\tout := make([]string, len(vs))")
	b.p("\tfor i, v := range vs {")
	b.p("\t\tout[i] = genMapValue(v, m)")
	b.p("\t}")
	b.p("\treturn out")
	b.p("}")
	b.p("")
	b.p("// generatedToolsets lists the toolsets of generated areas.")
	b.p("var generatedToolsets = []string{%s}", strings.Join(names, ", "))
	return b.file("mcpserver", "gen/specs")
}

// emitMCPTest checks every generated tool answers against the fake.
func emitMCPTest(areas []*Area) string {
	b := newW()
	b.use("testing")
	b.use(modulePath + "/internal/mcpserver")
	var toolsets []string
	for _, a := range areas {
		if a.hasMCP() {
			toolsets = append(toolsets, a.Name)
		}
	}
	b.p("func TestGeneratedTools(t *testing.T) {")
	b.p("\tcs, _ := connect(t, mcpserver.Options{ReadOnly: true, Toolsets: []string{%s}})", quoteList(toolsets))
	b.p("\tfor _, name := range []string{")
	for _, a := range areas {
		for _, o := range a.Items {
			if o.mcp() {
				b.p("\t\t%q,", o.Resource+"_list")
			}
		}
		for _, o := range a.Settings {
			if o.mcp() {
				b.p("\t\t%q,", o.Resource+"_get")
			}
		}
	}
	b.p("\t} {")
	b.p("\t\tif out, ok := call(t, cs, name, map[string]any{}); !ok {")
	b.p("\t\t\tt.Errorf(\"%%s: %%v\", name, out)")
	b.p("\t\t}")
	b.p("\t}")
	b.p("}")
	return b.file("mcpserver_test", "gen/specs")
}

// pluralize turns "firewall category" into "firewall categories" for tool titles.
func pluralize(s string) string {
	switch {
	case strings.HasSuffix(s, "y") && len(s) > 1 && !strings.ContainsRune("aeiou", rune(s[len(s)-2])):
		return s[:len(s)-1] + "ies"
	case strings.HasSuffix(s, "s"), strings.HasSuffix(s, "x"), strings.HasSuffix(s, "ch"), strings.HasSuffix(s, "sh"):
		return s + "es"
	}
	return s + "s"
}
