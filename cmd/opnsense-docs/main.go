// Command opnsense-docs writes the Terraform provider reference: one page per resource and
// action, built from the provider's own schemas, plus an index. It writes HTML (for the
// Pages site) and Markdown (for llms-full.txt).
//
//	opnsense-docs -out _site/docs
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
	opnprovider "github.com/smulis/opnsense-agentic-toolkit/internal/provider"
)

const repoURL = "https://github.com/SmuliS/opnsense-agentic-toolkit"

// areaInfo is what the specs say about a resource.
type areaInfo struct {
	Area     string
	Title    string
	Settings bool
	ID       string // settings resources: the fixed import id
}

// handWritten maps the resources that have no spec to their area and MCP toolset.
var handWritten = map[string]areaInfo{
	"acme_challenge_type": {Area: "acme", Title: "Services → ACME Client"},
	"acme_automation":     {Area: "acme", Title: "Services → ACME Client"},
	"firewall_rule":       {Area: "firewall_rule", Title: "Firewall → Rules [new]"},
	"plugin":              {Area: "firmware", Title: "System → Firmware → Plugins"},
	"auth_api_key":        {Area: "auth", Title: "System → Access → Users"},
	"ids_ruleset":         {Area: "ids", Title: "Services → Intrusion Detection → Download"},
}

type attrDoc struct {
	Name        string
	Type        string
	Required    bool
	Optional    bool
	Computed    bool
	Sensitive   bool
	Description string
	APIField    string
	Constraints []string
	Example     string // from an "e.g. `x`" in the description
}

type page struct {
	Kind        string // resource or action
	Name        string // opnsense_xxx
	Short       string // xxx
	Description string
	Area        areaInfo
	Attrs       []attrDoc
}

var (
	fieldSuffix = regexp.MustCompile(` OPNsense field ` + "`([^`]+)`" + `\.?$`)
	generated   = regexp.MustCompile(` Generated from \S+\.?$`)
	egValue     = regexp.MustCompile("e\\.g\\. `([^`]+)`")
)

func main() {
	out := flag.String("out", "_site/docs", "output directory")
	specs := flag.String("specs", "gen/specs", "directory of generator specs")
	flag.Parse()

	areas, err := loadAreas(*specs)
	if err != nil {
		log.Fatal(err)
	}
	pages, err := collect(areas)
	if err != nil {
		log.Fatal(err)
	}
	if err := write(*out, pages); err != nil {
		log.Fatal(err)
	}
	n, err := writeMCP(filepath.Join(*out, "mcp"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d Terraform pages and %d MCP tool pages to %s\n", len(pages), n, *out)
}

func loadAreas(dir string) (map[string]areaInfo, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	m := map[string]areaInfo{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var s struct {
			Area  string `json:"area"`
			Title string `json:"title"`
			Items []struct {
				Resource string `json:"resource"`
			} `json:"items"`
			Settings []struct {
				Resource string `json:"resource"`
				ID       string `json:"id"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, i := range s.Items {
			m[i.Resource] = areaInfo{Area: s.Area, Title: s.Title}
		}
		for _, i := range s.Settings {
			id := i.ID
			if id == "" {
				id = i.Resource
			}
			m[i.Resource] = areaInfo{Area: s.Area, Title: s.Title, Settings: true, ID: id}
		}
	}
	return m, nil
}

func collect(areas map[string]areaInfo) ([]page, error) {
	ctx := context.Background()
	p := opnprovider.New("dev")()
	var pages []page

	for _, nf := range p.Resources(ctx) {
		r := nf()
		var mr resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "opnsense"}, &mr)
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		short := strings.TrimPrefix(mr.TypeName, "opnsense_")
		info, ok := areas[short]
		if !ok {
			info, ok = handWritten[short]
		}
		if !ok {
			return nil, fmt.Errorf("%s: no area; add it to handWritten", mr.TypeName)
		}
		pg := page{Kind: "resource", Name: mr.TypeName, Short: short, Area: info,
			Description: cleanText(sr.Schema.Description)}
		pg.Attrs = resourceAttrs(ctx, sr.Schema)
		pages = append(pages, pg)
	}
	ap, ok := p.(provider.ProviderWithActions)
	if !ok {
		return nil, fmt.Errorf("provider has no actions")
	}
	for _, nf := range ap.Actions(ctx) {
		a := nf()
		var mr action.MetadataResponse
		a.Metadata(ctx, action.MetadataRequest{ProviderTypeName: "opnsense"}, &mr)
		var sr action.SchemaResponse
		a.Schema(ctx, action.SchemaRequest{}, &sr)
		short := strings.TrimPrefix(mr.TypeName, "opnsense_")
		pg := page{Kind: "action", Name: mr.TypeName, Short: short,
			Area:        areaInfo{Area: "wol", Title: "Services → Wake on LAN (plugin os-wol)"},
			Description: cleanText(sr.Schema.Description)}
		names := make([]string, 0, len(sr.Schema.Attributes))
		for n := range sr.Schema.Attributes {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			at := sr.Schema.Attributes[n].(actionschema.StringAttribute)
			d := attrDoc{Name: n, Type: "String", Required: at.Required, Optional: at.Optional}
			d.Description, d.APIField = splitField(at.Description)
			pg.Attrs = append(pg.Attrs, d)
		}
		pages = append(pages, pg)
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].Name < pages[j].Name })
	return pages, nil
}

func cleanText(s string) string { return generated.ReplaceAllString(strings.TrimSpace(s), "") }

func splitField(s string) (desc, field string) {
	s = strings.TrimSpace(s)
	if m := fieldSuffix.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(fieldSuffix.ReplaceAllString(s, "")), m[1]
	}
	return s, ""
}

func resourceAttrs(ctx context.Context, s schema.Schema) []attrDoc {
	var docs []attrDoc
	for name, a := range s.Attributes {
		d := attrDoc{Name: name, Type: typeName(a.GetType()), Required: a.IsRequired(), Optional: a.IsOptional(),
			Computed: a.IsComputed(), Sensitive: a.IsSensitive()}
		d.Description, d.APIField = splitField(a.GetDescription())
		d.Constraints = constraints(ctx, a)
		if m := egValue.FindStringSubmatch(d.Description); m != nil {
			d.Example = m[1]
		}
		docs = append(docs, d)
	}
	// id first, then required, optional, read-only; alphabetical within each group.
	rank := func(d attrDoc) int {
		switch {
		case d.Name == "id":
			return 0
		case d.Required:
			return 1
		case d.Optional:
			return 2
		}
		return 3
	}
	sort.Slice(docs, func(i, j int) bool {
		if ri, rj := rank(docs[i]), rank(docs[j]); ri != rj {
			return ri < rj
		}
		return docs[i].Name < docs[j].Name
	})
	return docs
}

func typeName(t attr.Type) string {
	switch t := t.(type) {
	case basetypes.StringType:
		return "String"
	case basetypes.Int64Type, basetypes.Int32Type, basetypes.Float64Type, basetypes.NumberType:
		return "Number"
	case basetypes.BoolType:
		return "Boolean"
	case basetypes.ListType:
		return "List of " + typeName(t.ElemType)
	case basetypes.SetType:
		return "Set of " + typeName(t.ElemType)
	case basetypes.MapType:
		return "Map of " + typeName(t.ElemType)
	}
	return t.String()
}

func constraints(ctx context.Context, a schema.Attribute) []string {
	var out []string
	add := func(v interface{ Description(context.Context) string }) {
		d := v.Description(ctx)
		switch {
		case d == "", d == "must match the OPNsense model mask":
			return // true of nearly every field, so it says nothing
		case strings.HasSuffix(d, " and 9007199254740992"): // the generator's "no upper bound"
			d = strings.Replace(strings.TrimSuffix(d, " and 9007199254740992"), "between", "at least", 1)
		}
		out = append(out, d)
	}
	switch a := a.(type) {
	case schema.StringAttribute:
		for _, v := range a.Validators {
			add(v)
		}
	case schema.Int64Attribute:
		for _, v := range a.Validators {
			add(v)
		}
	case schema.ListAttribute:
		for _, v := range a.Validators {
			add(v)
		}
	case schema.SetAttribute:
		for _, v := range a.Validators {
			add(v)
		}
	case schema.MapAttribute:
		for _, v := range a.Validators {
			add(v)
		}
	}
	return out
}

var _ validator.String // validator types are used through their Description method

// ---- rendering ----

func importText(p page) (cmd, note string) {
	switch {
	case p.Kind == "action":
		return "", ""
	case p.Short == "plugin":
		return "terraform import opnsense_plugin.example os-wol", "The ID is the package name. `allow_third_party` is set from the firmware catalog."
	case p.Short == "auth_api_key":
		return "terraform import opnsense_auth_api_key.example <key>", "The ID is the API key. The secret is only shown when the key is created, so it stays null after an import."
	case p.Short == "ids_ruleset":
		return "terraform import opnsense_ids_ruleset.example abuse.ch.sslblacklist.rules", "The ID is the rule set file name."
	case p.Area.Settings:
		return fmt.Sprintf("terraform import %s.example %s", p.Name, p.Area.ID),
			"A settings resource is a singleton: the ID is always `" + p.Area.ID + "`."
	}
	return fmt.Sprintf("terraform import %s.example <uuid-or-name>", p.Name),
		"The ID is the UUID OPNsense assigned, or the item's name when it is unique."
}

func hclValue(a attrDoc) string {
	if a.Example != "" {
		if a.Type == "Number" || a.Type == "Boolean" {
			return a.Example
		}
		return fmt.Sprintf("%q", a.Example)
	}
	switch {
	case a.Type == "Number":
		return "1"
	case a.Type == "Boolean":
		return "true"
	case strings.HasPrefix(a.Type, "List"), strings.HasPrefix(a.Type, "Set"):
		return `["example"]`
	case strings.HasPrefix(a.Type, "Map"):
		return `{ key = "value" }`
	}
	for _, c := range a.Constraints {
		if i := strings.Index(c, "one of: ["); i >= 0 {
			rest := strings.TrimPrefix(c[i:], "one of: [")
			if f := strings.Fields(strings.TrimSuffix(rest, "]")); len(f) > 0 {
				return fmt.Sprintf("%q", strings.Trim(f[0], `",`))
			}
		}
	}
	return `"example"`
}

func exampleHCL(p page) string {
	var b strings.Builder
	if p.Kind == "action" {
		fmt.Fprintf(&b, "action %q \"example\" {\n  config {\n", p.Name)
		for _, a := range p.Attrs {
			if a.Name == "host_id" {
				fmt.Fprintf(&b, "    %s = opnsense_wol_host.nas.id\n", a.Name)
			}
		}
		b.WriteString("  }\n}\n")
		return b.String()
	}
	fmt.Fprintf(&b, "resource %q \"example\" {\n", p.Name)
	for _, a := range p.Attrs {
		if a.Required && a.Name != "id" {
			fmt.Fprintf(&b, "  %s = %s\n", a.Name, hclValue(a))
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func flags(a attrDoc) string {
	var f []string
	switch {
	case a.Required:
		f = append(f, "Required")
	case a.Optional && a.Computed:
		f = append(f, "Optional", "Computed")
	case a.Optional:
		f = append(f, "Optional")
	default:
		f = append(f, "Read-only")
	}
	if a.Sensitive {
		f = append(f, "Sensitive")
	}
	return strings.Join(f, ", ")
}

func markdown(p page) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", p.Name, p.Description)
	fmt.Fprintf(&b, "OPNsense page: %s. MCP toolset: `%s`.\n\n", p.Area.Title, p.Area.Area)
	if p.Kind == "action" {
		b.WriteString("Actions need Terraform 1.14 or later. Run one with `terraform apply -invoke=action." + p.Name + ".example`, or trigger it from a resource's lifecycle with `action_trigger`.\n\n")
	}
	b.WriteString("## Example usage\n\n```hcl\n" + exampleHCL(p) + "```\n\n")
	b.WriteString("## Argument reference\n\n")
	section := func(title string, keep func(attrDoc) bool) {
		var rows []string
		for _, a := range p.Attrs {
			if !keep(a) {
				continue
			}
			row := fmt.Sprintf("- `%s` (%s, %s) %s", a.Name, a.Type, flags(a), a.Description)
			for _, c := range a.Constraints {
				row += " Constraint: " + c + "."
			}
			if a.APIField != "" {
				row += " OPNsense field `" + a.APIField + "`."
			}
			rows = append(rows, row)
		}
		if len(rows) > 0 {
			b.WriteString("### " + title + "\n\n" + strings.Join(rows, "\n") + "\n\n")
		}
	}
	section("Required", func(a attrDoc) bool { return a.Required })
	section("Optional", func(a attrDoc) bool { return !a.Required && a.Optional })
	section("Read-only", func(a attrDoc) bool { return !a.Required && !a.Optional })
	b.WriteString(privilegesMarkdown(privileges.ResourceEndpoints(p.Name)))
	if cmd, note := importText(p); cmd != "" {
		b.WriteString("## Import\n\n" + note + "\n\n```sh\n" + cmd + "\n```\n")
	}
	return b.String()
}

const css = `:root{--bg:#fff;--fg:#1c2128;--muted:#59636e;--card:#f4f6f8;--line:#d8dee4;--accent:#0b6bcb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6edf3;--muted:#9aa4af;--card:#171d24;--line:#2b333c;--accent:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}
main{max-width:56rem;margin:0 auto;padding:2rem 16px 4rem}
nav.crumbs{font-size:.9rem;color:var(--muted);margin-bottom:1rem}
h1{font-size:1.8rem;margin:.2rem 0 .5rem;font-family:ui-monospace,Menlo,monospace}
h2{margin-top:2.2rem;font-size:1.3rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
h3{font-size:1.05rem;margin-top:1.5rem}
a{color:var(--accent)}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto;font-size:.9rem}
code{font-family:ui-monospace,Menlo,monospace;font-size:.92em}
p code,li code,td code{background:var(--card);padding:1px 5px;border-radius:4px}
dl{margin:0}
dt{margin-top:1rem}
dd{margin:.2rem 0 0 0;padding-left:1rem;border-left:3px solid var(--line)}
.tag{color:var(--muted);font-size:.85rem;margin-left:.4rem}
.req{color:#b3261e}
.meta{color:var(--muted)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.area{margin-top:2rem}
footer{margin-top:3rem;color:var(--muted);font-size:.9rem}
`

var inlineCode = regexp.MustCompile("`([^`]+)`")

// htmlText escapes s and turns `code` spans into <code>.
func htmlText(s string) string {
	return inlineCode.ReplaceAllString(html.EscapeString(s), "<code>$1</code>")
}

// htmlPage wraps body in the site chrome. depth is the path back to the site root; section
// names the reference the page belongs to and sectionHref is its index, relative to the root.
func htmlPage(title, body, depth, section, sectionHref string) string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + `</title>
<style>
` + css + `</style>
</head>
<body>
<main>
<nav class="crumbs"><a href="` + depth + `index.html">OPNsense Agentic Toolkit</a> / <a href="` + depth + sectionHref + `">` + section + `</a></nav>
` + body + `
<footer><a href="` + repoURL + `">Source on GitHub</a></footer>
</main>
</body>
</html>
`
}

func htmlResource(p page) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<h1>%s</h1>\n<p>%s</p>\n", html.EscapeString(p.Name), htmlText(p.Description))
	fmt.Fprintf(&b, "<p class=\"meta\">OPNsense page: %s. MCP toolset: <code>%s</code>.</p>\n", html.EscapeString(p.Area.Title), p.Area.Area)
	if p.Kind == "action" {
		b.WriteString("<p>Actions need Terraform 1.14 or later. Run one with <code>terraform apply -invoke=action." + p.Name + ".example</code>, or trigger it from a resource's lifecycle with <code>action_trigger</code>.</p>\n")
	}
	b.WriteString("<h2>Example usage</h2>\n<pre><code>" + html.EscapeString(exampleHCL(p)) + "</code></pre>\n")
	b.WriteString("<h2>Argument reference</h2>\n")
	section := func(title string, keep func(attrDoc) bool) {
		var rows strings.Builder
		for _, a := range p.Attrs {
			if !keep(a) {
				continue
			}
			fmt.Fprintf(&rows, "<dt id=\"%s\"><code>%s</code><span class=\"tag\">%s, %s</span></dt>\n<dd>%s", a.Name, a.Name,
				html.EscapeString(a.Type), flags(a), htmlText(a.Description))
			for _, c := range a.Constraints {
				rows.WriteString("<br><span class=\"meta\">Constraint: " + htmlText(c) + ".</span>")
			}
			if a.APIField != "" {
				rows.WriteString("<br><span class=\"meta\">OPNsense field <code>" + html.EscapeString(a.APIField) + "</code>.</span>")
			}
			rows.WriteString("</dd>\n")
		}
		if rows.Len() > 0 {
			b.WriteString("<h3>" + title + "</h3>\n<dl>\n" + rows.String() + "</dl>\n")
		}
	}
	section("Required", func(a attrDoc) bool { return a.Required })
	section("Optional", func(a attrDoc) bool { return !a.Required && a.Optional })
	section("Read-only", func(a attrDoc) bool { return !a.Required && !a.Optional })
	b.WriteString(privilegesHTML(privileges.ResourceEndpoints(p.Name)))
	if cmd, note := importText(p); cmd != "" {
		b.WriteString("<h2>Import</h2>\n<p>" + htmlText(note) + "</p>\n<pre><code>" + html.EscapeString(cmd) + "</code></pre>\n")
	}
	return b.String()
}

func write(out string, pages []page) error {
	for _, d := range []string{"resources", "actions"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return err
		}
	}
	var full strings.Builder
	full.WriteString("# Terraform provider reference\n\nProvider `opnsense` (source `smulis/opnsense`). Every resource and action below.\n")
	type group struct {
		Title string
		Pages []page
	}
	groups := map[string]*group{}
	var order []string
	for _, p := range pages {
		dir := p.Kind + "s"
		if err := os.WriteFile(filepath.Join(out, dir, p.Short+".md"), []byte(markdown(p)), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, dir, p.Short+".html"),
			[]byte(htmlPage(p.Name, htmlResource(p), "../../", "Terraform provider", "docs/index.html")), 0o644); err != nil {
			return err
		}
		full.WriteString("\n\n---\n\n" + markdown(p))
		key := p.Area.Title
		if p.Kind == "action" {
			key = "Actions"
		}
		g, ok := groups[key]
		if !ok {
			g = &group{Title: key}
			groups[key] = g
			order = append(order, key)
		}
		g.Pages = append(g.Pages, p)
	}
	sort.Strings(order)

	var idx, llms strings.Builder
	fmt.Fprintf(&idx, "<h1 style=\"font-family:inherit\">Terraform provider reference</h1>\n"+
		"<p>%d resources and actions. Each page lists an example, every argument with its type and constraints, and how to import.</p>\n", len(pages))
	idx.WriteString("<p>Looking for the MCP server? See the <a href=\"mcp/index.html\">MCP tool reference</a>.</p>\n<h2>Using the provider</h2>\n<pre><code>terraform {\n  required_providers {\n    opnsense = {\n      source = \"smulis/opnsense\"\n    }\n  }\n}\n\nprovider \"opnsense\" {\n  # url, api_key and api_secret can also come from\n  # OPNSENSE_URL, OPNSENSE_API_KEY and OPNSENSE_API_SECRET.\n}</code></pre>\n")
	llms.WriteString("# Terraform provider reference\n\n")
	for _, k := range order {
		g := groups[k]
		idx.WriteString("<div class=\"area\"><h2>" + html.EscapeString(g.Title) + "</h2>\n<table>\n")
		llms.WriteString("## " + g.Title + "\n\n")
		for _, p := range g.Pages {
			fmt.Fprintf(&idx, "<tr><td><a href=\"%ss/%s.html\"><code>%s</code></a></td><td>%s</td></tr>\n", p.Kind, p.Short, p.Name, htmlText(firstSentence(p.Description)))
			fmt.Fprintf(&llms, "- [%s](https://smulis.github.io/opnsense-agentic-toolkit/docs/%ss/%s.md): %s\n", p.Name, p.Kind, p.Short, firstSentence(p.Description))
		}
		idx.WriteString("</table></div>\n")
		llms.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(out, "index.html"), []byte(htmlPage("Terraform provider reference", idx.String(), "../", "Terraform provider", "docs/index.html")), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "llms-index.md"), []byte(llms.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "reference.md"), []byte(full.String()), 0o644)
}

func firstSentence(s string) string {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '.' && s[i+1] == ' ' && !strings.HasSuffix(s[:i], "e.g") && !strings.HasSuffix(s[:i], "i.e") {
			return s[:i+1]
		}
	}
	return s
}
