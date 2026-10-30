package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	pkgTypes        = "github.com/hashicorp/terraform-plugin-framework/types"
	pkgAttr         = "github.com/hashicorp/terraform-plugin-framework/attr"
	pkgDiag         = "github.com/hashicorp/terraform-plugin-framework/diag"
	pkgResource     = "github.com/hashicorp/terraform-plugin-framework/resource"
	pkgSchema       = "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	pkgPlanmod      = "github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	pkgBoolDefault  = "github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	pkgStrDefault   = "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	pkgIntDefault   = "github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	pkgSetDefault   = "github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	pkgListDefault  = "github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	pkgValidator    = "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	pkgStrValidator = "github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	pkgIntValidator = "github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	pkgSetValidator = "github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	pkgFramework    = "github.com/hashicorp/terraform-plugin-framework/"
	pkgValidators   = "github.com/hashicorp/terraform-plugin-framework-validators/"
)

// Packages a raw spec expression may refer to, by identifier prefix.
var exprPackages = map[string]string{
	"stringvalidator.":    pkgValidators + "stringvalidator",
	"int64validator.":     pkgValidators + "int64validator",
	"setvalidator.":       pkgValidators + "setvalidator",
	"listvalidator.":      pkgValidators + "listvalidator",
	"stringplanmodifier.": pkgFramework + "resource/schema/stringplanmodifier",
	"boolplanmodifier.":   pkgFramework + "resource/schema/boolplanmodifier",
	"int64planmodifier.":  pkgFramework + "resource/schema/int64planmodifier",
	"setplanmodifier.":    pkgFramework + "resource/schema/setplanmodifier",
	"listplanmodifier.":   pkgFramework + "resource/schema/listplanmodifier",
	"regexp.":             "regexp",
}

func useExpr(b *w, expr string) {
	for prefix, pkg := range exprPackages {
		if strings.Contains(expr, prefix) {
			b.use(pkg)
		}
	}
}

// tfType is the Terraform model type of a field.
func tfType(f *Field) string {
	switch f.TFKind() {
	case "bool":
		return "types.Bool"
	case "int":
		return "types.Int64"
	case "set":
		return "types.Set"
	case "list":
		return "types.List"
	}
	return "types.String"
}

// tfShape is the framework's type name: String, Bool, Int64, Set or List.
func tfShape(f *Field) string {
	return strings.TrimPrefix(tfType(f), "types.")
}

func splitVals(v, sep string) []string {
	var out []string
	for _, p := range strings.Split(v, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tfBool converts an API value of a boolean-shaped field to its Terraform value.
func tfBool(f *Field, api string) bool {
	if f.AsTrue != "" {
		return api == f.AsTrue
	}
	return (api == "1") != f.Invert
}

func strValues(b *w, vals []string) string {
	b.use(pkgAttr)
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("types.StringValue(%q)", v)
	}
	return "[]attr.Value{" + strings.Join(parts, ", ") + "}"
}

// tfChoices are the option values in Terraform spelling.
func tfChoices(f *Field) []string {
	out := make([]string, 0, len(f.Choices))
	for _, c := range f.Choices {
		out = append(out, f.toTF(c))
	}
	return out
}

func attrDescription(f *Field) string {
	d := f.Desc
	if (f.Kind == kOption || f.Kind == kOptions) && f.AsTrue == "" && !f.Computed {
		vals := make([]string, 0, len(f.Choices))
		named := 0 // values the hand-written description already names
		for _, c := range tfChoices(f) {
			if c != "" && strings.Contains(d, "`"+c+"`") {
				named++
			}
			if c == "" {
				c = "(empty)"
			}
			vals = append(vals, "`"+c+"`")
		}
		if named < len(nonEmpty(tfChoices(f))) {
			d = strings.TrimSpace(d + " One of " + strings.Join(vals, ", ") + ".")
		}
	}
	switch {
	case f.keepsUnset() && f.UpdateOnly:
		d = strings.TrimSpace(d + " Unset keeps the current value; OPNsense ignores `\"\"`.")
	case f.keepsUnset():
		d = strings.TrimSpace(d + " Unset keeps the value OPNsense has; `\"\"` clears it.")
	}
	if f.Invert {
		d = strings.TrimSpace(d + fmt.Sprintf(" OPNsense field `%s`, inverted.", f.XML))
	} else {
		d = strings.TrimSpace(d + fmt.Sprintf(" OPNsense field `%s`.", f.XML))
	}
	return d
}

// schemaAttr renders one schema attribute.
func schemaAttr(b *w, f *Field) string {
	b.use(pkgSchema)
	shape := tfShape(f)
	var parts []string
	var validators, planmods []string

	switch {
	case f.Computed || f.TFComputed:
		parts = append(parts, "Computed: true")
		if !f.TFUnstable {
			planmods = append(planmods, strings.ToLower(shape)+"planmodifier.UseStateForUnknown()")
		}
	case f.Required():
		parts = append(parts, "Required: true")
	case f.keepsUnset():
		parts = append(parts, "Optional: true", "Computed: true")
		planmods = append(planmods, "stringplanmodifier.UseStateForUnknown()")
	default:
		parts = append(parts, "Optional: true")
		if def := tfDefault(b, f); def != "" {
			parts = append(parts, "Computed: true", "Default: "+def)
		} else if (f.NoDefault || f.TFKind() != "int") && !f.optionalOnly() {
			parts = append(parts, "Computed: true")
		}
	}
	if f.Sensitive {
		parts = append(parts, "Sensitive: true")
	}
	parts = append(parts, fmt.Sprintf("Description: %q", attrDescription(f)))

	if !f.Computed && !f.TFComputed {
		switch {
		case f.Kind == kOption && f.AsTrue == "":
			b.use(pkgStrValidator)
			choices := tfChoices(f)
			if !f.APIRequired && !containsStr(choices, "") {
				choices = append([]string{""}, choices...)
			}
			validators = append(validators, "stringvalidator.OneOf("+quoteList(choices)+")")
		case f.Kind == kOptions:
			b.use(pkgSetValidator)
			b.use(pkgStrValidator)
			inner := "stringvalidator.OneOf(" + quoteList(nonEmpty(tfChoices(f))) + ")"
			if f.TFKind() == "list" {
				b.use(pkgValidators + "listvalidator")
				validators = append(validators, "listvalidator.ValueStringsAre("+inner+")")
			} else {
				validators = append(validators, "setvalidator.ValueStringsAre("+inner+")")
			}
		case f.Kind == kInt && f.HasRange:
			b.use(pkgIntValidator)
			validators = append(validators, fmt.Sprintf("int64validator.Between(%d, %d)", f.Min, f.Max))
		case f.Kind == kString && f.Mask != "" && len(f.Values) == 0 && !f.APIRequired:
			// OPNsense skips the mask for an empty value (TextField::getValidators), so ""
			// clears the field. Generated import config writes it out explicitly.
			validators = append(validators, fmt.Sprintf("optionalMask(regexp.MustCompile(%q))", f.Mask))
		case f.Kind == kString && f.Mask != "" && len(f.Values) == 0:
			validators = append(validators, fmt.Sprintf("stringvalidator.RegexMatches(regexp.MustCompile(%q), %q)",
				f.Mask, "must match the OPNsense model mask"))
		}
	}
	validators = append(validators, f.Validators...)
	planmods = append(planmods, f.PlanMods...)
	for _, e := range append(append([]string{}, validators...), planmods...) {
		useExpr(b, e)
	}
	if len(validators) > 0 {
		b.use(pkgValidator)
		parts = append(parts, "Validators: []validator."+shape+"{"+strings.Join(validators, ", ")+"}")
	}
	if len(planmods) > 0 {
		b.use(pkgPlanmod)
		parts = append(parts, "PlanModifiers: []planmodifier."+shape+"{"+strings.Join(planmods, ", ")+"}")
	}
	if shape == "Set" || shape == "List" {
		b.use(pkgTypes)
		parts = append([]string{"ElementType: types.StringType"}, parts...)
	}
	return "schema." + shape + "Attribute{" + strings.Join(parts, ", ") + "}"
}

// keepsUnset reports whether f is a secret that keeps its current value when the
// configuration leaves it unset. Config generated by an import writes every sensitive
// attribute as null, and with a default of "" the next apply would clear the secret.
func (f *Field) keepsUnset() bool {
	return f.Sensitive && !f.NoDefault && !f.Required() && !f.Computed && !f.TFComputed && f.TFKind() == "string"
}

// optionalOnly reports whether f is a write-only secret that is optional and not computed:
// OPNsense never returns it, so an unset value stays null.
func (f *Field) optionalOnly() bool {
	return f.WriteOnly && f.Sensitive && !f.keepsUnset()
}

// tfDefault renders the schema default, or "" for none.
func tfDefault(b *w, f *Field) string {
	if f.NoDefault {
		return ""
	}
	switch f.TFKind() {
	case "bool":
		b.use(pkgBoolDefault)
		return fmt.Sprintf("booldefault.StaticBool(%v)", tfBool(f, f.Default))
	case "int":
		if !f.HasDefault || f.Default == "" {
			return ""
		}
		b.use(pkgIntDefault)
		return "int64default.StaticInt64(" + f.Default + ")"
	case "set", "list":
		b.use(pkgTypes)
		var vals []string
		for _, v := range splitVals(f.Default, f.Sep) {
			vals = append(vals, f.toTF(v))
		}
		if f.TFKind() == "set" {
			b.use(pkgSetDefault)
			return "setdefault.StaticValue(types.SetValueMust(types.StringType, " + strValues(b, vals) + "))"
		}
		b.use(pkgListDefault)
		return "listdefault.StaticValue(types.ListValueMust(types.StringType, " + strValues(b, vals) + "))"
	}
	b.use(pkgStrDefault)
	return fmt.Sprintf("stringdefault.StaticString(%q)", f.toTF(f.Default))
}

func nonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// mapLiteral renders a Values map in the given direction.
func mapLiteral(f *Field, toAPI bool) string {
	var parts []string
	for _, tf := range sortedKeys(f.Values) {
		api := f.Values[tf]
		if toAPI {
			parts = append(parts, fmt.Sprintf("%q: %q", tf, api))
		} else {
			parts = append(parts, fmt.Sprintf("%q: %q", api, tf))
		}
	}
	return "map[string]string{" + strings.Join(parts, ", ") + "}"
}

// toAPIStmt copies model field f into API value v.
func toAPIStmt(f *Field) string {
	m := "m." + tfGo(f)
	switch {
	case f.Computed || !f.InTF:
		return ""
	case f.AsTrue != "":
		return fmt.Sprintf("if %s.ValueBool() {\nv.%s = %q\n} else {\nv.%s = %q\n}", m, f.GoPath(), f.AsTrue, f.GoPath(), f.AsFalse)
	case f.Kind == kBool:
		if f.Invert {
			return fmt.Sprintf("v.%s = opnsense.Bool(!%s.ValueBool())", f.GoPath(), m)
		}
		return fmt.Sprintf("v.%s = opnsense.Bool(%s.ValueBool())", f.GoPath(), m)
	case f.Kind == kInt:
		return fmt.Sprintf("v.%s = apiInt(%s)", f.GoPath(), m)
	case f.isList():
		s := fmt.Sprintf("diags.Append(%s.ElementsAs(ctx, (*[]string)(&v.%s), false)...)", m, f.GoPath())
		if len(f.Values) > 0 {
			s += fmt.Sprintf("\nfor i, x := range v.%s {\nv.%s[i] = genMapValue(x, %s)\n}", f.GoPath(), f.GoPath(), mapLiteral(f, true))
		}
		return s
	}
	val := m + ".ValueString()"
	if len(f.Values) > 0 {
		val = "genMapValue(" + val + ", " + mapLiteral(f, true) + ")"
	}
	if f.Kind == kOption || f.Kind == kRef {
		return fmt.Sprintf("v.%s = opnsense.Option(%s)", f.GoPath(), val)
	}
	return fmt.Sprintf("v.%s = %s", f.GoPath(), val)
}

func fromAPIStmt(f *Field) string {
	stmt := fromAPIValueStmt(f)
	if f.WriteOnly && stmt != "" {
		cond := "m." + tfGo(f) + ".IsUnknown()"
		if f.keepsUnset() {
			// An import starts from null: take what OPNsense returns, so the next plan has
			// nothing to fill in.
			cond += " || m." + tfGo(f) + ".IsNull()"
		}
		if f.NoDefault && !f.Sensitive && f.TFKind() == "string" {
			// Optional and computed without a default (a generated certificate): empty also
			// means "not known yet", as create first maps the item it posted.
			cond += " || m." + tfGo(f) + ".ValueString() == \"\""
		}
		return fmt.Sprintf("if %s { // write-only: keep what Terraform has\n%s\n}", cond, stmt)
	}
	return stmt
}

func fromAPIValueStmt(f *Field) string {
	m := "m." + tfGo(f)
	v := "v." + f.GoPath()
	switch {
	case !f.InTF:
		return ""
	case f.Computed:
		// Absent in what create sent; filled from the read that follows.
		return fmt.Sprintf("if %s != \"\" || %s.IsUnknown() || %s.IsNull() {\n%s = types.StringValue(string(%s))\n}", v, m, m, m, v)
	case f.AsTrue != "":
		return fmt.Sprintf("%s = types.BoolValue(string(%s) == %q)", m, v, f.AsTrue)
	case f.Kind == kBool:
		if f.Invert {
			return fmt.Sprintf("%s = types.BoolValue(!bool(%s))", m, v)
		}
		return fmt.Sprintf("%s = types.BoolValue(bool(%s))", m, v)
	case f.Kind == kInt:
		return fmt.Sprintf("%s = int64Value(%s)", m, v)
	case f.isList():
		src := "nonNil([]string(" + v + "))"
		if len(f.Values) > 0 {
			src = "genMapValues(" + src + ", " + mapLiteral(f, false) + ")"
		}
		return fmt.Sprintf("%s, d = types.%sValueFrom(ctx, types.StringType, %s)\ndiags.Append(d...)", m, tfShape(f), src)
	}
	val := v
	if f.Kind == kOption || f.Kind == kRef {
		val = "string(" + v + ")"
	}
	if len(f.Values) > 0 {
		val = "genMapValue(" + val + ", " + mapLiteral(f, false) + ")"
	}
	if f.Sensitive && !f.WriteOnly {
		// Secrets can read back empty; keep the configured value. fromAPIStmt guards
		// write-only fields itself.
		return fmt.Sprintf("if %s != \"\" || %s.IsUnknown() || %s.IsNull() {\n%s = types.StringValue(%s)\n}", v, m, m, m, val)
	}
	return fmt.Sprintf("%s = types.StringValue(%s)", m, val)
}

func usesD(o *Object) bool {
	for _, f := range o.tfFields() {
		if f.isList() {
			return true
		}
	}
	return false
}

func emitProvider(a *Area) string {
	b := newW()
	b.use("context")
	b.use(pkgDiag)
	b.use(pkgResource)
	b.use(pkgSchema)
	b.use(pkgTypes)
	b.use(modulePath + "/internal/opnsense")
	for _, o := range a.objects() {
		emitResource(b, a, o)
	}
	return b.file("provider", a.Spec)
}

func emitResource(b *w, a *Area, o *Object) {
	res := "gen" + o.Go + "Resource"
	model := "gen" + o.Go + "Model"
	crud := "gen" + o.Go + "CRUD"
	tfName := "opnsense_" + o.Resource

	b.p("var _ resource.ResourceWithImportState = (*%s)(nil)", res)
	b.p("")
	b.p("// New%sResource returns the %s resource.", o.Go, tfName)
	b.p("func New%sResource() resource.Resource { return &%s{} }", o.Go, res)
	b.p("")
	b.p("type %s struct{ baseResource }", res)
	b.p("")
	b.p("type %s struct {", model)
	b.p("\tID types.String `tfsdk:\"id\"`")
	for _, f := range o.tfFields() {
		b.p("\t%s %s `tfsdk:%q`", tfGo(f), tfType(f), f.Attr)
	}
	b.p("}")
	b.p("")
	b.p("func (r *%s) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {", res)
	b.p("\tresp.TypeName = req.ProviderTypeName + %q", "_"+o.Resource)
	b.p("}")
	b.p("")
	b.p("func (r *%s) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {", res)
	desc := oneLine(o.Description)
	if o.Settings {
		desc += " Only one per firewall."
		if o.Disable != "" {
			desc += fmt.Sprintf(" Destroying it turns `%s` off.", o.field(o.Disable).Attr)
		} else {
			desc += " Destroying it only removes it from Terraform state."
		}
	}
	b.p("\tresp.Schema = schema.Schema{")
	b.p("\t\tDescription: %q,", desc+" Generated from "+o.Model+".")
	b.p("\t\tAttributes: map[string]schema.Attribute{")
	if o.Settings {
		b.use(pkgPlanmod)
		b.use(exprPackages["stringplanmodifier."])
		b.p("\t\t\t\"id\": schema.StringAttribute{Computed: true, Description: %q, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},",
			"Always `"+o.settingsID()+"`.")
	} else {
		b.p("\t\t\t\"id\": idAttribute(%q),", strings.ReplaceAll(o.Resource, "_", " "))
	}
	for _, f := range o.tfFields() {
		b.p("\t\t\t%q: %s,", f.Attr, schemaAttr(b, f))
	}
	b.p("\t\t},")
	b.p("\t}")
	b.p("}")
	b.p("")

	// toAPI
	b.p("func (m *%s) toAPI(ctx context.Context) (opnsense.%s, diag.Diagnostics) {", model, o.Go)
	b.p("\tvar diags diag.Diagnostics")
	b.p("\tvar v opnsense.%s", o.Go)
	for _, f := range o.Fields {
		if s := toAPIStmt(f); s != "" {
			b.p("\t%s", s)
		}
	}
	if o.hook("to_api") {
		b.p("\tdiags.Append(m.hookToAPI(ctx, &v)...) // hand-written")
	}
	b.p("\t_ = ctx")
	b.p("\treturn v, diags")
	b.p("}")
	b.p("")
	// fromAPI
	if o.Settings {
		b.p("func (m *%s) fromAPI(ctx context.Context, v *opnsense.%s) diag.Diagnostics {", model, o.Go)
		b.p("\tm.ID = types.StringValue(%q)", o.settingsID())
	} else {
		b.p("func (m *%s) fromAPI(ctx context.Context, id string, v *opnsense.%s) diag.Diagnostics {", model, o.Go)
		b.p("\tm.ID = types.StringValue(id)")
	}
	b.p("\tvar diags diag.Diagnostics")
	if usesD(o) {
		b.p("\tvar d diag.Diagnostics")
	}
	for _, f := range o.Fields {
		if s := fromAPIStmt(f); s != "" {
			b.p("\t%s", s)
		}
	}
	if o.hook("from_api") {
		b.p("\tdiags.Append(m.hookFromAPI(ctx, v)...) // hand-written")
	}
	b.p("\t_ = ctx")
	b.p("\treturn diags")
	b.p("}")
	b.p("")

	what := strings.ReplaceAll(o.Resource, "_", " ")
	if o.Settings {
		b.p("var %s = settingsCRUD[opnsense.%s, %s, *%s]{", crud, o.Go, model, model)
		b.p("\twhat: %q,", what)
		b.p("\tid: %q,", o.settingsID())
		b.p("\tctl: func(c *opnsense.Client) *opnsense.SettingsController[opnsense.%s] { return c.%s.%s },", o.Go, a.Service, o.Plural)
		if o.Disable != "" {
			b.p("\tdisable: func(v *opnsense.%s) { v.%s = false },", o.Go, o.field(o.Disable).GoPath())
		}
		b.p("}")
	} else {
		b.p("func (m *%s) itemID() string { return m.ID.ValueString() }", model)
		b.p("")
		b.p("var %s = itemCRUD[opnsense.%s, opnsense.%sRow, %s, *%s]{", crud, o.Go, o.Go, model, model)
		b.p("\twhat: %q,", what)
		b.p("\titems: func(c *opnsense.Client) *opnsense.ItemController[opnsense.%s, opnsense.%sRow] { return c.%s.%s },",
			o.Go, o.Go, a.Service, o.Plural)
		if o.Apply != "" {
			b.p("\tapply: func(c *opnsense.Client) func(context.Context) error { return c.%s.%s }, // hand-written", a.Service, o.Apply)
		} else {
			b.p("\tapply: func(c *opnsense.Client) func(context.Context) error { return c.%s.%s.Apply },", a.Service, o.Plural)
		}
		b.p("}")
	}
	b.p("")
	for _, verb := range []string{"Create", "Read", "Update", "Delete"} {
		b.p("func (r *%s) %s(ctx context.Context, req resource.%sRequest, resp *resource.%sResponse) {", res, verb, verb, verb)
		b.p("\t%s.%s(ctx, r.client, req, resp)", crud, strings.ToLower(verb))
		b.p("}")
		b.p("")
	}
	if o.CustomImport {
		b.p("// ImportState is hand-written for this resource.")
		b.p("")
		return
	}
	if o.Settings {
		b.p("// ImportState accepts any id; there is only one %s.", what)
		b.p("func (r *%s) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {", res)
		b.p("\t%s.importState(ctx, resp)", crud)
	} else {
		how := "a UUID"
		if o.NameField != "" {
			how += " or the " + o.field(o.NameField).Attr
		}
		b.p("// ImportState accepts %s.", how)
		b.p("func (r *%s) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {", res)
		if o.NameField != "" {
			b.p("\timportByName(ctx, req, resp, r.client.%s.%s, %q)", a.Service, o.Plural, what)
		} else {
			b.use(pkgFramework + "path")
			b.p("\tresp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(\"id\"), req.ID)...)")
		}
	}
	b.p("}")
	b.p("")
}

func emitProviderIndex(areas []*Area) string {
	b := newW()
	b.use(pkgResource)
	b.p("// generatedResources lists every generated resource.")
	b.p("func generatedResources() []func() resource.Resource {")
	b.p("\treturn []func() resource.Resource{")
	for _, a := range areas {
		for _, o := range a.objects() {
			b.p("\t\tNew%sResource,", o.Go)
		}
	}
	b.p("\t}")
	b.p("}")
	b.p("")
	b.p("// genMapValue translates v through m, or returns it unchanged.")
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
	return b.file("provider", "gen/specs")
}

// ---- tests ----

// exampleValue returns the API value a generated test uses for f ("" with ok=false when the
// field is left unknown for a hook or OPNsense to fill).
func exampleValue(o *Object, f *Field) (string, bool) {
	if v, ok := o.Example[f.XML]; ok {
		return v, true
	}
	if f.Computed || f.TFComputed || f.NoDefault {
		return "", false
	}
	if f.HasDefault && !f.Required() {
		return f.Default, true
	}
	if !f.Required() {
		if f.TFKind() == "bool" {
			if f.AsTrue != "" {
				return f.AsFalse, true
			}
			if f.Invert {
				return "1", true
			}
			return "0", true
		}
		return "", true
	}
	switch f.Kind {
	case kBool:
		return "1", true
	case kInt:
		if f.HasRange {
			return strconv.FormatInt(f.Min, 10), true
		}
		return "1", true
	case kOption, kOptions:
		if f.AsTrue != "" {
			return f.AsTrue, true
		}
		return nonEmpty(f.Choices)[0], true
	case kRef, kRefs:
		return "lan", true
	}
	return "test-" + strings.ReplaceAll(f.Attr, "_", "-"), true
}

// tfLiteral renders the Terraform model value for API value v.
func tfLiteral(f *Field, v string, known bool) string {
	if !known {
		if f.optionalOnly() {
			return "types." + tfShape(f) + "Null()"
		}
		return "types." + tfShape(f) + "Unknown()"
	}
	switch f.TFKind() {
	case "bool":
		return fmt.Sprintf("types.BoolValue(%v)", tfBool(f, v))
	case "int":
		if v == "" {
			return "types.Int64Null()"
		}
		return "types.Int64Value(" + v + ")"
	case "set", "list":
		var vals []string
		for _, x := range splitVals(v, f.Sep) {
			vals = append(vals, f.toTF(x))
		}
		if f.TFKind() == "set" {
			return "strSet(" + quoteList(vals) + ")"
		}
		return "strList(" + quoteList(vals) + ")"
	}
	return fmt.Sprintf("types.StringValue(%q)", f.toTF(v))
}

// updateValues picks the fields the update step changes.
func updateValues(o *Object) map[string]string {
	if len(o.Update) > 0 {
		return o.Update
	}
	for _, f := range o.tfFields() {
		if f.Kind == kString && f.TFKind() == "string" && !f.Computed && !f.TFComputed && !f.Sensitive &&
			len(f.Values) == 0 && f.Mask == "" && (f.Attr == "description" || !f.APIRequired) && o.Example[f.XML] == "" {
			return map[string]string{f.XML: "updated by test"}
		}
	}
	for _, f := range o.tfFields() {
		if f.Kind == kBool && !f.Computed && !f.TFComputed {
			if v, _ := exampleValue(o, f); v == "1" {
				return map[string]string{f.XML: "0"}
			}
			return map[string]string{f.XML: "1"}
		}
	}
	return nil
}

func emitProviderTest(a *Area) string {
	b := newW()
	b.use("testing")
	b.use(pkgTypes)
	b.use(modulePath + "/internal/opnsense/opnsensetest")
	for _, o := range a.objects() {
		emitPlanHelper(b, o)
	}
	for _, o := range a.Items {
		if !o.NoTest {
			emitItemTest(b, o)
		}
	}
	for _, o := range a.Settings {
		emitSettingsTest(b, o)
	}
	return b.file("provider", a.Spec)
}

// emitPlanHelper writes gen<Go>Plan, a plan with example values that hand-written tests reuse.
func emitPlanHelper(b *w, o *Object) {
	vals := exampleValues(o, o.Settings) // settings tests write the update values directly
	b.p("// gen%sPlan returns a create plan with the example values from %s.", o.Go, o.Area.Spec)
	b.p("func gen%sPlan() gen%sModel {", o.Go, o.Go)
	b.p("\treturn gen%sModel{", o.Go)
	b.p("\t\tID: types.StringUnknown(),")
	for _, f := range o.tfFields() {
		v, known := vals[f.XML]
		b.p("\t\t%s: %s,", tfGo(f), tfLiteral(f, v.v, known && v.known))
	}
	b.p("\t}")
	b.p("}")
	b.p("")
}

type exVal struct {
	v     string
	known bool
}

func exampleValues(o *Object, withUpdate bool) map[string]exVal {
	vals := map[string]exVal{}
	for _, f := range o.Fields {
		v, ok := exampleValue(o, f)
		vals[f.XML] = exVal{v, ok}
	}
	if withUpdate {
		for k, v := range updateValues(o) {
			vals[k] = exVal{v, true}
		}
	}
	return vals
}

// checkStored compares stored API values with what the plan set.
func checkStored(b *w, o *Object, rec string, vals map[string]exVal, only map[string]string) {
	for _, f := range o.tfFields() {
		if f.Computed || f.TFComputed || !vals[f.XML].known {
			continue
		}
		if only != nil {
			if _, ok := only[f.XML]; !ok {
				continue
			}
		}
		want := vals[f.XML].v
		b.p("\tif !sameValues(%s[%q], %q) {", rec, f.XML, want)
		b.p("\t\tt.Errorf(\"%s: stored %%q, want %%q\", %s[%q], %q)", f.XML, rec, f.XML, want)
		b.p("\t}")
	}
}

func emitItemTest(b *w, o *Object) {
	model := "gen" + o.Go + "Model"
	vals := exampleValues(o, false)
	b.p("func TestGen%s(t *testing.T) {", o.Go)
	b.p("\tfake := opnsensetest.New(t)")
	b.p("\th := newHarness(t, fake, New%sResource())", o.Go)
	b.p("\tplan := gen%sPlan()", o.Go)
	b.p("\tvar got %s", model)
	b.p("\tst, ok := h.create(plan, &got)")
	b.p("\tif !ok {")
	b.p("\t\tt.Fatal(\"create failed\")")
	b.p("\t}")
	b.p("\tid := got.ID.ValueString()")
	b.p("\trec, ok := fake.Get(%q, id)", o.Key)
	b.p("\tif !ok {")
	b.p("\t\tt.Fatal(\"not stored\")")
	b.p("\t}")
	checkStored(b, o, "rec", vals, nil)
	for _, f := range o.tfFields() {
		if f.Computed {
			b.p("\tif got.%s.ValueString() == \"\" && rec[%q] != \"\" {", tfGo(f), f.XML)
			b.p("\t\tt.Error(\"computed %s not read back\")", f.Attr)
			b.p("\t}")
		}
	}
	if upd := updateValues(o); len(upd) > 0 {
		b.p("")
		b.p("\tplan.ID = got.ID")
		for _, f := range o.tfFields() {
			if f.Computed || f.TFComputed || !vals[f.XML].known {
				b.p("\tplan.%s = got.%s", tfGo(f), tfGo(f))
			}
		}
		for _, k := range sortedKeys(upd) {
			f := o.field(k)
			vals[k] = exVal{upd[k], true}
			b.p("\tplan.%s = %s", tfGo(f), tfLiteral(f, upd[k], true))
		}
		b.p("\tst = h.update(st, plan, &got)")
		b.p("\trec, _ = fake.Get(%q, id)", o.Key)
		checkStored(b, o, "rec", vals, upd)
	}
	b.p("")
	b.p("\tif _, ok := h.read(st, &got); !ok {")
	b.p("\t\tt.Fatal(\"read removed the resource\")")
	b.p("\t}")
	b.p("\tif imp, ok := h.importID(id); !ok || imp != id {")
	b.p("\t\tt.Fatalf(\"import by uuid = %%q\", imp)")
	b.p("\t}")
	if o.NameField != "" {
		f := o.field(o.NameField)
		if v := vals[o.NameField]; !f.Computed && v.known && v.v != "" {
			b.p("\tif imp, ok := h.importID(%q); !ok || imp != id {", v.v)
			b.p("\t\tt.Fatalf(\"import by name = %%q\", imp)")
			b.p("\t}")
		}
	}
	b.p("\th.delete(st)")
	b.p("\tif _, ok := fake.Get(%q, id); ok {", o.Key)
	b.p("\t\tt.Fatal(\"still stored after delete\")")
	b.p("\t}")
	if o.Reconfigure != "" {
		b.p("\tif fake.Applies[%q] == 0 {", o.Reconfigure)
		b.p("\t\tt.Error(\"never applied\")")
		b.p("\t}")
	}
	// The schema rejects invalid options at plan time.
	for _, f := range o.tfFields() {
		if f.Kind == kOption && f.AsTrue == "" && !f.Computed && !f.TFComputed {
			b.p("\tbad := plan")
			b.p("\tbad.%s = types.StringValue(\"not-an-option\")", tfGo(f))
			b.p("\tif !h.validateStrings(bad).HasError() {")
			b.p("\t\tt.Error(\"invalid %s accepted\")", f.Attr)
			b.p("\t}")
			break
		}
	}
	b.p("}")
	b.p("")
}

func emitSettingsTest(b *w, o *Object) {
	model := "gen" + o.Go + "Model"
	vals := exampleValues(o, true)
	b.p("func TestGen%s(t *testing.T) {", o.Go)
	b.p("\tfake := opnsensetest.New(t)")
	b.p("\th := newHarness(t, fake, New%sResource())", o.Go)
	b.p("\tplan := gen%sPlan()", o.Go)
	b.p("\tvar got %s", model)
	b.p("\tst, ok := h.create(plan, &got)")
	b.p("\tif !ok || got.ID.ValueString() != %q {", o.settingsID())
	b.p("\t\tt.Fatalf(\"create: %%+v\", got)")
	b.p("\t}")
	b.p("\trec := fake.Settings(%q, %q)", o.Get, settingsSection(o))
	checkStored(b, o, "rec", vals, nil)
	b.p("\tif _, ok := h.read(st, &got); !ok {")
	b.p("\t\tt.Fatal(\"read removed the resource\")")
	b.p("\t}")
	b.p("\th.delete(st)")
	if o.Disable != "" {
		b.p("\tif fake.Settings(%q, %q)[%q] != \"0\" {", o.Get, settingsSection(o), o.Disable)
		b.p("\t\tt.Error(\"destroy did not disable\")")
		b.p("\t}")
	}
	b.p("}")
	b.p("")
}

func emitProviderTestHelpers() string {
	b := newW()
	b.use("sort")
	b.use("strings")
	b.p("// sameValues compares API values, ignoring the order of list entries.")
	b.p("func sameValues(got, want string) bool {")
	b.p("\tnorm := func(s string) string {")
	b.p("\t\tparts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\\n' })")
	b.p("\t\tsort.Strings(parts)")
	b.p("\t\treturn strings.Join(parts, \",\")")
	b.p("\t}")
	b.p("\treturn norm(got) == norm(want)")
	b.p("}")
	return b.file("provider", "gen/specs")
}

// tfGo is the Terraform model field name, from the attribute (the client name may differ,
// e.g. client Disabled vs Terraform enabled).
func tfGo(f *Field) string { return goName(f.Attr) }
