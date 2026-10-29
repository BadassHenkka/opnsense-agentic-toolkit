package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Spec is one gen/specs/<area>.json file: an API area and the resources to generate for it.
// Field types, defaults, option lists and required flags come from the pinned model XML; the
// spec only adds what the XML cannot say (API paths, names, examples, overrides).
type Spec struct {
	// Area names the MCP toolset and, camel-cased, the client service (Client.<Service>).
	Area    string `json:"area"`
	Service string `json:"service,omitempty"`
	Title   string `json:"title"`

	Items    []ObjectSpec `json:"items,omitempty"`
	Settings []ObjectSpec `json:"settings,omitempty"`

	// Embed names a hand-written struct type embedded (as a pointer) in the generated service,
	// for state hand-written methods need; it must have a constructor new<Embed>(*Client).
	Embed string `json:"embed,omitempty"`
	// MCP false skips generated MCP tools for the whole area (hand-written tools cover it).
	MCP *bool `json:"mcp,omitempty"`
}

// ObjectSpec describes one item array or settings section.
type ObjectSpec struct {
	// Resource is the Terraform type without the provider prefix, e.g. "vlan"; it also names
	// the MCP tools (<resource>_list, <resource>_get).
	Resource string `json:"resource"`
	// GoName overrides the Go type name (default: camel-cased resource).
	GoName string `json:"go_name,omitempty"`
	// Plural names the field on the service: the ItemController (default GoName + "s") or the
	// SettingsController (default GoName).
	Plural      string `json:"plural,omitempty"`
	Description string `json:"description"`

	// Model is the XML file under gen/models, e.g. "core/Interfaces/Vlan.xml".
	Model string `json:"model"`
	// Node is the dotted path below <items> to the ArrayField or settings section.
	Node string `json:"node"`

	// Items: controller base, wrapper key, action suffix and verb overrides.
	Base    string            `json:"base,omitempty"`
	Key     string            `json:"key,omitempty"`
	Suffix  string            `json:"suffix,omitempty"`
	Actions map[string]string `json:"actions,omitempty"`
	// NameField is the XML field used to import and look up items by name.
	NameField string `json:"name_field,omitempty"`

	// Settings: endpoints and the response path [root, section].
	Get  string   `json:"get,omitempty"`
	Set  string   `json:"set,omitempty"`
	Path []string `json:"path,omitempty"`
	// Disable is a boolean XML field set to false when the resource is destroyed.
	Disable string `json:"disable,omitempty"`
	// ID is the constant id of a settings resource (default: the resource name).
	ID string `json:"id,omitempty"`

	Reconfigure string `json:"reconfigure,omitempty"`

	Fields map[string]FieldSpec `json:"fields,omitempty"`
	// Example holds API values (as OPNsense stores them) used by the generated tests;
	// Update holds values changed in the update step. Missing ones are derived.
	Example map[string]string `json:"example,omitempty"`
	Update  map[string]string `json:"update,omitempty"`

	// ZeroField is the XML field whose emptiness means "not found" in Get ("-" for none;
	// default: the first required text field without a default).
	ZeroField string `json:"zero_field,omitempty"`
	// MCP false skips the generated MCP tools for this object.
	MCP *bool `json:"mcp,omitempty"`
	// Hooks lists hand-written Terraform model methods the generated code calls:
	// "to_api" -> hookToAPI(ctx, *T) diag.Diagnostics, "from_api" -> hookFromAPI(ctx, *T) diag.Diagnostics.
	Hooks []string `json:"hooks,omitempty"`
	// Apply names a hand-written service method used instead of the reconfigure action, e.g.
	// one that verifies the firewall is still reachable afterwards.
	Apply string `json:"apply,omitempty"`
	// CustomImport leaves ImportState to hand-written code (e.g. lookups by name/TYPE).
	CustomImport bool `json:"custom_import,omitempty"`
	// NoTest skips the generated resource test, for items that need other items to exist
	// (a hand-written test covers them); the plan helper is still generated.
	NoTest bool `json:"no_test,omitempty"`
}

// FieldSpec overrides what the XML says about one field.
type FieldSpec struct {
	Attr string `json:"attr,omitempty"`
	// Type is one of bool, int, string, option, options, ref, refs, list. Required for
	// custom field types (".\FooField") the generator cannot map.
	Type        string   `json:"type,omitempty"`
	Skip        bool     `json:"skip,omitempty"`
	Computed    bool     `json:"computed,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty"`
	Description string   `json:"description,omitempty"`
	Choices     []string `json:"choices,omitempty"`
	// FakeValue is the pattern the fake uses for a computed field on add ("%d" = counter).
	FakeValue string `json:"fake_value,omitempty"`

	// GoName overrides the Go field name.
	GoName string `json:"go_name,omitempty"`
	// Sep overrides the list separator ("\n" for newline-separated lists such as alias content).
	Sep string `json:"sep,omitempty"`
	// Required overrides whether the Terraform attribute is required.
	Required *bool `json:"required,omitempty"`
	// Default overrides the XML default (an API value).
	Default *string `json:"default,omitempty"`
	// NoDefault makes the attribute optional and computed without a default (the value
	// comes from a hook or from OPNsense).
	NoDefault bool `json:"no_default,omitempty"`
	// TFType is "set" or "list" for list-like fields (default: list for free-form lists,
	// set for option and relation lists).
	TFType string `json:"tf_type,omitempty"`
	// Invert exposes a boolean negated, e.g. OPNsense "disabled" as Terraform "enabled".
	Invert bool `json:"invert,omitempty"`
	// AsBool exposes a two-value option as a boolean: {"true": "<api value>", "false": "<api value>"}.
	AsBool map[string]string `json:"as_bool,omitempty"`
	// Values renames option values for Terraform and MCP: {"<terraform value>": "<api value>"}.
	Values map[string]string `json:"values,omitempty"`
	// Validators and PlanModifiers are Go expressions appended to the attribute.
	Validators    []string `json:"validators,omitempty"`
	PlanModifiers []string `json:"plan_modifiers,omitempty"`
	// Include generates a volatile field (one OPNsense computes or keeps elsewhere).
	Include bool `json:"include,omitempty"`
	// TF false leaves the field out of Terraform (client and MCP only).
	TF *bool `json:"tf,omitempty"`
	// TFComputed makes the attribute computed in Terraform only (set by a hook); it is still sent.
	TFComputed bool `json:"tf_computed,omitempty"`
	// TFUnstable marks a computed attribute OPNsense changes on its own (no UseStateForUnknown).
	TFUnstable bool `json:"tf_unstable,omitempty"`
	// WriteOnly marks an input OPNsense does not return faithfully (volatile creation
	// parameters, private keys): reads keep the value Terraform has and only fill an unknown
	// one. A sensitive write-only attribute is not computed, so a value OPNsense generates
	// (a private key) never reaches the state.
	WriteOnly bool `json:"write_only,omitempty"`
}

// Area is a parsed spec, ready for the emitters.
type Area struct {
	Spec     string // spec file name, for the generated header
	Name     string
	Service  string
	Title    string
	Items    []*Object
	Settings []*Object
	Embed    string
	NoMCP    bool
}

// objects returns items and settings.
func (a *Area) objects() []*Object { return append(append([]*Object{}, a.Items...), a.Settings...) }

// hasMCP reports whether any object of the area gets generated MCP tools.
func (a *Area) hasMCP() bool {
	for _, o := range a.objects() {
		if o.mcp() {
			return true
		}
	}
	return false
}

// Object is an item array or a settings section with resolved fields.
type Object struct {
	ObjectSpec
	Settings bool
	Go       string
	Fields   []*Field
	Skipped  []string // nested containers and fields left out, for the generated comment
	Area     *Area
}

func (o *Object) mcp() bool { return !o.Area.NoMCP && (o.MCP == nil || *o.MCP) }

func (o *Object) hook(name string) bool {
	for _, h := range o.Hooks {
		if h == name {
			return true
		}
	}
	return false
}

// tfFields are the fields that appear in Terraform.
func (o *Object) tfFields() []*Field {
	var out []*Field
	for _, f := range o.Fields {
		if f.InTF {
			out = append(out, f)
		}
	}
	return out
}

// Field kinds.
const (
	kBool    = "bool"
	kInt     = "int"
	kString  = "string"
	kOption  = "option"  // single value from a static list
	kOptions = "options" // several values from a static list
	kRef     = "ref"     // single value from a dynamic list (relation, interface, certificate, ...)
	kRefs    = "refs"    // several values from a dynamic list
	kList    = "list"    // free-form list (AsList / CSVListField)
)

// Field is one resolved model field.
type Field struct {
	XML, Attr, Go string
	Kind          string
	Sep           string // list separator for list kinds
	APIRequired   bool
	Default       string
	HasDefault    bool
	Choices       []string
	Min, Max      int64
	HasRange      bool
	Computed      bool
	Sensitive     bool
	// UpdateOnly fields (UpdateOnlyTextField) read back empty, and OPNsense ignores an empty
	// value on write.
	UpdateOnly bool
	Desc       string
	FakeValue  string
	// Mask is the model's validation regex translated to Go syntax ("" if none or untranslatable).
	Mask string
	// Unique fields must not repeat across items (optionally together with UniqueWith).
	Unique     bool
	UniqueWith []string

	InTF          bool
	TFComputed    bool
	TFUnstable    bool
	WriteOnly     bool
	NoDefault     bool
	ForceRequired *bool
	TFAsList      bool   // list-like field exposed as a Terraform list (else set)
	Invert        bool   // bool exposed negated
	AsTrue        string // option exposed as bool: API value for true
	AsFalse       string // ... and for false
	Values        map[string]string
	Validators    []string
	PlanMods      []string
	// Container is the enclosing XML node for nested fields ("source"); ContainerGo its Go name.
	Container, ContainerGo string
	// XMLDefault is the model's own default; the fake uses it even when the spec overrides
	// the Terraform default.
	XMLDefault    string
	XMLHasDefault bool
}

// Required in Terraform: OPNsense requires it and has no default to fall back on.
func (f *Field) Required() bool {
	if f.Computed || f.TFComputed {
		return false
	}
	if f.ForceRequired != nil {
		return *f.ForceRequired
	}
	return f.APIRequired && !f.HasDefault
}

// GoPath is the field's path in the client struct, e.g. Source.Network.
func (f *Field) GoPath() string {
	if f.Container != "" {
		return f.ContainerGo + "." + f.Go
	}
	return f.Go
}

// isList reports a field holding several values.
func (f *Field) isList() bool { return f.Kind == kOptions || f.Kind == kRefs || f.Kind == kList }

// TFKind is the Terraform shape: bool, int, string, set or list.
func (f *Field) TFKind() string {
	switch {
	case f.AsTrue != "" || f.Kind == kBool:
		return "bool"
	case f.Kind == kInt:
		return "int"
	case f.isList() && f.TFAsList:
		return "list"
	case f.isList():
		return "set"
	}
	return "string"
}

// toTF maps an API value to its Terraform/MCP spelling (Values, AsBool, Invert).
func (f *Field) toTF(v string) string {
	for tf, api := range f.Values {
		if api == v {
			return tf
		}
	}
	return v
}

// xmlNode is a generic model XML element.
type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Children []xmlNode  `xml:",any"`
	Text     string     `xml:",chardata"`
}

func (n *xmlNode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n *xmlNode) child(name string) *xmlNode {
	for i := range n.Children {
		if n.Children[i].XMLName.Local == name {
			return &n.Children[i]
		}
	}
	return nil
}

func (n *xmlNode) value(name string) string {
	if c := n.child(name); c != nil {
		return strings.TrimSpace(c.Text)
	}
	return ""
}

// loadSpecs reads every spec in dir and resolves it against the models in modelDir.
func loadSpecs(dir, modelDir string) ([]*Area, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var areas []*Area
	for _, f := range files {
		a, err := loadSpec(f, modelDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		areas = append(areas, a)
	}
	return areas, nil
}

func loadSpec(file, modelDir string) (*Area, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var s Spec
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	if s.Area == "" {
		return nil, fmt.Errorf("area is required")
	}
	a := &Area{Spec: "gen/specs/" + filepath.Base(file), Name: s.Area, Service: s.Service, Title: s.Title,
		Embed: s.Embed, NoMCP: s.MCP != nil && !*s.MCP}
	if a.Service == "" {
		a.Service = camel(s.Area)
	}
	for _, obj := range s.Items {
		o, err := resolve(obj, false, modelDir)
		if err != nil {
			return nil, fmt.Errorf("item %s: %w", obj.Resource, err)
		}
		o.Area = a
		a.Items = append(a.Items, o)
	}
	for _, obj := range s.Settings {
		o, err := resolve(obj, true, modelDir)
		if err != nil {
			return nil, fmt.Errorf("settings %s: %w", obj.Resource, err)
		}
		o.Area = a
		a.Settings = append(a.Settings, o)
	}
	return a, nil
}

func resolve(s ObjectSpec, settings bool, modelDir string) (*Object, error) {
	if s.Resource == "" || s.Model == "" || (s.Node == "" && !settings) {
		return nil, fmt.Errorf("resource, model and node are required")
	}
	if settings {
		if s.Get == "" || s.Set == "" || len(s.Path) < 1 || len(s.Path) > 2 {
			return nil, fmt.Errorf("settings need get, set and path [root] or [root, section]")
		}
	} else if s.Base == "" || s.Key == "" {
		return nil, fmt.Errorf("items need base and key")
	}
	o := &Object{ObjectSpec: s, Settings: settings, Go: s.GoName}
	if o.Go == "" {
		o.Go = camel(s.Resource)
	}
	if o.Plural == "" {
		o.Plural = o.Go + "s"
		if settings {
			o.Plural = o.Go // the service field; for settings usually set to e.g. "General"
		}
	}

	data, err := os.ReadFile(filepath.Join(modelDir, s.Model))
	if err != nil {
		return nil, err
	}
	var root xmlNode
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Model, err)
	}
	node := root.child("items")
	if node == nil {
		return nil, fmt.Errorf("%s: no <items>", s.Model)
	}
	for _, part := range strings.Split(s.Node, ".") {
		if part == "" {
			continue // settings fields directly below <items>
		}
		if node = node.child(part); node == nil {
			return nil, fmt.Errorf("%s: no node %s", s.Model, s.Node)
		}
	}

	used := map[string]bool{}
	for fs := range s.Fields {
		used[fs] = false
	}
	attrs := map[string]string{}
	type cand struct {
		n         *xmlNode
		container string
	}
	var cands []cand
	for i := range node.Children {
		n := &node.Children[i]
		typ := n.attr("type")
		switch {
		case typ == "":
			// A container groups fields one level deeper (e.g. a NAT rule's source/destination);
			// they are generated with a dotted name. Deeper nesting is left out.
			for j := range n.Children {
				c := &n.Children[j]
				if c.attr("type") == "" {
					o.Skipped = append(o.Skipped, n.XMLName.Local+"."+c.XMLName.Local+" (nested container)")
					continue
				}
				cands = append(cands, cand{c, n.XMLName.Local})
			}
		case settings && strings.HasSuffix(typ, "ArrayField"):
			o.Skipped = append(o.Skipped, n.XMLName.Local+" (items; a separate resource)")
		default:
			cands = append(cands, cand{n, ""})
		}
	}
	for _, cd := range cands {
		n := cd.n
		name := n.XMLName.Local
		if cd.container != "" {
			name = cd.container + "." + name
		}
		fs, hasSpec := s.Fields[name]
		if hasSpec {
			used[name] = true
		}
		typ := n.attr("type")
		if fs.Skip || (n.attr("volatile") == "true" && !fs.Include) {
			o.Skipped = append(o.Skipped, name)
			continue
		}
		f, err := field(n, typ, fs, cd.container)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", name, err)
		}
		if other, dup := attrs[f.Attr]; dup {
			return nil, fmt.Errorf("fields %s and %s both map to attribute %q", other, name, f.Attr)
		}
		attrs[f.Attr] = name
		o.Fields = append(o.Fields, f)
	}
	for name, ok := range used {
		if !ok {
			return nil, fmt.Errorf("spec mentions field %q, which the model does not have", name)
		}
	}
	if s.NameField != "" && o.field(s.NameField) == nil {
		return nil, fmt.Errorf("name_field %q is not a generated field", s.NameField)
	}
	if s.Disable != "" {
		if f := o.field(s.Disable); f == nil || f.Kind != kBool {
			return nil, fmt.Errorf("disable field %q must be a boolean field", s.Disable)
		}
	}
	for k := range s.Example {
		if o.field(k) == nil {
			return nil, fmt.Errorf("example for unknown field %q", k)
		}
	}
	for k := range s.Update {
		if o.field(k) == nil {
			return nil, fmt.Errorf("update for unknown field %q", k)
		}
	}
	if s.ZeroField != "" && s.ZeroField != "-" && o.field(s.ZeroField) == nil {
		return nil, fmt.Errorf("zero_field %q is not a generated field", s.ZeroField)
	}
	for _, h := range s.Hooks {
		if h != "to_api" && h != "from_api" {
			return nil, fmt.Errorf("unknown hook %q (to_api, from_api)", h)
		}
	}
	return o, nil
}

func (o *Object) field(xmlName string) *Field {
	for _, f := range o.Fields {
		if f.XML == xmlName {
			return f
		}
	}
	return nil
}

// Field types by kind. Types not listed must be given in the spec.
var xmlTypes = map[string]string{
	"BooleanField":              kBool,
	"IntegerField":              kInt,
	"TextField":                 kString,
	"DescriptionField":          kString,
	"StrictTextField":           kString,
	"HostnameField":             kString,
	"NetworkField":              kString,
	"EmailField":                kString,
	"UrlField":                  kString,
	"MacAddressField":           kString,
	"IPPortField":               kString,
	"Base64Field":               kString,
	"PortField":                 kString, // may hold ranges or well-known names
	"NumericField":              kString, // decimals
	"UpdateOnlyTextField":       kString,
	"OptionField":               kOption,
	"ModelRelationField":        kRef,
	"InterfaceField":            kRef,
	"CertificateField":          kRef,
	"NetworkAliasField":         kRef,
	"AuthGroupField":            kRef,
	"AuthenticationServerField": kRef,
	"JsonKeyValueStoreField":    kRef,
	"ConfigdActionsField":       kRef,
	"VirtualIPField":            kRef,
	"CountryField":              kRef,
	"ProtocolField":             kRef,
	"CSVListField":              kList,
	"AutoNumberField":           kString,
}

// Tail types that are never configuration.
var skipTypes = map[string]bool{"JsonAuditField": true, "LegacyLinkField": true}

func field(n *xmlNode, typ string, fs FieldSpec, container string) (*Field, error) {
	name := n.XMLName.Local
	f := &Field{XML: name, Attr: fs.Attr, Computed: fs.Computed, Sensitive: fs.Sensitive,
		Desc: fs.Description, FakeValue: fs.FakeValue}
	if f.Attr == "" {
		f.Attr = snake(name)
		if container != "" {
			f.Attr = snake(container) + "_" + snake(name)
		}
	}
	if container != "" {
		f.XML, f.Container, f.ContainerGo = container+"."+name, container, camel(container)
	}
	if reservedAttrs[f.Attr] {
		return nil, fmt.Errorf("attribute name %q is reserved in Terraform; set fields.%s.attr", f.Attr, f.XML)
	}
	f.Go = goName(f.Attr)
	if container != "" {
		f.Go = goName(snake(name)) // inside the container's struct
	}
	if fs.GoName != "" {
		f.Go = fs.GoName
	}
	f.InTF = fs.TF == nil || *fs.TF
	f.TFComputed, f.TFUnstable, f.NoDefault, f.WriteOnly = fs.TFComputed, fs.TFUnstable, fs.NoDefault, fs.WriteOnly
	f.ForceRequired, f.Invert, f.Values = fs.Required, fs.Invert, fs.Values
	f.Validators, f.PlanMods = fs.Validators, fs.PlanModifiers
	if fs.AsBool != nil {
		f.AsTrue, f.AsFalse = fs.AsBool["true"], fs.AsBool["false"]
		if f.AsTrue == f.AsFalse || len(fs.AsBool) != 2 {
			return nil, fmt.Errorf("as_bool needs distinct \"true\" and \"false\" values")
		}
	}
	if fs.Sensitive {
		f.Desc = strings.TrimSpace(f.Desc + " Write-only for MCP: never returned.")
	}

	kind := fs.Type
	if kind == "" {
		if skipTypes[typ] {
			return nil, fmt.Errorf("type %s is not configuration; skip it", typ)
		}
		k, ok := xmlTypes[strings.TrimPrefix(typ, ".\\")]
		if !ok || strings.HasPrefix(typ, ".") {
			return nil, fmt.Errorf("custom or unknown type %s: set fields.%s.type", typ, f.XML)
		}
		kind = k
		if typ == "UpdateOnlyTextField" {
			f.Sensitive, f.UpdateOnly = true, true
		}
		if typ == "AutoNumberField" {
			f.Computed = true
		}
	}
	multiple := n.value("Multiple") == "Y"
	asList := n.value("AsList") == "Y"
	switch {
	case kind == kOption && multiple:
		kind = kOptions
	case kind == kRef && multiple:
		kind = kRefs
	case kind == kString && asList:
		kind = kList
	}
	switch kind {
	case kBool, kInt, kString, kOption, kOptions, kRef, kRefs, kList:
	default:
		return nil, fmt.Errorf("unknown type override %q", kind)
	}
	f.Kind = kind
	f.Sep = ","
	if sep := n.value("FieldSeparator"); sep != "" {
		f.Sep = sep
	}
	if fs.Sep != "" {
		f.Sep = fs.Sep
	}

	f.APIRequired = n.value("Required") == "Y"
	if d := n.child("Default"); d != nil {
		f.Default, f.HasDefault = strings.TrimSpace(d.Text), true
		f.XMLDefault, f.XMLHasDefault = f.Default, true
	}
	if kind == kOption || kind == kOptions {
		f.Choices = fs.Choices
		if f.Choices == nil {
			f.Choices = optionValues(n.child("OptionValues"))
		}
		if len(f.Choices) == 0 {
			return nil, fmt.Errorf("option field without OptionValues; use type ref or set choices")
		}
		// Some models ship a default that is not one of their options (Syslog transport
		// "udp" vs udp4/udp6). OPNsense rejects it on save, so treat the field as having none.
		if f.HasDefault && f.Default != "" {
			for _, d := range strings.Split(f.Default, f.Sep) {
				if !containsStr(f.Choices, d) {
					f.Desc = strings.TrimSpace(f.Desc + fmt.Sprintf(" (The model default %q is not a valid option.)", f.Default))
					f.Default, f.HasDefault = "", false
					break
				}
			}
		}
	}
	if kind == kInt {
		lo, hi := n.value("MinimumValue"), n.value("MaximumValue")
		if lo != "" || hi != "" {
			f.HasRange, f.Min, f.Max = true, 0, 1<<53
			if v, err := strconv.ParseInt(lo, 10, 64); err == nil {
				f.Min = v
			}
			if v, err := strconv.ParseInt(hi, 10, 64); err == nil {
				f.Max = v
			}
		}
		if f.HasDefault {
			if _, err := strconv.ParseInt(f.Default, 10, 64); err != nil && f.Default != "" {
				return nil, fmt.Errorf("integer default %q", f.Default)
			}
			if f.Default == "" {
				f.HasDefault = false
			}
		}
	}
	if m := n.value("Mask"); m != "" && (kind == kString || kind == kList) {
		f.Mask = translateMask(m)
	}
	if cs := n.child("Constraints"); cs != nil {
		for i := range cs.Children {
			c := &cs.Children[i]
			if c.value("type") != "UniqueConstraint" {
				continue
			}
			f.Unique = true
			if add := c.child("addFields"); add != nil {
				for j := range add.Children {
					f.UniqueWith = append(f.UniqueWith, strings.TrimSpace(add.Children[j].Text))
				}
			}
		}
	}
	if fs.Default != nil {
		f.Default, f.HasDefault = *fs.Default, true
	}
	switch fs.TFType {
	case "":
		f.TFAsList = f.Kind == kList
	case "list":
		f.TFAsList = true
	case "set":
	default:
		return nil, fmt.Errorf("tf_type must be set or list")
	}
	if f.Computed {
		f.Mask = ""
		if f.isList() && f.InTF {
			return nil, fmt.Errorf("computed list fields are client-only; set tf: false")
		}
		if !f.isList() {
			f.Kind = kString
		}
	}
	if !f.InTF && !f.Computed {
		return nil, fmt.Errorf("tf: false would clear the field on every write; only computed fields can be left out")
	}
	if f.Invert && f.Kind != kBool {
		return nil, fmt.Errorf("invert needs a boolean field")
	}
	if f.AsTrue != "" && f.Kind != kOption && f.Kind != kString {
		return nil, fmt.Errorf("as_bool needs a single-value field")
	}
	for tf, api := range f.Values {
		if f.Kind == kOption && !containsStr(f.Choices, api) {
			return nil, fmt.Errorf("values: %q maps to %q, which is not an option", tf, api)
		}
	}
	return f, nil
}

// translateMask turns a PHP (PCRE) mask like /^[a-z]+$/u into Go syntax, or "" when RE2
// cannot express it (look-arounds, back references) or uses unknown flags.
func translateMask(m string) string {
	if len(m) < 2 || m[0] != '/' {
		return ""
	}
	end := strings.LastIndex(m, "/")
	if end <= 0 {
		return ""
	}
	pattern, flags := m[1:end], m[end+1:]
	prefix := ""
	for _, fl := range flags {
		switch fl {
		case 'u':
		case 'i', 's', 'm':
			prefix += string(fl)
		default:
			return ""
		}
	}
	if prefix != "" {
		pattern = "(?" + prefix + ")" + pattern
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return ""
	}
	return pattern
}

// optionValues returns the stored values of an OptionValues block, in XML order. A value
// attribute wins over the element name; option groups are flattened.
func optionValues(n *xmlNode) []string {
	if n == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	var walk func(*xmlNode)
	walk = func(n *xmlNode) {
		for i := range n.Children {
			c := &n.Children[i]
			if len(c.Children) > 0 { // an option group; its value attribute is the label
				walk(c)
				continue
			}
			v := c.XMLName.Local
			for _, a := range c.Attrs {
				if a.Name.Local == "value" {
					v = a.Value
				}
			}
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	walk(n)
	return out
}

var reservedAttrs = map[string]bool{
	"id": true, "count": true, "for_each": true, "provider": true, "lifecycle": true,
	"depends_on": true, "connection": true, "provisioner": true, "source": true, "version": true,
}

// Attribute renames applied to every model.
var globalRenames = map[string]string{"descr": "description"}

// snake turns an XML name into a Terraform attribute name: FromDomain -> from_domain.
func snake(s string) string {
	if r, ok := globalRenames[s]; ok {
		return r
	}
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		if unicode.IsUpper(r) {
			prevLower := i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]))
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			prevUpper := i > 0 && unicode.IsUpper(rs[i-1])
			if i > 0 && rs[i-1] != '_' && (prevLower || (prevUpper && nextLower)) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		if r == '-' || r == '.' {
			r = '_'
		}
		b.WriteRune(r)
	}
	return b.String()
}

var initialisms = map[string]string{
	"id": "ID", "ip": "IP", "url": "URL", "uri": "URI", "uuid": "UUID", "dns": "DNS", "tls": "TLS",
	"http": "HTTP", "https": "HTTPS", "mac": "MAC", "mtu": "MTU", "tcp": "TCP", "udp": "UDP",
	"api": "API", "vlan": "VLAN", "vhid": "VHID", "ttl": "TTL", "cpu": "CPU", "ssh": "SSH",
	"ntp": "NTP", "nat": "NAT", "vip": "VIP", "pcp": "PCP", "acl": "ACL", "ipv4": "IPv4", "ipv6": "IPv6",
	"ips": "IPs", "ids": "IDs", "mx": "MX", "txt": "TXT", "ptr": "PTR", "rr": "RR", "psk": "PSK", "ca": "CA", "eab": "EAB", "hmac": "HMAC",
}

// goName turns an attribute into an exported Go name: parent_interface -> ParentInterface.
func goName(attr string) string {
	var b strings.Builder
	for _, p := range strings.Split(attr, "_") {
		if p == "" {
			continue
		}
		if up, ok := initialisms[p]; ok {
			b.WriteString(up)
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	s := b.String()
	if s == "" || unicode.IsDigit(rune(s[0])) {
		s = "F" + s
	}
	return s
}

// camel turns a resource or area name into a Go type name: syslog_destination -> SyslogDestination.
func camel(s string) string { return goName(snake(s)) }

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	// Keep leading initialisms readable: VLAN -> vlan, VIPAddress -> vipAddress.
	rs := []rune(s)
	i := 0
	for i < len(rs) && unicode.IsUpper(rs[i]) {
		i++
	}
	if i > 1 && i < len(rs) {
		i--
	}
	return strings.ToLower(string(rs[:i])) + string(rs[i:])
}

func containsStr(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

// settingsID is the constant Terraform id of a settings resource.
func (o *Object) settingsID() string {
	if o.ID != "" {
		return o.ID
	}
	return o.Resource
}
