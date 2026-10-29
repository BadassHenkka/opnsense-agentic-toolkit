package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGeneratedUpToDate fails when gen/specs, gen/models or the generator changed without
// regenerating (task gen).
func TestGeneratedUpToDate(t *testing.T) {
	root := filepath.Join("..", "..")
	files, err := generate(root)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := writeFiles(root, files, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) > 0 {
		t.Fatalf("generated files are out of date, run `task gen`: %s", strings.Join(stale, ", "))
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"FromDomain": "from_domain", "descr": "description", "subnet_bits": "subnet_bits",
		"HttpTls": "http_tls", "TLSServer": "tls_server", "peer6": "peer6", "vlanif": "vlanif",
	} {
		if got := snake(in); got != want {
			t.Errorf("snake(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"parent": "Parent", "subnet_bits": "SubnetBits", "vhid": "VHID", "max_file_size": "MaxFileSize",
		"tls_server_name": "TLSServerName", "1to1": "F1to1",
	} {
		if got := goName(in); got != want {
			t.Errorf("goName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := lowerFirst("VLAN"); got != "vlan" {
		t.Errorf("lowerFirst(VLAN) = %q", got)
	}
}

func TestTranslateMask(t *testing.T) {
	for in, want := range map[string]string{
		`/^[a-z]+$/u`:         `^[a-z]+$`,
		`/^a.b$/s`:            `(?s)^a.b$`,
		`/^(.){1,1023}$/s`:    "", // RE2 caps repeats at 1000
		`/^abc$/i`:            `(?i)^abc$`,
		`/^(?=x)y$/`:          "", // look-ahead: RE2 cannot
		`/^x$/x`:              "", // unknown flag
		`not-a-regex`:         "",
		`/^[0-9a-f]{6,6}$/u`:  `^[0-9a-f]{6,6}$`,
		`/^\/path\/[a-z]*$/u`: `^\/path\/[a-z]*$`,
	} {
		if got := translateMask(in); got != want {
			t.Errorf("translateMask(%q) = %q, want %q", in, got, want)
		}
	}
}

// OPNsense skips the mask for an empty value, so only a required field rejects "".
func TestMaskValidator(t *testing.T) {
	for required, want := range map[bool]string{
		false: `optionalMask(regexp.MustCompile("^0x[0-9a-f]*$"))`,
		true:  `stringvalidator.RegexMatches(regexp.MustCompile("^0x[0-9a-f]*$"), "must match the OPNsense model mask")`,
	} {
		f := &Field{XML: "ifid", Attr: "ifid", Kind: kString, Mask: "^0x[0-9a-f]*$", APIRequired: required, InTF: true}
		if got := schemaAttr(newW(), f); !strings.Contains(got, want) {
			t.Errorf("required=%v: %s, want %s", required, got, want)
		}
	}
}

const testModel = `<model><items>
  <thing type="ArrayField">
    <name type="TextField"><Required>Y</Required>
      <Constraints><check001><type>UniqueConstraint</type></check001></Constraints></name>
    <mode type="OptionField"><Default>b</Default><OptionValues><a/><bee value="b">B</bee>
      <grp><c value="c"/></grp></OptionValues></mode>
    <tags type="OptionField"><Multiple>Y</Multiple><OptionValues><x/><y/></OptionValues></tags>
    <hosts type="HostnameField"><AsList>Y</AsList></hosts>
    <port type="IntegerField"><MinimumValue>1</MinimumValue><MaximumValue>10</MaximumValue></port>
    <secret type="UpdateOnlyTextField"/>
    <link type=".\CustomField"/>
    <state type="TextField" volatile="true"/>
    <nested><x type="TextField"/></nested>
  </thing>
</items></model>`

func writeTestSpec(t *testing.T, spec string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	specs, models := filepath.Join(dir, "specs"), filepath.Join(dir, "models")
	for _, d := range []string{specs, filepath.Join(models, "core", "T")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(models, "core", "T", "T.xml"), []byte(testModel), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(specs, "t.json"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return specs, models
}

func TestResolveFields(t *testing.T) {
	specs, models := writeTestSpec(t, `{"area": "t", "title": "T", "items": [{
		"resource": "thing", "description": "d", "model": "core/T/T.xml", "node": "thing",
		"base": "t/thing", "key": "thing", "name_field": "name",
		"fields": {"link": {"type": "ref"}}}]}`)
	areas, err := loadSpecs(specs, models)
	if err != nil {
		t.Fatal(err)
	}
	o := areas[0].Items[0]
	kinds := map[string]string{}
	for _, f := range o.Fields {
		kinds[f.XML] = f.Kind
	}
	want := map[string]string{"name": kString, "mode": kOption, "tags": kOptions, "hosts": kList,
		"port": kInt, "secret": kString, "link": kRef}
	for k, v := range want {
		if kinds[k] != v {
			t.Errorf("%s: kind %q, want %q", k, kinds[k], v)
		}
	}
	if _, ok := kinds["state"]; ok {
		t.Error("volatile field generated")
	}
	if got := strings.Join(o.Skipped, ","); got != "state" {
		t.Errorf("skipped %q", got)
	}
	if nx := o.field("nested.x"); nx == nil || nx.Attr != "nested_x" || nx.GoPath() != "Nested.X" {
		t.Errorf("nested field %+v", nx)
	}
	mode := o.field("mode")
	if strings.Join(mode.Choices, ",") != "a,b,c" || mode.Default != "b" || mode.Required() {
		t.Errorf("mode %+v", mode)
	}
	if !o.field("name").Required() || !o.field("name").Unique {
		t.Error("name should be required and unique")
	}
	if !o.field("secret").Sensitive {
		t.Error("UpdateOnlyTextField should be sensitive")
	}
	if p := o.field("port"); !p.HasRange || p.Min != 1 || p.Max != 10 {
		t.Errorf("port range %+v", p)
	}
}

// Import-generated config writes a secret as null. The secret must keep its value then,
// not fall back to a default of "" that the next apply sends.
func TestSecretKeepsUnset(t *testing.T) {
	for _, writeOnly := range []bool{false, true} {
		specs, models := writeTestSpec(t, fmt.Sprintf(`{"area": "t", "title": "T", "items": [{
			"resource": "thing", "description": "d", "model": "core/T/T.xml", "node": "thing",
			"base": "t/thing", "key": "thing",
			"fields": {"link": {"type": "ref"}, "secret": {"write_only": %v}}}]}`, writeOnly))
		areas, err := loadSpecs(specs, models)
		if err != nil {
			t.Fatal(err)
		}
		f := areas[0].Items[0].field("secret")
		attr := schemaAttr(newW(), f)
		for _, want := range []string{"Optional: true, Computed: true", "Sensitive: true", "UseStateForUnknown()", "OPNsense ignores"} {
			if !strings.Contains(attr, want) {
				t.Errorf("write_only=%v: %s lacks %q", writeOnly, attr, want)
			}
		}
		if strings.Contains(attr, "Default:") {
			t.Errorf("write_only=%v: %s has a default", writeOnly, attr)
		}
		if stmt := fromAPIStmt(f); writeOnly && !strings.Contains(stmt, "IsNull()") {
			t.Errorf("write-only read does not fill a null value after import: %s", stmt)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	for name, tc := range map[string]struct{ fields, want string }{
		"custom type":   {`{}`, "custom or unknown type"},
		"unknown field": {`{"link": {"type": "ref"}, "nope": {}}`, `"nope"`},
		"reserved attr": {`{"link": {"type": "ref"}, "name": {"attr": "count"}}`, "reserved"},
		"duplicate":     {`{"link": {"type": "ref", "attr": "name"}}`, "both map"},
	} {
		t.Run(name, func(t *testing.T) {
			specs, models := writeTestSpec(t, `{"area": "t", "title": "T", "items": [{
				"resource": "thing", "description": "d", "model": "core/T/T.xml", "node": "thing",
				"base": "t/thing", "key": "thing", "fields": `+tc.fields+`}]}`)
			_, err := loadSpecs(specs, models)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

const mappingModel = `<model><items>
  <thing type="ArrayField">
    <disabled type="BooleanField"><Required>Y</Required><Default>0</Default></disabled>
    <tls type="OptionField"><Required>Y</Required><Default>0</Default><OptionValues><a value="0"/><b value="1"/></OptionValues></tls>
    <scheme type="OptionField"><Default>0</Default><OptionValues><x value="0"/><y value="1"/><z value="2"/></OptionValues></scheme>
    <peers type="ModelRelationField"><Multiple>Y</Multiple></peers>
    <state type="TextField" volatile="true"/>
    <plain type="TextField"/>
  </thing>
</items></model>`

func TestFieldMappings(t *testing.T) {
	dir := t.TempDir()
	specs, models := filepath.Join(dir, "specs"), filepath.Join(dir, "models", "core", "T")
	for _, d := range []string{specs, models} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(models, "T.xml"), []byte(mappingModel), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(specs, "t.json"), []byte(`{"area": "t", "title": "T", "items": [{
		"resource": "thing", "description": "d", "model": "core/T/T.xml", "node": "thing",
		"base": "t/thing", "key": "thing", "fields": {
			"disabled": {"attr": "enabled", "go_name": "Disabled", "invert": true},
			"tls": {"as_bool": {"true": "0", "false": "1"}},
			"scheme": {"values": {"http": "0", "https": "1", "h2c": "2"}},
			"peers": {"computed": true, "tf": false},
			"state": {"include": true, "computed": true},
			"plain": {"write_only": true, "no_default": true}
		}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	areas, err := loadSpecs(specs, filepath.Join(dir, "models"))
	if err != nil {
		t.Fatal(err)
	}
	o := areas[0].Items[0]
	en := o.field("disabled")
	if en.Attr != "enabled" || en.Go != "Disabled" || tfGo(en) != "Enabled" || !en.Invert {
		t.Errorf("enabled %+v", en)
	}
	if !strings.Contains(toAPIStmt(en), "opnsense.Bool(!m.Enabled.ValueBool())") || tfBool(en, en.Default) != true {
		t.Errorf("inverted bool: %s, default %v", toAPIStmt(en), tfBool(en, en.Default))
	}
	tls := o.field("tls")
	if tls.TFKind() != "bool" || !tfBool(tls, "0") || tfBool(tls, "1") {
		t.Errorf("as_bool %+v", tls)
	}
	sc := o.field("scheme")
	if sc.toTF("1") != "https" || !strings.Contains(fromAPIStmt(sc), "genMapValue") {
		t.Errorf("values: %q / %s", sc.toTF("1"), fromAPIStmt(sc))
	}
	if strings.Join(tfChoices(sc), ",") != "http,https,h2c" {
		t.Errorf("choices %v", tfChoices(sc))
	}
	if p := o.field("peers"); p == nil || p.InTF || clientType(p) != "ReadOnlyList" {
		t.Errorf("peers %+v", p)
	}
	if st := o.field("state"); st == nil || clientType(st) != "ReadOnly" {
		t.Error("included volatile field should be generated read-only")
	}
	if p := fromAPIStmt(o.field("plain")); !strings.Contains(p, "m.Plain.IsUnknown() || m.Plain.ValueString() == \"\"") {
		t.Errorf("write-only: %s", p)
	}
	if len(o.tfFields()) != 5 { // enabled, tls, scheme, state, plain
		t.Errorf("tf fields %d", len(o.tfFields()))
	}
}

func TestPluralize(t *testing.T) {
	for in, want := range map[string]string{"firewall category": "firewall categories", "ids policy": "ids policies",
		"gateway": "gateways", "neighbor": "neighbors", "postfix address": "postfix addresses", "kea dhcp4 pd pool": "kea dhcp4 pd pools",
		"relay": "relays", "trust ca": "trust cas"} {
		if got := pluralize(in); got != want {
			t.Errorf("pluralize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRowsHaveNoSecrets: MCP list tools hand search rows to the model as they are, and OPNsense
// returns secret columns in them, so a generated Row must never carry a sensitive field.
func TestRowsHaveNoSecrets(t *testing.T) {
	root := filepath.Join("..", "..")
	areas, err := loadSpecs(filepath.Join(root, "gen", "specs"), filepath.Join(root, "gen", "models"))
	if err != nil {
		t.Fatal(err)
	}
	sensitive := 0
	for _, a := range areas {
		src := emitClient(a)
		for _, o := range a.Items {
			start := strings.Index(src, "type "+o.Go+"Row struct {")
			if start < 0 {
				t.Fatalf("%s: no Row struct", o.Go)
			}
			row := src[start : start+strings.Index(src[start:], "\n}")]
			for _, f := range o.Fields {
				if !f.Sensitive || f.Container != "" {
					continue
				}
				sensitive++
				if strings.Contains(row, "json:"+`"`+f.XML+`"`) {
					t.Errorf("%sRow has the sensitive field %q", o.Go, f.XML)
				}
			}
		}
	}
	if sensitive < 10 {
		t.Fatalf("only %d sensitive fields found; the check is not exercising the specs", sensitive)
	}
}
