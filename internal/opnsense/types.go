package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// OPNsense models return option fields differently on read and write:
//
//	getItem:  "type": {"host": {"value": "Host(s)", "selected": 1}, "network": {...}}
//	setItem:  "type": "host"
//
// The types in this file accept both forms when decoding and always encode the write form,
// so one Go struct serves as both the request and the response model.

// Bool is an OPNsense boolean, sent as "1" or "0".
type Bool bool

func (b Bool) MarshalJSON() ([]byte, error) {
	if b {
		return []byte(`"1"`), nil
	}
	return []byte(`"0"`), nil
}

func (b *Bool) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		var n int
		if err2 := json.Unmarshal(data, &n); err2 != nil {
			return fmt.Errorf("opnsense: cannot decode %s as bool", data)
		}
		*b = Bool(n != 0)
		return nil
	}
	*b = Bool(s == "1" || strings.EqualFold(s, "true"))
	return nil
}

// Option is a single-select field.
type Option string

func (o *Option) UnmarshalJSON(data []byte) error {
	sel, err := decodeSelection(data, ",")
	if err != nil {
		return err
	}
	*o = Option(strings.Join(sel, ","))
	return nil
}

// CSVList is a multi-select or list field written as a comma-separated string.
type CSVList []string

func (l CSVList) MarshalJSON() ([]byte, error) { return json.Marshal(strings.Join(l, ",")) }

func (l *CSVList) UnmarshalJSON(data []byte) error {
	sel, err := decodeSelection(data, ",")
	*l = sel
	return err
}

// LineList is a list field written as a newline-separated string (e.g. alias content).
type LineList []string

func (l LineList) MarshalJSON() ([]byte, error) { return json.Marshal(strings.Join(l, "\n")) }

func (l *LineList) UnmarshalJSON(data []byte) error {
	sel, err := decodeSelection(data, "\n")
	*l = sel
	return err
}

type optionEntry struct {
	Value    string          `json:"value"`
	Selected json.RawMessage `json:"selected"`
}

func (e optionEntry) isSelected() bool {
	s := string(bytes.Trim(e.Selected, `"`))
	return s == "1" || s == "true"
}

// decodeSelection returns the selected keys of an option map, or splits a plain string.
func decodeSelection(data []byte, sep string) ([]string, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	switch data[0] {
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return splitNonEmpty(s, sep), nil
	case '[': // OPNsense encodes an empty option map as []
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, err
		}
		if len(arr) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("opnsense: unexpected list value %s", truncate(string(data), 80))
	case '{':
		var m map[string]optionEntry
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		var out []string
		for k, e := range m {
			if e.isSelected() {
				out = append(out, k)
			}
		}
		sort.Strings(out) // map order is random; callers that care about order use the string form
		return out, nil
	default:
		return nil, fmt.Errorf("opnsense: unexpected option value %s", truncate(string(data), 80))
	}
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Int is an optional integer field. OPNsense sends "" when it is unset.
type Int struct {
	Value int64
	Valid bool
}

// IntOf returns a set Int.
func IntOf(v int64) Int { return Int{Value: v, Valid: true} }

func (i Int) MarshalJSON() ([]byte, error) {
	if !i.Valid {
		return []byte(`""`), nil
	}
	return json.Marshal(strconv.FormatInt(i.Value, 10))
}

func (i *Int) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if s == "" || s == "null" {
		*i = Int{}
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("opnsense: cannot decode %s as integer", data)
	}
	*i = IntOf(v)
	return nil
}

// Text is a string field in search rows. It also accepts numbers and booleans, since
// search output is not typed consistently across OPNsense versions.
type Text string

func (t *Text) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*t = Text(s)
		return nil
	}
	switch v := strings.TrimSpace(string(data)); v {
	case "null":
		*t = ""
	case "true":
		*t = "1"
	case "false":
		*t = "0"
	default:
		if len(v) > 0 && (v[0] == '{' || v[0] == '[') {
			*t = "" // structured values are not meaningful in a row summary
		} else {
			*t = Text(v)
		}
	}
	return nil
}

// ReadOnly is a field OPNsense maintains itself, such as a status code or timestamp. It is
// decoded on read and never sent on write: with an `omitzero` tag, IsZero always reports
// true, so encoding/json skips it.
type ReadOnly string

// IsZero makes `omitzero` drop the field when encoding.
func (ReadOnly) IsZero() bool { return true }

func (r *ReadOnly) UnmarshalJSON(data []byte) error {
	var t Text
	err := t.UnmarshalJSON(data)
	*r = ReadOnly(t)
	return err
}

// Params holds model fields that are not part of a Go struct, such as the provider-specific
// settings of an ACME challenge type. Values are in write form (strings); option fields are
// reduced to their selected key(s), comma-separated.
type Params map[string]string

// marshalWithParams encodes known (a struct) and adds params for keys known does not use.
func marshalWithParams(known any, params Params) ([]byte, error) {
	data, err := json.Marshal(known)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	for k, v := range params {
		if _, taken := m[k]; !taken {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// unmarshalWithParams decodes data into known (a pointer to a struct) and returns every
// other field as Params. skip lists keys to drop entirely, such as internal ids.
func unmarshalWithParams(data []byte, known any, skip ...string) (Params, error) {
	if err := json.Unmarshal(data, known); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	taken := jsonFieldNames(known)
	for _, k := range skip {
		taken[k] = true
	}
	params := Params{}
	for k, v := range raw {
		if taken[k] {
			continue
		}
		sel, err := decodeSelection(v, ",")
		if err != nil {
			// Not a scalar or option map (e.g. a nested structure): skip rather than fail.
			continue
		}
		params[k] = strings.Join(sel, ",")
	}
	return params, nil
}

// jsonFieldNames returns the JSON names of a struct's fields.
func jsonFieldNames(v any) map[string]bool {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	names := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names[name] = true
	}
	return names
}

// DecodeTemplate reduces a raw template (see ItemController.Template) to defaults in write
// form and, for option fields, the available choices.
func DecodeTemplate(raw map[string]json.RawMessage) (defaults Params, choices map[string][]string) {
	defaults, choices = Params{}, map[string][]string{}
	for k, v := range raw {
		sel, err := decodeSelection(v, ",")
		if err != nil {
			continue
		}
		defaults[k] = strings.Join(sel, ",")
		var m map[string]optionEntry
		if json.Unmarshal(v, &m) == nil && len(m) > 0 {
			keys := make([]string, 0, len(m))
			for key := range m {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			choices[k] = keys
		}
	}
	return defaults, choices
}

// ReadOnlyList is a list field OPNsense maintains, decoded like CSVList and never encoded
// (see ReadOnly).
type ReadOnlyList []string

// IsZero makes `omitzero` drop the field when encoding.
func (ReadOnlyList) IsZero() bool { return true }

func (l *ReadOnlyList) UnmarshalJSON(data []byte) error {
	sel, err := decodeSelection(data, ",")
	*l = sel
	return err
}
