package opnsensetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Generic helpers used by generated areas (zz_gen_*.go).

// checkFields applies the model rules every OPNsense field type enforces: required fields,
// option membership for static option lists, and integer ranges. Keys are "<key>.<field>".
func checkFields(s *Server, key string, fields map[string]Field, r Record) map[string]string {
	v := map[string]string{}
	for name, f := range fields {
		val := r[name]
		if val == "" {
			if f.Required {
				v[key+"."+name] = "This field is required."
			}
			continue
		}
		if f.Kind == Option && f.Choices != nil {
			choices := map[string]bool{}
			for _, c := range f.Choices(s) {
				choices[c] = true
			}
			for _, p := range split(val, f.Sep) {
				if !choices[p] {
					v[key+"."+name] = "Option not in list."
				}
			}
		}
		if f.Mask != "" && !regexp.MustCompile(f.Mask).MatchString(val) {
			v[key+"."+name] = "Value does not match the field's mask."
		}
		if f.HasRange {
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n < f.Min || n > f.Max {
				v[key+"."+name] = fmt.Sprintf("Value should be between %d and %d.", f.Min, f.Max)
			}
		}
	}
	return v
}

// settingsGroup is every settings section served by one get/set endpoint pair.
type settingsGroup struct {
	root     string
	sections map[string]*settingsSection
}

type settingsSection struct {
	fields   map[string]Field
	rec      Record
	validate func(s *Server, r Record) map[string]string
}

// addSettings serves a settings section at get/set, under {"<root>": {"<section>": {...}}}.
// Several sections can share an endpoint pair; get returns all of them, like OPNsense.
func (s *Server) addSettings(get, set, root, section string, fields map[string]Field,
	validate func(*Server, Record) map[string]string) {
	g, ok := s.settings[get]
	if !ok {
		g = &settingsGroup{root: root, sections: map[string]*settingsSection{}}
		s.settings[get] = g
		s.extra[get] = func(s *Server, w http.ResponseWriter, _ *http.Request, _ string) {
			out := map[string]any{}
			for name, sec := range g.sections {
				if name == "" { // fields directly below the root
					for k, v := range renderFields(s, sec.fields, sec.rec) {
						out[k] = v
					}
					continue
				}
				out[name] = renderFields(s, sec.fields, sec.rec)
			}
			writeJSON(w, map[string]any{g.root: out})
		}
		s.extra[set] = func(s *Server, w http.ResponseWriter, r *http.Request, _ string) {
			var body map[string]map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sections := map[string]map[string]any{}
			flat := map[string]any{}
			for name, v := range body[g.root] {
				if m, ok := v.(map[string]any); ok && g.sections[name] != nil && name != "" {
					sections[name] = m
				} else {
					flat[name] = v
				}
			}
			if _, ok := g.sections[""]; ok {
				sections[""] = flat // fields directly below the root, next to any named sections
			}
			staged := map[string]Record{}
			validations := map[string]string{}
			for name, posted := range sections {
				sec, ok := g.sections[name]
				if !ok {
					continue // OPNsense ignores unknown sections
				}
				prefix := g.root
				if name != "" {
					prefix += "." + name
				}
				rec, ok := decodeFields(w, prefix, sec.fields, posted)
				if !ok {
					return
				}
				merged := Record{}
				for k, v := range sec.rec {
					merged[k] = v
				}
				for k, v := range rec {
					merged[k] = v
				}
				for k, msg := range checkFields(s, prefix, sec.fields, merged) {
					validations[k] = msg
				}
				if sec.validate != nil {
					for k, msg := range sec.validate(s, merged) {
						validations[k] = msg
					}
				}
				staged[name] = merged
			}
			if len(validations) > 0 {
				writeJSON(w, map[string]any{"result": "failed", "validations": validations})
				return
			}
			for name, rec := range staged {
				g.sections[name].rec = rec
			}
			writeJSON(w, map[string]any{"result": "saved"})
		}
	}
	rec := Record{}
	for k, f := range fields {
		rec[k] = f.Default
	}
	g.sections[section] = &settingsSection{fields: fields, rec: rec, validate: validate}
}

// Settings returns a copy of a settings section served at get, e.g.
// Settings("syslog/settings/get", "general").
func (s *Server) Settings(get, section string) Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := Record{}
	if g, ok := s.settings[get]; ok {
		if sec, ok := g.sections[section]; ok {
			for k, v := range sec.rec {
				cp[k] = v
			}
		}
	}
	return cp
}

// computedOnAdd fills a field the server computes when an item is created (e.g. a VLAN's
// device name), from a pattern with %d replaced by a running number.
func computedOnAdd(c *Collection, field, pattern string) func(*Server, string, Record) {
	return func(s *Server, uuid string, posted Record) {
		if _, exists := c.items[uuid]; exists {
			return
		}
		posted[field] = strings.ReplaceAll(pattern, "%d", strconv.Itoa(len(c.items)))
	}
}

// checkUnique adds a validation error when another item has the same value in field (and in
// every field of with), like OPNsense's UniqueConstraint.
func checkUnique(c *Collection, self string, r Record, v map[string]string, key, field string, with ...string) {
	if r[field] == "" {
		return
	}
	for id, other := range c.items {
		if id == self || other[field] != r[field] {
			continue
		}
		same := true
		for _, w := range with {
			same = same && other[w] == r[w]
		}
		if same {
			v[key+"."+field] = "Should be a unique value."
			return
		}
	}
}

// collection returns the generated collection with this base and key. Hand-written register
// functions use it to add behaviour a spec cannot describe (cross-item checks, cascades,
// fixed option lists for the fake's interfaces).
func (s *Server) collection(base, key string) *Collection {
	for _, c := range s.collections {
		if c.Base == base && c.Key == key {
			return c
		}
	}
	panic("opnsensetest: no collection " + base + " " + key + "; run make gen")
}

// alsoValidate chains an extra check after a collection's existing validation.
func alsoValidate(c *Collection, extra func(s *Server, self string, r Record) map[string]string) {
	prev := c.Validate
	c.Validate = func(s *Server, self string, r Record) map[string]string {
		v := map[string]string{}
		if prev != nil {
			v = prev(s, self, r)
		}
		for k, msg := range extra(s, self, r) {
			v[k] = msg
		}
		return v
	}
}

// settingsRec returns the live record of a settings section, for handlers that run with the
// server lock held (Settings takes the lock itself).
func (s *Server) settingsRec(get, section string) Record {
	if g, ok := s.settings[get]; ok {
		if sec, ok := g.sections[section]; ok {
			return sec.rec
		}
	}
	return Record{}
}
