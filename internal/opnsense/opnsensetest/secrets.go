package opnsensetest

import "sort"

// SeedSecrets stores one item per collection, and sets the settings sections, with a distinct
// marker in every Sensitive field. It returns the markers. A test then drives a front end and
// fails if any marker shows up in what it returns to the user.
func (s *Server) SeedSecrets(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var markers []string
	mark := func(id string, fields map[string]Field, rec Record) {
		for _, name := range sortedFieldNames(fields) {
			if fields[name].Sensitive {
				m := prefix + id + "." + name
				rec[name] = m
				markers = append(markers, m)
			}
		}
	}
	for _, c := range s.collections {
		if c.Base == "" || !hasSensitive(c.Fields) {
			continue
		}
		id := "secret-" + c.Key
		rec := Record{}
		for k, f := range c.Fields {
			rec[k] = f.Default
		}
		mark(c.Base+"/"+c.Key, c.Fields, rec)
		c.items[id] = rec
	}
	for get, g := range s.settings {
		for name, sec := range g.sections {
			mark(get+"/"+name, sec.fields, sec.rec)
		}
	}
	sort.Strings(markers)
	return markers
}

func hasSensitive(fields map[string]Field) bool {
	for _, f := range fields {
		if f.Sensitive {
			return true
		}
	}
	return false
}

func sortedFieldNames(fields map[string]Field) []string {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
