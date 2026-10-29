// Package opnsensetest is an in-memory fake of the OPNsense API for tests. It mimics the
// JSON shapes the real API uses: wrapped writes, option maps on read, [] for an unknown
// uuid, and validation failures returned with HTTP 200.
//
// Each API area is declared as a Collection in collections.go.
package opnsensetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const (
	Key    = "test-key"
	Secret = "test-secret"
)

// Record is an item in write form: every field is a string.
type Record map[string]string

// FieldKind says how a field is rendered by get<Item>.
type FieldKind int

const (
	// Text fields are returned as-is.
	Text FieldKind = iota
	// Option fields become an option map over Choices, with the stored value(s) selected.
	Option
	// List fields become an option map whose keys are the stored entries.
	List
)

// Field describes one model field.
type Field struct {
	Kind FieldKind
	// Sep separates multiple values for Option and List fields ("," or "\n").
	Sep string
	// Choices returns the options for an Option field. It runs with the server lock held.
	Choices func(s *Server) []string
	// Default is stored when an add request omits the field.
	Default string
	// Required fields must not be empty (checked by checkFields).
	Required bool
	// Min and Max bound integer fields when HasRange is set.
	Min, Max int64
	HasRange bool
	// Mask is a Go regexp a non-empty value must match.
	Mask string
	// Virtual computes a volatile field on read (it is never stored), e.g. a WireGuard
	// peer's instances, which live on the instances.
	Virtual func(s *Server, uuid string) string
	// ReadOnly fields are maintained by OPNsense (status, timestamps). A client that sends
	// one gets HTTP 400, so tests catch writes that would clobber them.
	ReadOnly bool
	// Sensitive fields hold credentials. SeedSecrets fills them so tests can check that
	// no front end shows them.
	Sensitive bool
}

// Collection is one OPNsense model array served under Base with the <action><Suffix> pattern.
type Collection struct {
	Base   string // e.g. "firewall/alias"
	Suffix string // "Item", "HostOverride", ...
	// Actions overrides whole action names by canonical verb, e.g. {"set": "update"}.
	Actions map[string]string
	Key     string // request/response wrapper, e.g. "alias"
	Fields  map[string]Field
	// Validate returns field errors keyed like "alias.name"; self is "" on add.
	Validate func(s *Server, self string, r Record) map[string]string
	// EmptyDelete makes del<Item> answer with an empty body, like os-wol's delHost.
	EmptyDelete bool
	// CanDelete returns a message when an item must not be deleted (it is in use). The fake
	// then answers like a UserException: HTTP 400 with {"errorMessage": ...}.
	CanDelete func(s *Server, uuid string) string
	// OnDelete runs after an item is removed, e.g. to cascade deletes.
	OnDelete func(s *Server, uuid string)
	// ExtraRows are appended to search results, e.g. automatic/legacy firewall rules that
	// are not part of the model.
	ExtraRows func(s *Server) []map[string]string
	// SearchFilter, when set, limits search results like a controller's filter function,
	// e.g. Unbound's searchForward lists only query forwarding servers.
	SearchFilter func(rec Record) bool
	// OnWrite runs on add and set with the posted fields, before they are stored. It may
	// remove volatile fields from posted after acting on them.
	OnWrite func(s *Server, uuid string, posted Record)
	// NewID picks the id of an added item instead of a UUID, e.g. "opt3" for interface
	// assignments.
	NewID func(s *Server, rec Record) string

	items map[string]Record
}

// Server is a fake OPNsense.
type Server struct {
	*httptest.Server

	mu          sync.Mutex
	collections []*Collection
	// Leases are the rows dnsmasq/leases/search returns.
	Leases []map[string]string
	// KeaLeases4 and KeaLeases6 are the rows kea/leases4|6/search return.
	KeaLeases4, KeaLeases6 []map[string]string

	extra       map[string]func(s *Server, w http.ResponseWriter, r *http.Request, arg string)
	reconfigure map[string]bool
	// reconfigureStatus overrides the status a reconfigure path answers with.
	reconfigureStatus map[string]string
	nextID            int

	// Applies counts reconfigure calls per path, e.g. Applies["unbound/service/reconfigure"].
	Applies map[string]int
	// InUse marks uuids that refuse deletion, like an alias used by a firewall rule.
	InUse      map[string]bool
	operations []string
	// LockOutAfter makes every request fail with 503 once the named apply path has been
	// called, to simulate firewall rules that cut off the API client.
	LockOutAfter string
	lockedOut    bool
	firmware     *firmwareState
	wakes        []string
	settings     map[string]*settingsGroup
}

// Operations returns the calls made to non-CRUD endpoints, e.g.
// "acmeclient/certificates/sign/<uuid>".
func (s *Server) Operations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.operations...)
}

// AcmeSettings returns a copy of the stored ACME settings (write form).
func (s *Server) AcmeSettings() Record { return s.Settings("acmeclient/settings/get", "settings") }

// New starts a fake server with every known collection. It is closed when the test ends.
func New(t testing.TB) *Server {
	s := &Server{
		extra:             map[string]func(*Server, http.ResponseWriter, *http.Request, string){},
		reconfigure:       map[string]bool{},
		reconfigureStatus: map[string]string{},
		Applies:           map[string]int{},
		InUse:             map[string]bool{},
		settings:          map[string]*settingsGroup{},
	}
	registerAll(s)
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) add(c *Collection) *Collection {
	c.items = map[string]Record{}
	s.collections = append(s.collections, c)
	return c
}

// Client returns an opnsense.Client pointed at the fake.
func (s *Server) Client(t testing.TB) *opnsense.Client {
	t.Helper()
	c, err := opnsense.NewClient(s.Config())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Config returns a client config for the fake.
func (s *Server) Config() opnsense.Config {
	return opnsense.Config{URL: s.URL, APIKey: Key, APISecret: Secret, HTTPClient: s.Server.Client()}
}

// Get returns a copy of a stored record by collection key ("alias", "host", ...) and uuid.
func (s *Server) Get(key, uuid string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.collections {
		if c.Key == key && c.Base != "" {
			if r, ok := c.items[uuid]; ok {
				cp := Record{}
				for k, v := range r {
					cp[k] = v
				}
				return cp, true
			}
		}
	}
	return nil, false
}

// TotalApplies sums reconfigure calls across services.
func (s *Server) TotalApplies() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range s.Applies {
		n += v
	}
	return n
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if k, sec, ok := r.BasicAuth(); !ok || k != Key || sec != Secret {
		http.Error(w, `{"status":401,"message":"Authentication Failed"}`, http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet && r.Header.Get("Content-Type") != "" {
		http.Error(w, "GET with Content-Type", http.StatusBadRequest)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/")

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lockedOut {
		http.Error(w, "connection blocked", http.StatusServiceUnavailable)
		return
	}
	if s.reconfigure[path] && r.Method == http.MethodPost {
		s.Applies[path]++
		if path == s.LockOutAfter {
			s.lockedOut = true
		}
		status := "ok"
		if st, ok := s.reconfigureStatus[path]; ok {
			status = st
		}
		writeJSON(w, map[string]string{"status": status})
		return
	}
	for prefix, h := range s.extra {
		if rest, ok := strings.CutPrefix(path, prefix); ok && (rest == "" || rest[0] == '/') {
			h(s, w, r, strings.TrimPrefix(rest, "/"))
			return
		}
	}
	for _, c := range s.collections {
		rest, ok := strings.CutPrefix(path, c.Base+"/")
		if !ok {
			continue
		}
		action, arg, _ := strings.Cut(rest, "/")
		verb := c.verbFor(action)
		if verb == "" {
			continue
		}
		if c.serve(s, verb, arg, w, r) {
			return
		}
	}
	http.NotFound(w, r)
}

// verbFor maps an action name to its canonical verb, or "" if the collection has no such action.
func (c *Collection) verbFor(action string) string {
	for _, v := range []string{"add", "get", "set", "del", "search"} {
		name, ok := c.Actions[v]
		if !ok {
			suffix := c.Suffix
			if suffix == "" {
				suffix = "Item"
			}
			name = v + suffix
		}
		if name == action {
			return v
		}
	}
	return ""
}

// Defaults returns a new record with every field's default.
func (c *Collection) Defaults() Record {
	r := Record{}
	for name, f := range c.Fields {
		r[name] = f.Default
	}
	return r
}

func (c *Collection) serve(s *Server, verb, arg string, w http.ResponseWriter, r *http.Request) bool {
	switch {
	case verb == "add" && r.Method == http.MethodPost:
		rec, ok := c.decode(w, r)
		if !ok {
			return true
		}
		for name, f := range c.Fields {
			if _, set := rec[name]; !set {
				rec[name] = f.Default
			}
		}
		if c.reject(s, w, "", rec) {
			return true
		}
		var id string
		if c.NewID != nil {
			id = c.NewID(s, rec)
		} else {
			s.nextID++
			id = fmt.Sprintf("00000000-0000-4000-8000-%012d", s.nextID)
		}
		if c.OnWrite != nil {
			c.OnWrite(s, id, rec)
		}
		c.items[id] = rec
		writeJSON(w, map[string]any{"result": "saved", "uuid": id})

	case verb == "get" && r.Method == http.MethodGet && arg == "":
		// No uuid: a blank item with defaults, as the UI's add dialog receives it.
		writeJSON(w, map[string]any{c.Key: c.readForm(s, "", c.Defaults())})

	case verb == "get" && r.Method == http.MethodGet:
		rec, ok := c.items[arg]
		if !ok {
			writeJSON(w, []any{})
			return true
		}
		writeJSON(w, map[string]any{c.Key: c.readForm(s, arg, rec)})

	case verb == "set" && r.Method == http.MethodPost:
		old, ok := c.items[arg]
		if !ok {
			writeJSON(w, map[string]any{"result": "failed"})
			return true
		}
		rec, ok := c.decode(w, r)
		if !ok {
			return true
		}
		if c.OnWrite != nil {
			c.OnWrite(s, arg, rec)
		}
		for k, v := range old { // setItem merges into the existing item
			if _, set := rec[k]; !set {
				rec[k] = v
			}
		}
		if c.reject(s, w, arg, rec) {
			return true
		}
		c.items[arg] = rec

		writeJSON(w, map[string]any{"result": "saved"})

	case verb == "del" && r.Method == http.MethodPost:
		if _, ok := c.items[arg]; !ok {
			writeJSON(w, map[string]any{"result": "not found"})
			return true
		}
		if s.InUse[arg] {
			writeJSON(w, map[string]any{"result": "failed"})
			return true
		}
		if c.CanDelete != nil {
			if msg := c.CanDelete(s, arg); msg != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"errorMessage": msg, "errorTitle": "Error"})
				return true
			}
		}
		delete(c.items, arg)
		if c.OnDelete != nil {
			c.OnDelete(s, arg)
		}
		if c.EmptyDelete {
			w.Header().Set("Content-Type", "application/json")
			return true
		}
		writeJSON(w, map[string]any{"result": "deleted"})

	case verb == "search":
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		phrase, _ := req["searchPhrase"].(string)
		ids := make([]string, 0, len(c.items))
		for id := range c.items {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rows := []map[string]string{}
		for _, id := range ids {
			rec := c.items[id]
			if phrase != "" && !matches(rec, phrase) {
				continue
			}
			if c.SearchFilter != nil && !c.SearchFilter(rec) {
				continue
			}
			if !filtersMatch(c, c.withVirtual(s, id, rec), req) {
				continue
			}
			row := map[string]string{"uuid": id}
			for k, v := range c.withVirtual(s, id, rec) {
				row[k] = strings.ReplaceAll(v, "\n", ",")
			}
			rows = append(rows, row)
		}
		if c.ExtraRows != nil {
			rows = append(rows, c.ExtraRows(s)...)
		}
		writeJSON(w, map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})

	default:
		return false
	}
	return true
}

// filtersMatch applies controller filters: a string request parameter named like a field
// (e.g. "host" on searchHostAlias) must equal the stored value.
//
// A list parameter (e.g. {"servers": ["uuid"]} on WireGuard searchClient) matches when it
// shares an entry with the field's comma-separated value.
func filtersMatch(c *Collection, rec Record, req map[string]any) bool {
	for k, v := range req {
		if _, field := c.Fields[k]; !field {
			continue
		}
		switch v := v.(type) {
		case string:
			if v != "" && rec[k] != v {
				return false
			}
		case []any:
			if len(v) == 0 {
				continue
			}
			have := map[string]bool{}
			for _, x := range split(rec[k], ",") {
				have[x] = true
			}
			hit := false
			for _, x := range v {
				if s, ok := x.(string); ok && have[s] {
					hit = true
				}
			}
			if !hit {
				return false
			}
		}
	}
	return true
}

// withVirtual returns rec plus its computed (volatile) fields.
func (c *Collection) withVirtual(s *Server, uuid string, rec Record) Record {
	out := Record{}
	for k, v := range rec {
		out[k] = v
	}
	for name, f := range c.Fields {
		if f.Virtual != nil {
			out[name] = f.Virtual(s, uuid)
		}
	}
	return out
}

func matches(rec Record, phrase string) bool {
	phrase = strings.ToLower(phrase)
	for _, v := range rec {
		if strings.Contains(strings.ToLower(v), phrase) {
			return true
		}
	}
	return false
}

func (c *Collection) reject(s *Server, w http.ResponseWriter, self string, rec Record) bool {
	if c.Validate == nil {
		return false
	}
	if v := c.Validate(s, self, rec); len(v) > 0 {
		writeJSON(w, map[string]any{"result": "failed", "validations": v})
		return true
	}
	return false
}

// decode reads {"<key>": {...}}, keeping only known fields, all as strings.
func (c *Collection) decode(w http.ResponseWriter, r *http.Request) (Record, bool) {
	var body map[string]map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return decodeFields(w, c.Key, c.Fields, body[c.Key])
}

// decodeFields keeps known fields, all as strings, and rejects writes to read-only ones.
func decodeFields(w http.ResponseWriter, key string, fields map[string]Field, in map[string]any) (Record, bool) {
	rec := Record{}
	for k, v := range flattenNested(in, fields) {
		f, known := fields[k]
		if !known {
			continue // OPNsense ignores unknown fields
		}
		if f.ReadOnly {
			http.Error(w, fmt.Sprintf("field %s.%s is maintained by OPNsense and must not be sent", key, k), http.StatusBadRequest)
			return nil, false
		}
		switch v := v.(type) {
		case string:
			rec[k] = v
		case nil:
			rec[k] = ""
		default:
			// The real API only accepts strings for scalar fields; make tests notice.
			http.Error(w, fmt.Sprintf("field %s.%s: expected string, got %T", key, k, v), http.StatusBadRequest)
			return nil, false
		}
	}
	return rec, true
}

// readForm renders a record the way get<Item> does.
func (c *Collection) readForm(s *Server, uuid string, rec Record) map[string]any {
	return renderFields(s, c.Fields, c.withVirtual(s, uuid, rec))
}

func renderFields(s *Server, fields map[string]Field, rec Record) map[string]any {
	out := renderFlat(s, fields, rec)
	// Fields of a container (e.g. a NAT rule's source.network) are nested, as OPNsense sends them.
	for name, v := range out {
		if parent, child, ok := strings.Cut(name, "."); ok {
			m, _ := out[parent].(map[string]any)
			if m == nil {
				m = map[string]any{}
				out[parent] = m
			}
			m[child] = v
			delete(out, name)
		}
	}
	return out
}

// flattenNested turns {"source": {"network": "x"}} into {"source.network": "x"} for fields
// declared with a dotted name.
func flattenNested(in map[string]any, fields map[string]Field) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		if m, ok := v.(map[string]any); ok {
			nested := false
			for ck, cv := range m {
				if _, known := fields[k+"."+ck]; known {
					out[k+"."+ck] = cv
					nested = true
				}
			}
			if nested {
				continue
			}
		}
		out[k] = v
	}
	return out
}

func renderFlat(s *Server, fields map[string]Field, rec Record) map[string]any {
	out := map[string]any{}
	for name, f := range fields {
		v := rec[name]
		switch f.Kind {
		case Text:
			out[name] = v
		case Option:
			selected := map[string]bool{}
			for _, p := range split(v, f.Sep) {
				selected[p] = true
			}
			var choices []string
			if f.Choices != nil {
				choices = f.Choices(s)
			}
			out[name] = optionMap(choices, selected)
		case List:
			entries := split(v, f.Sep)
			sel := map[string]bool{}
			for _, e := range entries {
				sel[e] = true
			}
			out[name] = optionMap(entries, sel)
		}
	}
	return out
}

// optionMap renders choices as {"k": {"value": "k", "selected": 0|1}}, or [] when empty,
// which is how PHP encodes an empty array.
func optionMap(choices []string, selected map[string]bool) any {
	if len(choices) == 0 {
		return []any{}
	}
	m := map[string]any{}
	for _, c := range choices {
		n := 0
		if selected[c] {
			n = 1
		}
		m[c] = map[string]any{"value": c, "selected": n}
	}
	return m
}

func split(v, sep string) []string {
	if sep == "" {
		sep = ","
	}
	var out []string
	for _, p := range strings.Split(v, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func static(vals ...string) func(*Server) []string { return func(*Server) []string { return vals } }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
