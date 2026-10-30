package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ItemController covers the CRUD pattern shared by most OPNsense MVC controllers:
//
//	POST /api/<module>/<controller>/addItem          {"<key>": {...}}  -> {"result":"saved","uuid":"..."}
//	GET  /api/<module>/<controller>/getItem/<uuid>                     -> {"<key>": {...}}
//	POST /api/<module>/<controller>/setItem/<uuid>   {"<key>": {...}}  -> {"result":"saved"}
//	POST /api/<module>/<controller>/delItem/<uuid>                     -> {"result":"deleted"}
//	POST /api/<module>/<controller>/searchItem       {...}             -> {"rows":[...],"total":n}
//	POST /api/<module>/<service>/reconfigure                           -> {"status":"ok"}
//
// T is the item model; S is the row type returned by search. Writes are staged in the
// config until Apply runs the reconfigure action.
type ItemController[T, S any] struct {
	c *Client
	// Base is "<module>/<controller>", e.g. "firewall/alias".
	Base string
	// Key wraps the item in requests and responses, e.g. "alias".
	Key string
	// Suffix is appended to the action names. Most controllers use "Item"; some use the
	// model name, e.g. Unbound's "HostOverride" (addHostOverride, getHostOverride, ...).
	Suffix string
	// Actions overrides whole action names, keyed by the canonical verb ("add", "get", "set",
	// "del", "search"). The ACME plugin, for example, uses add/get/update/del/search with no
	// suffix.
	Actions map[string]string
	// ReconfigurePath is the apply endpoint, e.g. "firewall/alias/reconfigure".
	ReconfigurePath string
}

// SearchResult is one page of search rows.
type SearchResult[S any] struct {
	Rows     []S `json:"rows"`
	RowCount int `json:"rowCount"`
	Total    int `json:"total"`
	Current  int `json:"current"`
}

type mutationResponse struct {
	Result      string            `json:"result"`
	UUID        string            `json:"uuid"`
	Validations map[string]string `json:"validations"`
	// ErrorMessage is set when a controller throws a UserException, e.g. "Gateway X cannot
	// be deleted because it is in use on Static Route(s) ...".
	ErrorMessage string `json:"errorMessage"`
}

func (r mutationResponse) err(want string) error {
	if r.Result == want {
		return nil
	}
	if r.ErrorMessage != "" {
		return fmt.Errorf("opnsense: %s", r.ErrorMessage)
	}
	if len(r.Validations) > 0 || r.Result == "failed" {
		return &ValidationError{Fields: r.Validations}
	}
	return fmt.Errorf("opnsense: unexpected result %q", r.Result)
}

func (ic *ItemController[T, S]) path(verb string, uuid ...string) string {
	action, ok := ic.Actions[verb]
	if !ok {
		suffix := ic.Suffix
		if suffix == "" {
			suffix = "Item"
		}
		action = verb + suffix
	}
	p := ic.Base + "/" + action
	for _, u := range uuid {
		p += "/" + url.PathEscape(u)
	}
	return p
}

// Add creates an item and returns its UUID. The change is staged until Apply.
func (ic *ItemController[T, S]) Add(ctx context.Context, item T) (string, error) {
	var resp mutationResponse
	if err := ic.c.Post(ctx, ic.path("add"), map[string]T{ic.Key: item}, &resp); err != nil {
		return "", err
	}
	if err := resp.err("saved"); err != nil {
		return "", err
	}
	if resp.UUID == "" {
		return "", errors.New("opnsense: add succeeded but returned no uuid")
	}
	return resp.UUID, nil
}

// Get returns the item with the given UUID, or ErrNotFound.
func (ic *ItemController[T, S]) Get(ctx context.Context, uuid string) (*T, error) {
	if strings.TrimSpace(uuid) == "" {
		return nil, errors.New("opnsense: uuid is required")
	}
	var resp json.RawMessage
	if err := ic.c.Get(ctx, ic.path("get", uuid), &resp); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp, &raw); err != nil {
		// A bare [] instead of an object means the uuid is unknown.
		return nil, ErrNotFound
	}
	body, ok := raw[ic.Key]
	// Depending on the version, an unknown uuid yields [], {}, or a blank default item.
	if !ok || string(body) == "[]" || string(body) == "{}" || string(body) == "null" {
		return nil, ErrNotFound
	}
	var item T
	if err := json.Unmarshal(body, &item); err != nil {
		return nil, fmt.Errorf("opnsense: decode %s: %w", ic.Key, err)
	}
	if z, ok := any(&item).(interface{ IsZero() bool }); ok && z.IsZero() {
		return nil, ErrNotFound
	}
	if k, ok := any(&item).(kinded); ok {
		if err := checkKind(uuid, body, k); err != nil {
			return nil, err
		}
	}
	return &item, nil
}

// kinded is an item that shares its model array with items of another kind, such as
// Unbound's query forwarding and DNS over TLS servers. The get action of such a controller
// returns an item of any kind, so Get checks the type field that tells them apart.
type kinded interface {
	kind() string
}

// WrongKindError is Get finding an item of another kind in a shared array.
type WrongKindError struct {
	UUID, Got, Want string
}

func (e *WrongKindError) Error() string {
	return fmt.Sprintf("opnsense: item %s has type %q, not %q; it belongs to the resource or tool for %q items",
		e.UUID, e.Got, e.Want, e.Got)
}

func checkKind(uuid string, body json.RawMessage, k kinded) error {
	// The item's own Type is a ReadOnly, which can't hold the option map OPNsense returns.
	var got struct {
		Type Option `json:"type"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Errorf("opnsense: decode type: %w", err)
	}
	if want := k.kind(); string(got.Type) != want {
		return &WrongKindError{UUID: uuid, Got: string(got.Type), Want: want}
	}
	return nil
}

// Template returns a blank item with its default values and option lists, as the add dialog
// in the web UI gets it (get<Item> without a uuid). Nothing is saved. Fields are raw JSON.
func (ic *ItemController[T, S]) Template(ctx context.Context) (map[string]json.RawMessage, error) {
	var raw map[string]map[string]json.RawMessage
	if err := ic.c.Get(ctx, ic.path("get"), &raw); err != nil {
		return nil, err
	}
	item, ok := raw[ic.Key]
	if !ok {
		return nil, fmt.Errorf("opnsense: template response has no %q", ic.Key)
	}
	return item, nil
}

// Set replaces the item with the given UUID. The change is staged until Apply.
func (ic *ItemController[T, S]) Set(ctx context.Context, uuid string, item T) error {
	if strings.TrimSpace(uuid) == "" {
		return errors.New("opnsense: uuid is required")
	}
	var resp mutationResponse
	if err := ic.c.Post(ctx, ic.path("set", uuid), map[string]T{ic.Key: item}, &resp); err != nil {
		return err
	}
	return resp.err("saved")
}

// Delete removes the item with the given UUID. The change is staged until Apply.
// Deleting an item that does not exist returns ErrNotFound.
func (ic *ItemController[T, S]) Delete(ctx context.Context, uuid string) error {
	if strings.TrimSpace(uuid) == "" {
		return errors.New("opnsense: uuid is required")
	}
	var resp mutationResponse
	if err := ic.c.Post(ctx, ic.path("del", uuid), nil, &resp); err != nil {
		return err
	}
	if resp.Result == "" && resp.ErrorMessage == "" && len(resp.Validations) == 0 {
		// Some controllers (e.g. os-wol's delHost) return no body at all. Check the outcome.
		if _, err := ic.Get(ctx, uuid); errors.Is(err, ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		return errors.New("opnsense: delete returned no result and the item still exists")
	}
	if resp.Result == "not found" {
		return ErrNotFound
	}
	if resp.ErrorMessage != "" {
		return fmt.Errorf("opnsense: %s", resp.ErrorMessage)
	}
	if resp.Result == "failed" && len(resp.Validations) == 0 {
		return errors.New("opnsense: delete failed (the item may still be referenced, e.g. by a firewall rule)")
	}
	return resp.err("deleted")
}

// Search returns rows matching phrase (all rows when phrase is empty).
func (ic *ItemController[T, S]) Search(ctx context.Context, phrase string) (*SearchResult[S], error) {
	return ic.SearchWith(ctx, phrase, nil)
}

// SearchWith is Search with controller-specific filters, e.g. {"host": uuid} for Unbound
// host aliases or {"servers": []string{uuid}} for WireGuard peers.
func (ic *ItemController[T, S]) SearchWith(ctx context.Context, phrase string, filters map[string]any) (*SearchResult[S], error) {
	req := map[string]any{"current": 1, "rowCount": -1, "searchPhrase": phrase}
	for k, v := range filters {
		req[k] = v
	}
	var res SearchResult[S]
	if err := ic.c.Post(ctx, ic.path("search"), req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Apply activates staged changes by calling the controller's reconfigure action.
// Items without a reconfigure action (plain configuration, e.g. firewall categories) need none.
func (ic *ItemController[T, S]) Apply(ctx context.Context) error {
	if ic.ReconfigurePath == "" {
		return nil
	}
	return ic.c.Reconfigure(ctx, ic.ReconfigurePath)
}
