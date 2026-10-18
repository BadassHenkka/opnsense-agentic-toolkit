package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SettingsController reads and writes one section of a model that a controller serves as a
// whole, the second common MVC pattern next to ItemController:
//
//	GET  /api/<module>/<controller>/get   -> {"<model>": {"general": {...}, "other": {...}, ...}}
//	POST /api/<module>/<controller>/set   {"<model>": {"general": {...}}} -> {"result":"saved"}
//
// set only changes the posted fields, so writing one section leaves the others alone.
type SettingsController[T any] struct {
	c *Client
	// GetPath and SetPath are the endpoints, e.g. "syslog/settings/get".
	GetPath, SetPath string
	// Path leads from the response root to the section, e.g. ["syslog", "general"].
	Path []string
	// ReconfigurePath is the apply endpoint.
	ReconfigurePath string
}

// NewSettingsController returns a controller for a settings section.
func NewSettingsController[T any](c *Client, get, set string, path []string, reconfigure string) *SettingsController[T] {
	return &SettingsController[T]{c: c, GetPath: get, SetPath: set, Path: path, ReconfigurePath: reconfigure}
}

// Get returns the section.
func (sc *SettingsController[T]) Get(ctx context.Context) (*T, error) {
	var raw json.RawMessage
	if err := sc.c.Get(ctx, sc.GetPath, &raw); err != nil {
		return nil, err
	}
	for _, key := range sc.Path {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("opnsense: %s: expected an object at %q", sc.GetPath, key)
		}
		next, ok := m[key]
		if !ok {
			return nil, fmt.Errorf("opnsense: %s: response has no %q", sc.GetPath, strings.Join(sc.Path, "."))
		}
		raw = next
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("opnsense: decode %s: %w", strings.Join(sc.Path, "."), err)
	}
	return &v, nil
}

// Set saves the section. The change is staged until Apply.
func (sc *SettingsController[T]) Set(ctx context.Context, v T) error {
	var body any = v
	for i := len(sc.Path) - 1; i >= 0; i-- {
		body = map[string]any{sc.Path[i]: body}
	}
	var resp mutationResponse
	if err := sc.c.Post(ctx, sc.SetPath, body, &resp); err != nil {
		return err
	}
	return resp.err("saved")
}

// Apply runs the reconfigure action, if the section has one.
func (sc *SettingsController[T]) Apply(ctx context.Context) error {
	if sc.ReconfigurePath == "" {
		return nil
	}
	return sc.c.Reconfigure(ctx, sc.ReconfigurePath)
}

// NewItemController returns an ItemController; generated services use it.
func NewItemController[T, S any](c *Client, base, key, suffix string, actions map[string]string, reconfigure string) *ItemController[T, S] {
	return &ItemController[T, S]{c: c, Base: base, Key: key, Suffix: suffix, Actions: actions, ReconfigurePath: reconfigure}
}
