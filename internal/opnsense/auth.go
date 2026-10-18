package opnsense

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
)

// System → Access (/api/auth/user, /api/auth/group).
//
//	{add,get,set,del,search}       users (key "user") and groups (key "group"); no suffix
//	addApiKey/<username>           new key: {"result":"ok","key":...,"secret":...}
//	delApiKey/<base64(key)>        {"result":"deleted"} or {"result":"not found"}
//	searchApiKey                   rows {username, key, id}; secrets are only stored hashed
//
// Users, groups and AuthService are generated (gen/specs/auth.json); this file adds API keys.
// Membership is stored on both sides; OPNsense syncs groups from the user's
// group_memberships on every user add/set. There is nothing to apply.

// APIKey is one API key; Secret is only known right after creation.
type APIKey struct {
	Username string `json:"username"`
	Key      string `json:"key"`
	ID       string `json:"id"`
	Secret   string `json:"secret,omitempty"`
}

// APIKeys lists every user's API keys (without secrets).
func (s *AuthService) APIKeys(ctx context.Context) ([]APIKey, error) {
	var res SearchResult[APIKey]
	if err := s.c.Post(ctx, "auth/user/searchApiKey", map[string]any{"current": 1, "rowCount": -1}, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// APIKey returns the key with this key string, or ErrNotFound.
func (s *AuthService) APIKey(ctx context.Context, key string) (*APIKey, error) {
	keys, err := s.APIKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Key == key {
			return &k, nil
		}
	}
	return nil, ErrNotFound
}

// AddAPIKey creates a key for the user. The secret is returned only here.
func (s *AuthService) AddAPIKey(ctx context.Context, username string) (*APIKey, error) {
	var res struct {
		Result string `json:"result"`
		Key    string `json:"key"`
		Secret string `json:"secret"`
	}
	if err := s.c.Post(ctx, "auth/user/addApiKey/"+url.PathEscape(username), nil, &res); err != nil {
		return nil, err
	}
	if res.Result != "ok" || res.Key == "" {
		return nil, fmt.Errorf("opnsense: adding an API key for %q failed (unknown user?)", username)
	}
	return &APIKey{Username: username, Key: res.Key, Secret: res.Secret, ID: base64.StdEncoding.EncodeToString([]byte(res.Key))}, nil
}

// DeleteAPIKey removes a key; a key that no longer exists is not an error.
func (s *AuthService) DeleteAPIKey(ctx context.Context, key string) error {
	id := url.PathEscape(base64.StdEncoding.EncodeToString([]byte(key)))
	var res mutationResponse
	if err := s.c.Post(ctx, "auth/user/delApiKey/"+id, nil, &res); err != nil {
		return err
	}
	switch res.Result {
	case "deleted", "not found":
		return nil
	}
	return fmt.Errorf("opnsense: deleting API key failed: %s", res.Result)
}
