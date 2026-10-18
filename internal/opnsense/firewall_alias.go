package opnsense

import (
	"context"
	"encoding/json"
	"net/url"
)

// AliasTypes lists the alias types OPNsense accepts.
var AliasTypes = []string{
	"host", "network", "port", "url", "urltable", "geoip", "networkgroup",
	"mac", "asn", "dynipv6host", "authgroup", "internal", "external",
}

// Alias, AliasRow and the FirewallService fields are generated (gen/specs/firewall.json).

// AliasUUIDByName looks up an alias UUID by its name, or returns ErrNotFound.
func (s *FirewallService) AliasUUIDByName(ctx context.Context, name string) (string, error) {
	var raw json.RawMessage
	if err := s.c.Get(ctx, "firewall/alias/getAliasUUID/"+url.PathEscape(name), &raw); err != nil {
		return "", err
	}
	var resp struct {
		UUID string `json:"uuid"`
	}
	// An unknown name returns [] instead of an object.
	if err := json.Unmarshal(raw, &resp); err != nil || resp.UUID == "" {
		return "", ErrNotFound
	}
	return resp.UUID, nil
}
