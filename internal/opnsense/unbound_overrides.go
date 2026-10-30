package opnsense

import (
	"context"
	"fmt"
	"strings"
)

// Services → Unbound DNS → Overrides is two models in /api/unbound/settings:
//
//	hosts.host      a host override: hostname.domain → A/AAAA/MX/TXT record
//	aliases.alias   an extra name for a host override; deleted together with its host
//
// Both are applied with /api/unbound/service/reconfigure.

// HostOverrideTypes lists the record types a host override supports.
var HostOverrideTypes = []string{"A", "AAAA", "MX", "TXT"}

// HostOverride, HostAlias, their rows and UnboundService are generated
// (gen/specs/unbound.json); this file adds lookups by name.

// FQDN returns hostname.domain, or the domain when hostname is empty.
func (h *HostOverride) FQDN() string { return fqdn(h.Hostname, h.Domain) }

// FQDN returns hostname.domain, or the domain when hostname is empty.
func (r HostOverrideRow) FQDN() string { return fqdn(string(r.Hostname), string(r.Domain)) }

// FQDN joins the alias's hostname and domain.
func (r HostAliasRow) FQDN() string { return fqdn(string(r.Hostname), string(r.Domain)) }

const unboundReconfigure = "unbound/service/reconfigure"

// Apply activates staged override and alias changes (reloads Unbound).
func (s *UnboundService) Apply(ctx context.Context) error {
	return s.c.Reconfigure(ctx, unboundReconfigure)
}

// FindHostOverrides returns the host overrides for a name, optionally limited to one record
// type. Several can match, e.g. an A and an AAAA record for the same host.
func (s *UnboundService) FindHostOverrides(ctx context.Context, name, rr string) ([]HostOverrideRow, error) {
	res, err := s.HostOverrides.Search(ctx, "")
	if err != nil {
		return nil, err
	}
	want := normName(name)
	var out []HostOverrideRow
	for _, r := range res.Rows {
		if normName(r.FQDN()) != want {
			continue
		}
		if rr != "" && !strings.EqualFold(rrKey(string(r.RR)), rr) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// HostAliasesOf returns the aliases that belong to a host override.
func (s *UnboundService) HostAliasesOf(ctx context.Context, hostUUID string) ([]HostAliasRow, error) {
	res, err := s.HostAliases.SearchWith(ctx, "", map[string]any{"host": hostUUID})
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// FindHostAliases returns the host aliases for a name. Only aliases that set both hostname
// and domain can be matched by name.
func (s *UnboundService) FindHostAliases(ctx context.Context, name string) ([]HostAliasRow, error) {
	res, err := s.HostAliases.Search(ctx, "")
	if err != nil {
		return nil, err
	}
	want := normName(name)
	var out []HostAliasRow
	for _, r := range res.Rows {
		if normName(r.FQDN()) == want {
			out = append(out, r)
		}
	}
	return out, nil
}

func fqdn(host, domain string) string {
	if host == "" {
		return domain
	}
	if domain == "" {
		return host
	}
	return host + "." + domain
}

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// rrKey turns a search row's record type ("A" or a label like "A (IPv4 address)") into the key.
func rrKey(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

// ApplyBlocklists downloads and compiles the DNS blocklists (Services → Unbound DNS →
// Blocklist → Apply), then reloads Unbound. The dnsbl action answers with configd's output
// rather than "ok", so only an explicit failure counts as an error.
func (s *UnboundService) ApplyBlocklists(ctx context.Context) error {
	var resp struct {
		Status string `json:"status"`
	}
	if err := s.c.Post(ctx, "unbound/service/dnsbl", nil, &resp); err != nil {
		return err
	}
	if st := strings.ToLower(resp.Status); strings.Contains(st, "fail") || strings.Contains(st, "error") {
		return fmt.Errorf("opnsense: updating blocklists: %s", strings.TrimSpace(resp.Status))
	}
	return s.Apply(ctx)
}
