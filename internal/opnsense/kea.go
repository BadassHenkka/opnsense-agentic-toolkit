package opnsense

import "context"

// Services → Kea DHCP. Subnets, reservations, options, peers and settings are generated
// (gen/specs/kea.json); this file adds the read-only lease lists.
//
//	kea/leases4/search, kea/leases6/search   current leases (rows are built from the lease database;
//	                                          the columns depend on the release, so they stay a map)

// KeaLease is one lease row as OPNsense returns it (address, hwaddr, hostname, expire, ...).
type KeaLease map[string]any

// Leases lists the DHCPv4 (ipv6 false) or DHCPv6 leases, optionally filtered by a search phrase.
func (s *KeaService) Leases(ctx context.Context, ipv6 bool, phrase string) ([]KeaLease, error) {
	path := "kea/leases4/search"
	if ipv6 {
		path = "kea/leases6/search"
	}
	var res SearchResult[KeaLease]
	if err := s.c.Post(ctx, path, map[string]any{"current": 1, "rowCount": -1, "searchPhrase": phrase}, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}
