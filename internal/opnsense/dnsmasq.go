package opnsense

import "context"

// Services → Dnsmasq DNS & DHCP. Hosts, domains, tags, ranges, options, boot entries and the
// general settings are generated (gen/specs/dnsmasq.json); this file adds the lease list.
//
//	dnsmasq/leases/search   current DHCP leases (read-only; rows are built from the lease file)

// DnsmasqLease is one DHCP lease.
type DnsmasqLease struct {
	Address    string `json:"address"`
	Hostname   string `json:"hostname"`
	HWAddr     string `json:"hwaddr"`
	ClientID   string `json:"client_id"`
	Expire     any    `json:"expire"`
	Interface  string `json:"if_name"`
	IfDescr    string `json:"if_descr"`
	MACInfo    string `json:"mac_info"`
	IsReserved any    `json:"is_reserved"`
}

// Leases lists the current DHCP leases, optionally filtered by a search phrase.
func (s *DnsmasqService) Leases(ctx context.Context, phrase string) ([]DnsmasqLease, error) {
	var res SearchResult[DnsmasqLease]
	body := map[string]any{"current": 1, "rowCount": -1, "searchPhrase": phrase}
	if err := s.c.Post(ctx, "dnsmasq/leases/search", body, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}
