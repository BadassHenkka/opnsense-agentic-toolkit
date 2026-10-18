package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Services → Wake on LAN (plugin os-wol, /api/wol/wol).
//
//	{add,get,set,del,search}Host   saved hosts, key "host" (model array wolentry)
//	set                            wake: {"uuid": ...} for a saved host, or {"wake": {interface, mac}}
//	wakeall                        wake every saved host
//
// There is nothing to apply: hosts are plain configuration. Waking runs `wol` on the firewall
// against the interface's broadcast address, which the plugin computes from the interface's
// static IPv4 address; interfaces configured by DHCP cannot be used.
//
// WolService, WolHost and WolHostRow are generated (gen/specs/wol.json); this file adds waking.
//
// Quirks: delHost returns an empty body (ItemController.Delete verifies instead), and wake
// returns {"status":"OK"} on success, {"status":"error","error_msg":...} for a bad interface,
// and {} when an ad-hoc request fails validation.

var macRe = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)

// NormalizeMAC accepts aa:bb:cc:dd:ee:ff, AA-BB-..., or aabb.ccdd.eeff and returns the
// lower-case colon form OPNsense expects, or an error.
func NormalizeMAC(s string) (string, error) {
	hex := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(hex) != 12 {
		return "", fmt.Errorf("opnsense: %q is not a MAC address", s)
	}
	var parts []string
	for i := 0; i < 12; i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	mac := strings.ToLower(strings.Join(parts, ":"))
	if !macRe.MatchString(mac) {
		return "", fmt.Errorf("opnsense: %q is not a MAC address", s)
	}
	return mac, nil
}

// WakeResult is the outcome of one wake request.
type WakeResult struct {
	MAC     string `json:"mac,omitempty"`
	Status  string `json:"status"`
	Message string `json:"error_msg,omitempty"`
}

// OK reports whether the magic packet was sent.
func (r WakeResult) OK() bool { return strings.EqualFold(strings.TrimSpace(r.Status), "ok") }

func (r WakeResult) err() error {
	if r.OK() {
		return nil
	}
	if r.Message != "" {
		return fmt.Errorf("opnsense: wake failed: %s", r.Message)
	}
	if r.Status == "" {
		return fmt.Errorf("opnsense: wake failed: invalid interface or MAC address")
	}
	return fmt.Errorf("opnsense: wake failed: %s", r.Status)
}

// postWake calls wol/wol/set. PHP encodes an empty result as [], so decode loosely.
func (s *WolService) postWake(ctx context.Context, body any) error {
	var raw json.RawMessage
	if err := s.c.Post(ctx, "wol/wol/set", body, &raw); err != nil {
		return err
	}
	var res WakeResult
	_ = json.Unmarshal(raw, &res) // [] leaves res empty, which err() reports
	return res.err()
}

// Wake sends a magic packet to a saved host.
func (s *WolService) Wake(ctx context.Context, uuid string) error {
	if err := s.postWake(ctx, map[string]string{"uuid": uuid}); err != nil {
		if strings.Contains(err.Error(), "invalid interface or MAC") {
			return fmt.Errorf("opnsense: wake failed: no saved host %s", uuid)
		}
		return err
	}
	return nil
}

// WakeMAC sends a magic packet to any MAC address on an interface's network.
func (s *WolService) WakeMAC(ctx context.Context, iface, mac string) error {
	norm, err := NormalizeMAC(mac)
	if err != nil {
		return err
	}
	return s.postWake(ctx, map[string]any{"wake": map[string]string{"interface": iface, "mac": norm}})
}

// WakeAll sends a magic packet to every saved host.
func (s *WolService) WakeAll(ctx context.Context) ([]WakeResult, error) {
	var resp struct {
		Results []WakeResult `json:"results"`
	}
	if err := s.c.Post(ctx, "wol/wol/wakeall", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// FindByMAC returns the uuid of the saved host with this MAC, or ErrNotFound.
func (s *WolService) FindByMAC(ctx context.Context, mac string) (string, error) {
	norm, err := NormalizeMAC(mac)
	if err != nil {
		return "", err
	}
	res, err := s.Hosts.Search(ctx, "")
	if err != nil {
		return "", err
	}
	for _, r := range res.Rows {
		if strings.EqualFold(string(r.MAC), norm) {
			return string(r.UUID), nil
		}
	}
	return "", ErrNotFound
}
