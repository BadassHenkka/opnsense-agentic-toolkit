package opnsense

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// TestedVersion is the OPNsense release series the generated specs are pinned to.
const TestedVersion = "26.7"

// Check is one line of a Diagnose report.
type Check struct {
	Name   string
	Status CheckStatus
	Detail string
	// Hint says how to fix a failed or suspicious check.
	Hint string
}

// CheckStatus is the outcome of a check.
type CheckStatus string

const (
	CheckOK   CheckStatus = "ok"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
)

// Probes are read calls that need one privilege each. A 403 means the API user lacks it.
var probes = []struct{ Area, Path, Privilege string }{
	{"firewall aliases", "firewall/alias/searchItem", "Firewall: Alias"},
	// "Firewall: Rules" without [new] only grants the legacy firewall_rules.php page.
	{"firewall rules", "firewall/filter/searchRule", "Firewall: Rules [new]"},
	{"unbound overrides", "unbound/settings/searchHostOverride", "Services: Unbound DNS"},
	{"firmware", "core/firmware/info", "System: Firmware"},
}

// knownPlugins are the plugins whose toolsets and resources need an installed package.
var knownPlugins = []string{"os-acme-client", "os-caddy", "os-frr", "os-node_exporter", "os-wol",
	"os-ddclient", "os-postfix", "os-rspamd"}

// Diagnose checks the configuration and the connection step by step and never prints secrets.
// It only reads. Failures carry a hint for the likely fix.
func Diagnose(ctx context.Context, cfg Config) []Check {
	var out []Check
	add := func(c Check) { out = append(out, c) }
	fail := func(name, detail, hint string) []Check {
		add(Check{Name: name, Status: CheckFail, Detail: detail, Hint: hint})
		return out
	}

	var missing []string
	for _, v := range []struct{ val, env string }{{cfg.URL, EnvURL}, {cfg.APIKey, EnvAPIKey}, {cfg.APISecret, EnvAPISecret}} {
		if v.val == "" {
			missing = append(missing, v.env)
		}
	}
	if len(missing) > 0 {
		return fail("configuration", "not set: "+strings.Join(missing, ", "),
			"export them in the shell or put them in the MCP client's env block (see examples/mcp)")
	}
	if !strings.HasPrefix(cfg.URL, "https://") {
		add(Check{Name: "configuration", Status: CheckWarn, Detail: "URL is not https",
			Hint: "API credentials are sent with every request; use https://"})
	} else {
		add(Check{Name: "configuration", Status: CheckOK, Detail: "URL, key and secret are set"})
	}
	if cfg.Insecure {
		add(Check{Name: "tls", Status: CheckWarn, Detail: "certificate verification is off (OPNSENSE_INSECURE)",
			Hint: "export the CA from System > Trust > Authorities and set OPNSENSE_CA_FILE instead"})
	}
	if cfg.CAFile != "" {
		if _, err := os.Stat(cfg.CAFile); err != nil {
			return fail("tls", "CA file: "+err.Error(), "check the OPNSENSE_CA_FILE path (use an absolute path)")
		}
	}

	c, err := NewClient(cfg)
	if err != nil {
		return fail("client", err.Error(), "")
	}
	var info FirmwareInfo
	err = c.Get(ctx, "core/firmware/info", &info)
	var api *APIError
	switch {
	case err == nil:
		add(Check{Name: "connection", Status: CheckOK, Detail: "authenticated; OPNsense " + string(info.ProductVersion)})
	case errors.As(err, &api) && api.StatusCode == http.StatusForbidden:
		// 403 comes after authentication, so the key and secret are right.
		add(Check{Name: "connection", Status: CheckOK, Detail: "authenticated (the version is hidden without System: Firmware)"})
	default:
		return fail("connection", err.Error(), connectionHint(err))
	}

	if v := string(info.ProductVersion); v != "" && !strings.HasPrefix(v, TestedVersion) {
		add(Check{Name: "version", Status: CheckWarn, Detail: "OPNsense " + v + ", tested against " + TestedVersion + ".x",
			Hint: "most areas still work; if a call fails with a missing field or 404, run `task acc` and open an issue"})
	} else if v != "" {
		add(Check{Name: "version", Status: CheckOK, Detail: v + " matches the tested series"})
	}

	var denied []string
	for _, p := range probes {
		var resp map[string]any
		var e error
		if strings.Contains(p.Path, "search") {
			e = c.Post(ctx, p.Path, map[string]any{"rowCount": 1}, &resp)
		} else {
			e = c.Get(ctx, p.Path, &resp)
		}
		if errors.As(e, &api) && api.StatusCode == http.StatusForbidden {
			denied = append(denied, fmt.Sprintf("%s (%s)", p.Area, p.Privilege))
		}
	}
	if len(denied) > 0 {
		add(Check{Name: "permissions", Status: CheckWarn, Detail: "no access to: " + strings.Join(denied, ", "),
			Hint: "System > Access > Users > edit the API user > Effective Privileges; add only what the areas you use need"})
	} else {
		add(Check{Name: "permissions", Status: CheckOK, Detail: "read access to aliases, rules, Unbound overrides and firmware"})
	}

	if len(info.Plugins) > 0 {
		installed := map[string]bool{}
		for _, p := range info.Plugins {
			if p.IsInstalled() {
				installed[string(p.Name)] = true
			}
		}
		var have, lack []string
		for _, n := range knownPlugins {
			if installed[n] {
				have = append(have, n)
			} else {
				lack = append(lack, n)
			}
		}
		add(Check{Name: "plugins", Status: CheckOK,
			Detail: fmt.Sprintf("installed: %s; not installed: %s", orNone(have), orNone(lack)),
			Hint:   "areas of a missing plugin return not-found; install with the opnsense_plugin resource or System > Firmware > Plugins"})
	}
	return out
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func connectionHint(err error) string {
	var api *APIError
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &api) && api.StatusCode == http.StatusUnauthorized:
		return "key or secret is wrong, or the user is disabled. Create the key under System > Access > Users > API keys; the secret is only shown once"
	case errors.As(err, &unknown):
		return "the certificate is not trusted: export the CA from System > Trust > Authorities and set OPNSENSE_CA_FILE"
	case errors.As(err, &hostErr):
		return "the certificate does not match the host name in OPNSENSE_URL; use the name the certificate was issued for, or set it in OPNSENSE_TLS_SERVER_NAME"
	case errors.As(err, &dnsErr):
		return "the host name does not resolve; check OPNSENSE_URL or use the IP address"
	case strings.Contains(err.Error(), "connection refused"):
		return "nothing listens there; check the port (the web UI port, 443 by default) and System > Settings > Administration"
	case strings.Contains(err.Error(), "deadline exceeded"), strings.Contains(err.Error(), "timeout"):
		return "no answer: check routing and firewall rules between this machine and the firewall's web UI"
	case errors.As(err, &api) && api.StatusCode == http.StatusNotFound:
		return "the URL answers but is not the OPNsense web UI; it should be the address you open in the browser, without /ui or /api"
	}
	return ""
}
