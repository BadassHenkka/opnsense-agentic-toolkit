# opnsense-agentic-toolkit

Let an AI agent work on an OPNsense firewall without giving up review and reproducibility.

The idea is three steps with a clear owner for each:

1. **Explore (MCP).** The agent reads the live state as freely as it likes: rules, aliases, DNS,
   routes, WireGuard handshakes, backups and diffs. The server runs read-only by default in the
   examples, so exploring cannot break anything.
2. **Verify (MCP, optional).** When the agent needs to know whether an idea works, it may make a
   short-lived trial change through the MCP write tools (staged, applied only on request), look at
   the result, and undo it. Trial changes are scaffolding, not the result.
3. **Implement (Terraform).** The proposed end state is written as Terraform. You review the plan
   and apply it. Terraform state is the source of truth for what the firewall should look like.

One Go OPNsense API client is shared by both front ends, so an endpoint and its quirks are written
once:

- **`mcp-opnsense`**: local MCP server (stdio) for steps 1 and 2.
- **`terraform-provider-opnsense`**: Terraform provider (Plugin Framework, protocol 6) for step 3.

Supported so far:

| OPNsense page | Terraform resources | MCP toolset |
|---|---|---|
| Firewall → Aliases | `opnsense_firewall_alias` | `firewall_alias` |
| Services → Unbound DNS → Overrides | `opnsense_unbound_host_override`, `opnsense_unbound_host_alias` | `unbound` |
| Services → Unbound DNS → General, Advanced, ACL, Query Forwarding, DNS over TLS, Blocklist | `opnsense_unbound_settings`, `opnsense_unbound_advanced`, `opnsense_unbound_acl_settings`, `opnsense_unbound_forwarding`, `opnsense_unbound_acl`, `opnsense_unbound_forward`, `opnsense_unbound_dot`, `opnsense_unbound_blocklist` | `unbound` (read-only) |
| Services → ACME Client (plugin os-acme-client) | `opnsense_acme_settings`, `opnsense_acme_account`, `opnsense_acme_challenge_type`, `opnsense_acme_automation`, `opnsense_acme_certificate` | `acme` |
| VPN → WireGuard | `opnsense_wireguard_settings`, `opnsense_wireguard_instance`, `opnsense_wireguard_peer` | `wireguard` |
| System → Gateways, Groups, System → Routes | `opnsense_gateway`, `opnsense_gateway_group`, `opnsense_route` | `routing` |
| Firewall → Rules | `opnsense_firewall_rule` | `firewall_rule` |
| System → Firmware (plugins, updates) | `opnsense_plugin` | `firmware` |
| Services → Prometheus Exporter (plugin os-node_exporter) | `opnsense_node_exporter_settings` | `nodeexporter` (read-only) |
| Services → Wake on LAN (plugin os-wol) | `opnsense_wol_host`, action `opnsense_wol_wake` | `wol` |
| Services → Dynamic DNS (plugin os-ddclient) | `opnsense_dyndns_settings`, `opnsense_dyndns_account` | `dyndns` (read-only) |
| Services → Captive Portal | `opnsense_captive_portal_zone` | `captiveportal` (read-only) |
| System → High Availability | `opnsense_hasync_settings` | `system` (read-only) |
| Services → Kea DHCP | `opnsense_kea_dhcp4_{settings,subnet,reservation,option,peer}`, `opnsense_kea_dhcp6_{settings,subnet,reservation,pd_pool,option,peer}`, `opnsense_kea_ctrl_agent_settings` | `kea` (read-only, plus `kea_lease4_list`, `kea_lease6_list`) |
| Interfaces → Assignments, Other Types, Neighbors | `opnsense_interface`, `opnsense_vlan`, `opnsense_virtual_ip`, `opnsense_bridge`, `opnsense_lagg`, `opnsense_gif`, `opnsense_gre`, `opnsense_vxlan`, `opnsense_loopback`, `opnsense_neighbor` | `interfaces` (read-only) |
| Interfaces → VLAN, Virtual IPs | `opnsense_vlan`, `opnsense_virtual_ip` | `interfaces` (read-only) |
| Firewall → Categories | `opnsense_firewall_category` | `firewall` (read-only) |
| Firewall → NAT → Port Forward, Outbound, One-to-One, NPTv6 | `opnsense_firewall_nat_port_forward`, `opnsense_firewall_nat_outbound` (+ `_mode`), `opnsense_firewall_nat_one_to_one`, `opnsense_firewall_nat_npt` | `firewall` (read-only) |
| Firewall → Groups | `opnsense_firewall_interface_group` | `firewall` (read-only) |
| System → Cron, Logging, Tunables | `opnsense_cron_job`, `opnsense_syslog_destination`, `opnsense_syslog_settings`, `opnsense_tunable` | `system` (read-only) |
| Services → Caddy Web Server (plugin os-caddy) | `opnsense_caddy_settings`, `opnsense_caddy_domain`, `opnsense_caddy_subdomain`, `opnsense_caddy_handler`, `opnsense_caddy_access_list`, `opnsense_caddy_basic_auth`, `opnsense_caddy_header`, `opnsense_caddy_layer4_route` | `caddy` |

## Quick start

Four steps, then one command tells you whether it worked.

**1. Create an API user on the firewall.**
1. System → Access → Users → add a user, e.g. `automation` (a random password you will not use).
2. Edit it → *Effective Privileges* → add only what the areas you use need. Search the list for
   the area name: *Firewall: Alias*, *Firewall: Rules*, *Services: Unbound DNS*, *VPN: WireGuard*,
   *System: Gateways*, *System: Static Routes*, *System: Firmware*, *System: Trust*, *Services:
   Caddy*, *Services: ACME Client*, *Services: Wake on LAN*. Start small; step 4 tells you what is
   missing. OPNsense has no read-only privileges for most pages, so "read-only" is enforced by
   `mcp-opnsense --read-only`, not by the user. Using one user per front end (MCP, Terraform)
   lets you revoke them separately.
3. Same user → *API keys* → **+**. The browser downloads a file with `key=` and `secret=`. The
   secret is shown only once.

**2. Trust the firewall's certificate** (only for a self-signed one): System → Trust →
Authorities → export the CA certificate as PEM and keep it at, say,
`~/.config/opnsense/ca.pem`. Do not use `OPNSENSE_INSECURE` except for a throwaway test.

**3. Build and configure.**

```sh
make build                         # bin/mcp-opnsense and bin/terraform-provider-opnsense
export OPNSENSE_URL=https://opnsense.lan      # the address you open in the browser
export OPNSENSE_API_KEY=...
export OPNSENSE_API_SECRET=...
export OPNSENSE_CA_FILE=$HOME/.config/opnsense/ca.pem   # only for a self-signed certificate
```

**4. Check it.**

```sh
./bin/mcp-opnsense --check
```

```
[ok  ] configuration URL, key and secret are set
[ok  ] connection    authenticated; OPNsense 26.7.3
[ok  ] version       26.7.3 matches the tested series
[warn] permissions   no access to: firewall rules (Firewall: Rules)
       -> System > Access > Users > edit the API user > Effective Privileges; ...
[ok  ] plugins       installed: os-caddy; not installed: os-frr, ...
```

Each failure prints the likely fix (wrong secret, untrusted certificate, wrong port, missing
privilege). Nothing is changed and no secret is printed. When it ends with "Setup looks good",
register the server with your MCP client ([MCP server](#mcp-server) below) and ask it to run
`firmware_status`.

## Build and test

```sh
make tidy     # first run: resolves dependencies and writes go.sum
make test
make build    # binaries in ./bin
```

The tests run against an in-memory fake of the OPNsense API, so they need no firewall.

## MCP server

```sh
./bin/mcp-opnsense --read-only            # only list/get tools
./bin/mcp-opnsense --toolsets unbound
```

Write tools exist for trial changes that verify an idea, not for the final configuration. They
only **stage** changes: nothing takes effect until the agent calls the toolset's apply tool, and
the server instructions tell it to confirm with you first and to undo trial changes afterwards
(`backup_diff_get` shows whether the firewall is back at its baseline). Lasting changes go
through Terraform. Use `--read-only` when you only want exploration.

| Toolset | Tools |
|---|---|
| `firewall_alias` | `firewall_alias_{list,get,create,update,delete}`, `firewall_alias_apply` |
| `unbound` | `unbound_host_override_{list,get,create,update,delete}`, `unbound_host_alias_{list,get,create,update,delete}`, `unbound_apply` |
| `wireguard` | `wireguard_settings_{get,update}`; `wireguard_status` (live handshakes/traffic); `wireguard_{instance,peer}_{list,get,create,update,delete}`; `wireguard_apply` |
| `routing` | `routing_gateway_{list,get,create,update,delete}`, `routing_gateway_status`; `routing_route_{list,get,create,update,delete}`; `routing_apply` |
| `firewall_rule` | `firewall_interface_list`; `firewall_rule_{list,get,create,update,delete,move}`; `firewall_rule_apply` (verifies the API is still reachable) |
| `firmware` | `firmware_status`, `firmware_plugin_list`, `firmware_plugin_{install,remove}`, `firmware_update` (minor updates; never reboots) |
| `backup` | `backup_list`, `backup_diff_get` (what a change did), `snapshot_list` (ZFS); read-only, no revert/download |
| `wol` | `wol_host_{list,create,update,delete}`, `wol_wake` (saved host or any MAC), `wol_wake_all` |
| `caddy` | `caddy_status`, `caddy_settings_update`, `caddy_caddyfile_get`; `caddy_expose` (hostname → LAN service in one call); `caddy_{domain,subdomain,handler,access_list}_{list,delete}`, `caddy_handler_{get,update}`, `caddy_access_list_create`; `caddy_apply` |
| `acme` | `acme_settings_{get,update}`; `acme_{account,challenge_type,automation,certificate}_{list,get,create,update,delete}`; `acme_challenge_type_fields`, `acme_automation_fields` (discover provider fields); `acme_account_register`; `acme_certificate_{issue,revoke,run_automations}`; `acme_apply` |

ACME credentials (DNS API tokens, EAB keys, automation passwords) can be set through MCP but
are never returned: `get` tools show them as `(set, hidden)`. `acme_certificate_issue` and
`acme_certificate_revoke` contact the CA; issuing runs in the background on the firewall,
so the agent checks the status with `acme_certificate_get` afterwards.

Firewall rules created through MCP are **disabled** unless the agent passes `enabled: true`.
OPNsense has no rollback for rule changes (the old savepoint API is gone), so
`firewall_rule_apply` reloads the rules and then checks over a *new* connection that the API
still answers. If it doesn't, the tool says so instead of reporting success.

WireGuard keys are generated locally (X25519), not on the firewall. `wireguard_peer_create`
without a `public_key` generates the device's key pair and returns a ready-to-import client
config once: the device's private key is not stored on the firewall or anywhere else.
Instance private keys and preshared keys are never returned by `get` tools.

Updates are patches: only the fields given change. Host overrides can be addressed by name
(`nas.home.lan`), plus `type` when a name has several records (e.g. A and AAAA).

Client config examples: [examples/mcp](examples/mcp). Run `./bin/mcp-opnsense --check` first. For Claude Code:

```sh
claude mcp add opnsense --scope user \
  -e OPNSENSE_URL=https://opnsense.lan -e OPNSENSE_API_KEY=... -e OPNSENSE_API_SECRET=... \
  -- $PWD/bin/mcp-opnsense --read-only
claude mcp list                    # opnsense should show as connected
```

Start with `--read-only`. Drop it only when you want the agent to be able to run trial changes.
The MCP client does not inherit your shell's `export`s, so the credentials go in `-e` (or the
client's `env` block). That stores them in the client's config file in plain text and in your
shell history; for tighter handling point `command` at a small wrapper script that reads them
from your password manager and then runs `exec bin/mcp-opnsense --read-only`.

## Terraform provider

```sh
make install-tf   # builds into $(go env GOPATH)/bin
```

Add a dev override in `~/.terraformrc` (skip `terraform init` for this provider):

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/smulis/opnsense" = "/Users/<you>/go/bin"
  }
  direct {}
}
```

Then see [examples/terraform/main.tf](examples/terraform/main.tf). Existing objects import by
name or UUID:

```sh
terraform import opnsense_firewall_alias.servers homelab_servers
terraform import opnsense_unbound_host_override.nas nas.home.lan/A   # name/TYPE if ambiguous
terraform import opnsense_unbound_host_alias.truenas truenas.home.lan
terraform import opnsense_interface.lan lan                          # identifier or description
terraform import opnsense_acme_certificate.fw fw.example.com            # ACME objects by name
terraform import opnsense_acme_settings.this acmeclient
terraform import opnsense_wireguard_instance.home home                # WireGuard by name
terraform import opnsense_gateway.site2 WG_SITE2                      # gateway by name
terraform import opnsense_route.site2 192.168.50.0/24                 # route by network
terraform import opnsense_firewall_rule.nas "site2 to NAS"            # rule by description
terraform import opnsense_plugin.ddclient os-ddclient                 # plugin by package name
terraform import opnsense_wol_host.nas nas                            # WoL host by description
```

### Plugins

`opnsense_plugin` installs a plugin on create and removes it on destroy. Both wait for the
package job, with a 15 minute limit. The provider and MCP refuse third-party packages (tier 4,
from repositories other than OPNsense/SunnyValley) unless you set `allow_third_party`. The API
cannot add package repositories: a community repository is a one-time shell step on the
firewall. Plugin *settings* need their own resources (ACME has them; others don't yet).

```hcl
resource "opnsense_plugin" "ddclient" {
  name = "os-ddclient"
}
```

### Wake on LAN and Terraform actions

`opnsense_wol_host` saves a host; `opnsense_wol_wake` is a **Terraform action** (Terraform 1.14+),
because waking a machine is something you do, not state you keep:

```hcl
resource "opnsense_plugin" "wol" { name = "os-wol" }

resource "opnsense_wol_host" "nas" {
  interface   = "lan"
  mac         = "00:11:22:33:44:55"
  description = "nas"
  depends_on  = [opnsense_plugin.wol]
}

action "opnsense_wol_wake" "nas" {
  config {
    host_id = opnsense_wol_host.nas.id
  }
}
```

Run it with `terraform apply -invoke=action.opnsense_wol_wake.nas`. The plugin sends to the
interface's broadcast address, which it computes from the interface's *static* IPv4 address,
so waking on a DHCP-configured interface fails with "Incorrect IPv4 configuration on interface".

### Prometheus

`opnsense_node_exporter_settings` runs the plugin's node_exporter. Bind `listen_address` to the
LAN address, add a pass rule for the scrape port (see `examples/terraform/main.tf`), then point
Prometheus at `http://<firewall>:9100/metrics`.

### Caddy reverse proxy

A **domain** is a site (`app.example.com`, or `*.example.com` with the DNS-01 challenge); a
**handler** sends its requests, optionally only below a path, to upstreams on the LAN; a
**subdomain** is one name under a wildcard domain, so all of them share one certificate:

```hcl
resource "opnsense_plugin" "caddy" { name = "os-caddy" }

resource "opnsense_caddy_settings" "this" {
  acme_email   = "me@example.com"
  dns_provider = "cloudflare"          # only needed for wildcards / DNS-01
  dns_api_key  = var.cloudflare_token
  depends_on   = [opnsense_plugin.caddy]
}

resource "opnsense_caddy_domain" "lab" {
  domain        = "*.lab.example.com"
  dns_challenge = true
}

resource "opnsense_caddy_subdomain" "grafana" {
  domain_id = opnsense_caddy_domain.lab.id
  subdomain = "grafana.lab.example.com"
}

resource "opnsense_caddy_handler" "grafana" {
  domain_id     = opnsense_caddy_domain.lab.id
  subdomain_id  = opnsense_caddy_subdomain.grafana.id
  upstreams     = ["192.168.1.30"]
  upstream_port = 3000
}
```

Before enabling Caddy on 80/443, move the web GUI to another port (System → Settings →
Administration). For LAN-only names, point them at the firewall with an Unbound host override.
Through MCP, `caddy_expose` does the domain/subdomain/handler dance in one call. Basic auth users,
headers and layer4 routes are Terraform resources (`opnsense_caddy_basic_auth`, `_header`,
`_layer4_route`); the layer4 OpenVPN static keys are not modelled.

### Firewall rules and lockout

`opnsense_firewall_rule` reloads the rules after every change. It then opens a new connection to
the API, because existing connections survive in pf's state table. If the API doesn't answer
within 15 s, the apply fails with a lockout error and the rule stays in state, so you can fix
it from a host that still has access. OPNsense's own anti-lockout rule (LAN → web UI) is the
real safety net: keep it enabled while automating rules. Order rules with explicit `sequence`
numbers (100, 200, ...); omitted, OPNsense appends the rule at the end.

WireGuard: `opnsense_wireguard_instance` generates its private key when you omit
`private_key` (it is then kept in Terraform state, which you should treat as secret) and
shows the derived `public_key` in the plan. Peer membership is set only on the peer
(`instance_ids`). OPNsense stores it on the instance, but the provider never writes it there,
so two resources never fight over it.

### Routing to networks behind a WireGuard peer (site-to-site)

A peer's `tunnel_addresses` are its WireGuard *allowed IPs*. `/32` is one device. A wider block
(`192.168.50.0/24`) means a whole network sits behind that peer. By default OPNsense installs
routes for every allowed IP itself. For explicit control (monitoring, failover, policy routing),
set `disable_routes = true` on the instance, then add an `opnsense_gateway` that points at the
peer's tunnel IP and an `opnsense_route` per remote network. See the example in
[examples/terraform/main.tf](examples/terraform/main.tf).

One manual step remains: assign the `wgN` device as an interface (Interfaces → Assignments, it
becomes e.g. `opt3`) and enable it. The gateway's `interface` is that assigned name. Recent
OPNsense development versions add an assignment API, so a resource for this is on the roadmap.
Then allow the traffic with `opnsense_firewall_rule` on the WireGuard interface.

## Adding a resource

Most areas are **generated**. `cmd/opnsense-gen` reads a spec in `gen/specs/<area>.json` and
the pinned OPNsense model XML in `gen/models`, and writes `zz_gen_*.go` files: client types and
service, fake collections, Terraform resources with tests, and read-only MCP tools. Field types,
defaults, option lists, ranges, masks and uniqueness come from the XML.

1. Find the model and controller: `src/opnsense/mvc/app/models/OPNsense/<Module>/<File>.xml` and
   `controllers/OPNsense/<Module>/Api/*Controller.php` in opnsense/core (or the plugin).
   The controller gives `base`, `key`, `suffix` and any odd action names
   (`searchJobs` instead of `searchJob`).
2. Add it to a spec (see [gen/README.md](gen/README.md)), then `make fetch-models gen test`
   and `make verify-upstream` (checks actions and keys against the upstream controllers).
3. The generator stops on what it cannot know (custom field types, reserved names) and says
   which `fields.<name>` override to add.

Hand-write an area only when the API needs behaviour a spec cannot describe (secrets that are
generated locally, multi-step jobs, safety checks such as the firewall rule reachability test).
Then follow an existing area: client file, collection in `opnsensetest`, `*_tools.go`, and a
resource built on `itemCRUD` or `settingsCRUD`.
