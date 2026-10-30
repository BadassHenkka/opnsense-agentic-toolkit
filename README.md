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

The [`opnsense-agentic-toolkit` skill](.claude/skills/opnsense-agentic-toolkit/SKILL.md) teaches Claude Code this workflow.

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
| Routing → FRR (plugin os-frr) | `opnsense_frr_settings`, `opnsense_frr_bgp_{settings,neighbor,peer_group,aspath,community_list,prefix_list,route_map,redistribution}`, `opnsense_frr_ospf_{settings,area,network,neighbor,interface,prefix_list,route_map,redistribution}`, `opnsense_frr_ospf6_*`, `opnsense_frr_rip_settings`, `opnsense_frr_bfd_{settings,neighbor}`, `opnsense_frr_static_{settings,route}` | `frr` (read-only) |
| Services → Postfix (plugin os-postfix) | `opnsense_postfix_settings`, `_antispam_settings`, `_domain`, `_recipient`, `_sender`, `_header_check`, `_recipient_bcc`, `_sender_bcc`, `_address` | `postfix` (read-only) |
| Services → Rspamd (plugin os-rspamd) | `opnsense_rspamd_settings` | `rspamd` (read-only) |
| Services → Monit | `opnsense_monit_settings`, `_alert`, `_test`, `_service` | `monit` (read-only) |
| Services → Kea DHCP | `opnsense_kea_dhcp4_{settings,subnet,reservation,option,peer}`, `opnsense_kea_dhcp6_{settings,subnet,reservation,pd_pool,option,peer}`, `opnsense_kea_ctrl_agent_settings` | `kea` (read-only, plus `kea_lease4_list`, `kea_lease6_list`) |
| Services → Dnsmasq DNS & DHCP | `opnsense_dnsmasq_settings`, `opnsense_dnsmasq_host`, `_domain`, `_tag`, `_range`, `_option`, `_boot` | `dnsmasq` (read-only, plus `dnsmasq_lease_list`) |
| System → Access → Users, Groups | `opnsense_auth_user`, `opnsense_auth_group`, `opnsense_auth_api_key` | `auth` (read-only) |
| System → Trust → Authorities, Certificates, Settings | `opnsense_trust_ca`, `opnsense_trust_cert`, `opnsense_trust_settings` | `trust` (read-only) |
| Interfaces → Assignments, Other Types, Neighbors | `opnsense_interface`, `opnsense_vlan`, `opnsense_virtual_ip`, `opnsense_bridge`, `opnsense_lagg`, `opnsense_gif`, `opnsense_gre`, `opnsense_vxlan`, `opnsense_loopback`, `opnsense_neighbor` | `interfaces` (read-only) |
| Interfaces → VLAN, Virtual IPs | `opnsense_vlan`, `opnsense_virtual_ip` | `interfaces` (read-only) |
| Firewall → Categories | `opnsense_firewall_category` | `firewall` (read-only) |
| Firewall → NAT → Port Forward, Outbound, One-to-One, NPTv6 | `opnsense_firewall_nat_port_forward`, `opnsense_firewall_nat_outbound` (+ `_mode`), `opnsense_firewall_nat_one_to_one`, `opnsense_firewall_nat_npt` | `firewall` (read-only) |
| Services → Intrusion Detection | `opnsense_ids_settings`, `opnsense_ids_policy`, `opnsense_ids_user_rule`, `opnsense_ids_ruleset` | `ids` (read-only) |
| Firewall → Shaper | `opnsense_trafficshaper_pipe`, `opnsense_trafficshaper_queue`, `opnsense_trafficshaper_rule` | `trafficshaper` (read-only) |
| Firewall → Groups | `opnsense_firewall_interface_group` | `firewall` (read-only) |
| System → Cron, Logging, Tunables | `opnsense_cron_job`, `opnsense_syslog_destination`, `opnsense_syslog_settings`, `opnsense_tunable` | `system` (read-only) |
| Services → Caddy Web Server (plugin os-caddy) | `opnsense_caddy_settings`, `opnsense_caddy_domain`, `opnsense_caddy_subdomain`, `opnsense_caddy_handler`, `opnsense_caddy_access_list`, `opnsense_caddy_basic_auth`, `opnsense_caddy_header`, `opnsense_caddy_layer4_route` | `caddy` |

Every resource except `opnsense_firewall_rule`, `opnsense_plugin` and the ACME challenge types and automations is generated from OPNsense's model XML (see [gen/README.md](gen/README.md)) and exposes every field of the model. MCP tools marked read-only belong to generated areas; the others also have write tools.

See [docs/DESIGN.md](docs/DESIGN.md) for the layout, the research behind it, and the roadmap, and [docs/TODO.md](docs/TODO.md) for every OPNsense area still missing.

## Layout

```
cmd/
  mcp-opnsense/                 MCP server binary (flags, env, stdio)
  terraform-provider-opnsense/  Terraform provider binary
internal/
  opnsense/                     shared API client — one file per API controller
    item_controller.go          generic add/get/set/del/search/reconfigure
    firewall_alias.go           alias lookup by name (types generated)
    unbound_overrides.go        Unbound lookups by name (types generated)
    acme_client.go              ACME challenge types, automations, operations (rest generated)
    wireguard.go                WireGuard status, local X25519 key handling (types generated)
    routing.go                  gateway status and lookup (types generated)
    firewall_filter.go          filter rules, ordering, interface list, apply with reachability check
    firmware.go                 packages/plugins, update status, background pkg jobs
    wol.go                      Wake on LAN magic packets (hosts generated)
    caddy.go                    Caddy status, Caddyfile, scheme helpers (types generated)
    settings_controller.go      generic get/set settings sections
    zz_gen_*.go                 generated areas (do not edit)
    opnsensetest/               in-memory fake OPNsense used by all tests (collections.go)
  acceptance/                   tests against a real firewall (task acc)
  mcpserver/                    MCP tools — one *_tools.go file per area, grouped in toolsets
  provider/                     Terraform provider and resources
    item_crud.go                generic Create/Read/Update/Delete + apply for item resources
cmd/opnsense-gen/               code generator
gen/specs/, gen/models/         generator input: specs and pinned OPNsense model XML
examples/                       Terraform and MCP client config
```

## Quick start

Four steps, then one command tells you whether it worked.

**1. Create an API user on the firewall.**
1. System → Access → Users → add a user, e.g. `automation` (a random password you will not use).
2. Edit it → *Effective Privileges* → add only what the areas you use need. Search the list for
   the area name: *Firewall: Alias*, *Firewall: Rules [new]*, *Services: Unbound DNS*, *VPN:
   WireGuard*, *System: Gateways*, *System: Static Routes*, *System: Firmware*, *System: Trust*,
   *Services: Caddy*, *Services: ACME Client*, *Services: Wake on LAN*. Start small; step 4 tells
   you what is missing. OPNsense has no read-only privileges for most pages, so "read-only" is
   enforced by `mcp-opnsense --read-only`, not by the user. Using one user per front end (MCP,
   Terraform) lets you revoke them separately.
3. Same user → *API keys* → **+**. The browser downloads a file with `key=` and `secret=`. The
   secret is shown only once.

**2. Trust the firewall's certificate** (only for a self-signed one): System → Trust →
Authorities → export the CA certificate as PEM and keep it at, say,
`~/.config/opnsense/ca.pem`. Do not use `OPNSENSE_INSECURE` except for a throwaway test.

**3. Build and configure.**

```sh
task build                         # bin/mcp-opnsense and bin/terraform-provider-opnsense
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
[warn] permissions   no access to: firewall rules (Firewall: Rules [new])
       -> System > Access > Users > edit the API user > Effective Privileges; ...
[ok  ] plugins       installed: os-caddy; not installed: os-frr, ...
```

Each failure prints the likely fix (wrong secret, untrusted certificate, wrong port, missing
privilege). Nothing is changed and no secret is printed. When it ends with "Setup looks good",
register the server with your MCP client ([MCP server](#mcp-server) below) and ask it to run
`firmware_status`.

## Build and test

Tools (Go, [Task](https://taskfile.dev), golangci-lint, Terraform) are pinned in `mise.toml`:
`mise trust && mise install` sets them up. Without mise, install Go 1.24+ and Task yourself;
`task --list` shows every task. A git-ignored `.env` with the `OPNSENSE_*` variables is loaded by mise.

```sh
task tidy     # first run: resolves dependencies and writes go.sum
task test
task build    # binaries in ./bin
```

The tests run against an in-memory fake of the OPNsense API, so they need no firewall.

### Acceptance tests (real firewall)

The fake follows the specs, so it cannot tell whether OPNsense really behaves that way.
`internal/acceptance` runs the client against a real firewall with the usual `OPNSENSE_*`
variables:

```sh
task acc                          # read-only: safe on any firewall
OPNSENSE_ACC_WRITE=1 task acc     # also create/update/delete test objects (use a test VM)
```

- **Read-only (default):** lists every item collection and reads every settings section the
  client knows (found by reflection, so new areas are covered automatically), and compares the
  firewall's field names with the Go structs. A field the client has but the firewall lacks
  fails the test (schema drift); fields only the firewall has are logged. Areas of plugins that
  are not installed are skipped. Also reads gateway status, backups and snapshot support.
- **Writes:** a firewall alias, a disabled cron job and a disabled Unbound host override named
  `acc-test-*`, with 192.0.2.0/24 addresses and the `.invalid` domain. Each goes through
  add → get → set → get → set unchanged → delete and checks that OPNsense stores what was
  sent and that writing back what was read changes nothing. Unbound is not applied (that
  would restart the resolver); everything created is deleted, also when a test fails.

Without `OPNSENSE_ACC=1` the same tests run against the fake as part of `task test`.

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
Instance private keys and preshared keys are never returned by `get` or `list` tools.

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

### Secrets

No MCP tool returns a credential, whether from a `list` or a `get`: private keys, preshared
keys, passwords, tokens and API secrets are left out of search results and shown as
`(set, hidden)` or `<name>_set` elsewhere. That includes `backup_diff_get` (credential elements
in config.xml diffs) and `caddy_caddyfile_get`. DynDNS and user passwords have no `_set`
flag: OPNsense never returns them, not even whether one is set. Tools do show public keys. A
test seeds a marker into every sensitive field of the fake firewall and fails if any tool
returns one.

## Terraform provider

```sh
task install-tf   # builds into $(go env GOPATH)/bin
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
terraform import opnsense_trust_ca.home "Home CA"                   # uuid or description
terraform import opnsense_auth_api_key.ci <key>                      # secret stays null
terraform import opnsense_acme_certificate.fw fw.example.com            # ACME objects by name
terraform import opnsense_acme_settings.this acmeclient
terraform import opnsense_wireguard_instance.home home                # WireGuard by name
terraform import opnsense_gateway.site2 WG_SITE2                      # gateway by name
terraform import opnsense_route.site2 192.168.50.0/24                 # route by network
terraform import opnsense_firewall_rule.nas "site2 to NAS"            # rule by description
terraform import opnsense_plugin.ddclient os-ddclient                 # plugin by package name
terraform import opnsense_wol_host.nas nas                            # WoL host by description
```

Config that `tofu plan -generate-config-out` writes for an import has no secrets: OpenTofu
writes each sensitive attribute as `null # sensitive`. An optional secret left unset keeps the
value OPNsense has, so the plan after the import is empty, and `""` clears it. OPNsense never
returns or clears update-only fields, such as the DynDNS password and user passwords. The state
still holds the secrets OPNsense returns, such as WireGuard keys, so keep it encrypted.

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

ACME challenge types and automations have a `params` map for their provider/type fields
(`dns_cf_token`, `sftp_host`, ...). Terraform manages only the keys you set: other fields are
left alone and do not show as drift, and removing a key clears it. Unknown field names fail at
`terraform plan`. The map is sensitive, so pass secrets from variables.

Terraform manages the certificate *configuration*. OPNsense issues and renews the certificate
itself. To issue one immediately, use the web UI or the MCP tool `acme_certificate_issue`.

Don't let both tools write the same object: changes made through MCP show up as drift on the
next `terraform plan`. A simple rule is MCP read-only for anything Terraform manages.

## Claude Code skill

`.claude/skills/opnsense-agentic-toolkit/SKILL.md` teaches Claude Code the workflow this project is built for: explore with MCP, try ideas as short-lived MCP changes that are undone again, implement only through Terraform (plan, summary, your yes, apply), then check the result with MCP.

## Adding a resource

Most areas are **generated**. `cmd/opnsense-gen` reads a spec in `gen/specs/<area>.json` and
the pinned OPNsense model XML in `gen/models`, and writes `zz_gen_*.go` files: client types and
service, fake collections, Terraform resources with tests, and read-only MCP tools. Field types,
defaults, option lists, ranges, masks and uniqueness come from the XML.

1. Find the model and controller: `src/opnsense/mvc/app/models/OPNsense/<Module>/<File>.xml` and
   `controllers/OPNsense/<Module>/Api/*Controller.php` in opnsense/core (or the plugin).
   The controller gives `base`, `key`, `suffix` and any odd action names
   (`searchJobs` instead of `searchJob`).
2. Add it to a spec (see [gen/README.md](gen/README.md)), then `task fetch-models gen test`
   and `task verify-upstream` (checks actions and keys against the upstream controllers).
3. The generator stops on what it cannot know (custom field types, reserved names) and says
   which `fields.<name>` override to add.

Hand-write an area only when the API needs behaviour a spec cannot describe (secrets that are
generated locally, multi-step jobs, safety checks such as the firewall rule reachability test).
Then follow an existing area: client file, collection in `opnsensetest`, `*_tools.go`, and a
resource built on `itemCRUD` or `settingsCRUD`.
