# TODO: everything not yet in the Go client

Goal: every setting of OPNsense configurable through the shared client, the Terraform provider
and (read side) the MCP server.

Source of this list: the `Api/*Controller.php` files of `opnsense/core` (master) and
`opnsense/plugins` (master), read on 2026-10-17. "Item groups" are the `<verb><Name>` action
families (`addX`, `getX`, `setX`, `delX`, `searchX`); each one is normally one Terraform
resource. Check each area against the release the firewall actually runs before starting.

Legend: `[x]` done, `[ ]` open, `[-]` skipped on purpose (not needed in this homelab; revisit if that
changes, the generator makes most of them a spec of ~20 lines). **S** one item group on a known pattern, **M** several groups or special behaviour,
**L** many groups or a risky apply. Every item needs: client + fake collection + client test,
Terraform resource + test, MCP read tools (+ write tools only where useful), docs section.

## Done

Generated (`gen/specs`, models pinned to OPNsense 26.7.7 in `gen/models/REFS`): Dnsmasq, Kea DHCPv4/v6 and control agent, gateway groups, users and groups, CAs, certificates and trust settings, interface assignments, VLANs, virtual IPs, bridges, LAGGs, GIF/GRE/VXLAN tunnels, loopbacks, neighbors, firewall aliases and categories, NAT (port forward, outbound, 1:1, NPTv6), interface groups, traffic shaper, Unbound (overrides, settings, ACLs, forwards, DNS-over-TLS, DNSBL), gateways and static routes, WireGuard, ACME, Wake on LAN, Caddy (incl. basic auth, headers, layer 4), cron, syslog, tunables, Monit, intrusion detection (settings, policies, user rules), captive portal zones, high availability sync settings, dynamic DNS, Prometheus node_exporter, FRR (BGP, OSPF, OSPFv3, RIP, BFD, static), Postfix and Rspamd.

Hand-written: API keys, firewall filter rules, firmware/plugins, ACME challenge types and automations, IDS ruleset toggles, config backup/snapshot read tools, lease lists.

## 0. Before writing 100+ resources by hand

- [x] **Generator** (`cmd/opnsense-gen`, see `gen/README.md`). Every area repeats the same four artefacts. Each `Model.xml` in
      core/plugins already describes fields, types, defaults, option lists and required flags.
      Generate from it: Go struct (`Bool`/`Int`/`Option`/`CSVList`), fake `Collection` fields,
      Terraform schema + `toAPI`/`fromAPI`, MCP view types. Keep hand-written overrides for
      special cases (secrets, renamed fields, virtual fields). Pin the XML version per area and
      snapshot-test the generated output, so a plugin update shows up as a diff.
- [x] **Upstream spec check** (`task verify-upstream`): every spec against the PHP controllers
      at the pinned refs. Found four wrong keys/actions the fake could not catch.
- [x] **Schema drift test**: part of the acceptance read sweep (needs a real firewall).
- [x] **Acceptance tests** (`task acc`, `internal/acceptance`): read sweep of every area with a
      field-name drift check, plus write round trips for an alias, a cron job and a host override.
      Not yet: Terraform-level acceptance tests (terraform-plugin-testing needs the terraform binary).
- [ ] **Run the acceptance tests on an OPNsense VM** and fix what they find.
- [ ] **Raw escape hatch** for settings that have no resource yet: `opnsense_setting` with a
      model path and a map of fields (uses `Params`). Keeps "everything configurable" true while
      resources are added.
- [ ] Common resource features still missing: data sources (lookup by name), `tfplugindocs`,
      goreleaser, import-by-name everywhere, MCP tool-schema snapshot tests.

## 1. Core: network and firewall (highest value for a homelab)

### Interfaces (`Interfaces/*`)
- [x] **Assignment** `interfaces/assignment` (generated; applied with a reachability check,
      import by identifier or description).
- [x] **VLAN** `interfaces/vlan_settings` (generated).
- [x] **Bridge, LAGG, GIF, GRE, VXLAN, Loopback** (generated; wireless has no model in 26.7.7).
- [x] **Virtual IPs** `vip_settings` (generated; `UnusedVhid` helper still to do).
- [x] **Neighbors** `neighbor_settings` (generated).
- [-] **Interface general settings** `interfaces/settings`. **S**
- [-] Interface **IP configuration** (type, address, gateway, DHCP options, MTU, descriptions):
      not found in core master as a model controller; confirm for the target release. If it is
      missing, this stays UI-only until upstream adds it.
- [-] Read-only for MCP: `overview` (interfacesInfo), `diagnostics/interface` (ARP, NDP, routes,
      statistics, VIP/CARP status).

### Firewall (`Firewall/*`)
- [x] **NAT port forward** `firewall/d_nat` (generated; `moveRuleBefore` and import/export not yet).
- [x] **NAT outbound** `firewall/source_nat` incl. the outbound mode switch, **NAT 1:1**,
      **NAT NPTv6** (generated; `moveRuleBefore` and import/export not yet).
- [x] **Firewall categories** `firewall/category` (generated).
- [x] **Interface groups** `firewall/group` (generated).
- [-] **Firewall settings** (advanced: optimisation, bogons, state limits, `firewall/settings`). **S**
- [-] Filter rule extras: `listRuleIds`, rule stats, log queries, `flushStates`, `killStates`
      (read: `diagnostics/firewall` state, log, pftop). Support floating/automation rules fully.
- [-] Alias extras: GeoIP, `import`/`export`, `findReferences`, table size. **S**
- [x] **Traffic shaper** `trafficshaper/settings`: pipes, queues, rules (generated; up/download not yet).
- [-] **Schedules**, **limiters**: check whether an API exists; none found in core master.

### Routing (`Routing/*`, `Routes/*`)
- [x] **Gateway groups** `routing/group_settings` (generated; tiers 1–5, trigger, pool options).
- [x] Gateway *general* settings: the 26.7.7 model has none.

### DHCP, DNS, IPv6 RA
- [x] **Kea DHCPv4/v6**: subnets, reservations, options, PD pools, HA peers, general settings,
      control agent (generated); lease lists (MCP). Still open: DDNS daemon `kea/ddns`,
      reservation import/export. Not run in the homelab (Dnsmasq is), so untested on real hardware.
- [x] **Dnsmasq** `dnsmasq/settings`: general + DHCP settings, hosts, domains, ranges, options, tags,
      boot (generated); leases via `dnsmasq_lease_list` (MCP). Still open: hosts import/export.
- [x] **Unbound**: general/advanced settings, ACLs, forwards, DNS-over-TLS, **DNSBL** (generated;
      blocklists are refreshed on apply). Still open: reads of stats, queries, cache.
- [-] **Router advertisements** `radvd`, **DHCP relay** `dhcrelay`. **S** each
- [-] ISC DHCP (legacy): only leases are in the API; settings are UI-only.

### Services in core
- [x] **Cron** `cron/settings` (jobs, generated).
- [x] **Syslog** `syslog/settings` (destinations and general, generated).
- [x] **Monit** (general, alerts, tests, services; generated).
- [-] **NetFlow** (`diagnostics/netflow`: setconfig), **Host discovery** settings. **S**
- [x] **Captive portal** zones (generated). Still open: templates (base64 upload), vouchers, sessions (read).
- [x] **Intrusion detection (Suricata)**: general settings, policies, user rules (generated), ruleset
      enable/disable (hand-written). Still open: eve log options (3 levels deep, generator
      limit), rule download/update actions, per-rule action overrides, alerts (read). **M**
- [-] **NTP** (`ntpd`: only status in the API; config is UI-only).
- [x] **High availability** settings `core/hasync` (generated). Still open: status/sync actions.

## 2. Core: system, users, certificates

- [x] **Users** and **Groups** (generated; membership is set on the user), **API keys**
      (hand-written; the secret is only known at creation). Still open: OTP seeds, import/export,
      reading `auth/priv`.
- [x] **Trust**: CAs, certificates (create, import, CSR, sign) and settings (generated, write-only
      creation parameters; only the description changes in place). Still open: CRLs `trust/crl`,
      in-place reissue, `generateFile` downloads.
- [x] **Tunables** `core/tunables` (generated).
- [x] **Backups / snapshots** (read-only MCP): `backup_list`, `backup_diff_get`, `snapshot_list`.
      Deliberately not offered: download (holds all secrets), revert, delete, snapshot create/activate.
- [-] **Firmware options** `core/firmware` (mirror, flavour, subscription), reboot/poweroff
      (`core/system`) as Terraform **actions**, not resources. **S**
- [-] **Services** `core/service` (start/stop/restart) as an action. **S**
- [-] **Initial setup / defaults** (`core/initial_setup`, `core/defaults` factory reset): do not
      expose factory reset; initial setup only as a documented manual step.
- [-] System **general** (hostname, domain, DNS servers, timezone, language) and
      **administration** (web GUI port/protocol, SSH, console): no MVC controller found in core
      master. Confirm per release. Without an API these stay manual, and the Caddy move of the
      web GUI off 443 is one of them.
- [-] Read-only diagnostics for MCP: `diagnostics/system` (resources, disk, temperature),
      `diagnostics/log`, `diagnostics/traffic`, `systemhealth`, ping/traceroute/portprobe/packet
      capture (as actions or MCP-only tools).

## 3. VPN

- [-] **OpenVPN** `openvpn/instances` (+ static keys, `genKey`), `openvpn/client_overwrites`,
      export read. **M** (instances model replaced the legacy servers/clients in 24.x)
- [-] **IPsec** `ipsec/*`: connections with children, locals, remotes (swanctl), pools, pre-shared
      keys, key pairs, VTI, manual SPD, settings; sessions/SAD/SPD read. **L**
- [-] WireGuard: client/server legacy endpoints are not needed; check `ServerInfo`/`psk`
      helpers only if useful.
- [-] Plugins: **Tailscale** (settings, subnets), **NetBird**, **ZeroTier** (settings, networks),
      **tinc** (hosts, networks), **OpenConnect**, **stunnel**, **shadowsocks**, **Cloudflared**,
      **sslh**. **S** to **M** each

## 4. Plugins by interest (all use the same `Api` pattern; many are `get`/`set` singletons)

Proxies and web
- [-] **HAProxy** `haproxy/settings`: frontends, backends, servers, healthchecks, ACLs, actions,
      users, groups, mapfiles, error files, Lua, CPU, FCGI; maintenance, export. **L**
- [-] **Nginx** (`www/nginx`: upstreams, locations, server blocks, streams, TLS), **Squid**
      (general, PAC, ACLs, remote blacklists), **OPNProxy** ACL, **c-icap**,
      **web-proxy-sso**. **L**, **L**, **S**
- [x] **Caddy**: basic auth users, headers and layer4 routes (generated). Still open: layer4
      OpenVPN keys, general fields not yet modelled (timeouts, trusted proxies, DynDNS, auth
      providers). **S**

DNS and addressing
- [-] **BIND** (acl, domains: primary/secondary/forward, records, dnsbl, general), **dnscrypt-
      proxy** (servers, forwards, cloaks, whitelist, dnsbl), ~~**ddclient**~~ (done: accounts, settings),
      **chrony**, **tftp**, **mDNS repeater**, **ndp-proxy-go**, **tayga** (NAT64),
      **udpbroadcastrelay**, **ftp-proxy**, **relayd**. **S** to **M**

Security
- [-] **CrowdSec** (general, machines, bouncers, collections, scenarios, parsers, decisions,
      alerts; mostly read + a few settings), **ClamAV**, **Tor**, **maltrail**, **Wazuh agent**,
      **Q-Feeds**, **etpro-telemetry**. **S** to **M**
- [-] **FreeRADIUS** (clients, users, eap, ldap, proxy, dhcp, general), **radsecproxy**. **L**

Routing protocols
- [x] **FRR** (`net/frr`): general, BGP (neighbors, peer groups, prefix lists, route maps, AS paths,
      community lists, redistribution), OSPF and OSPFv3, RIP, BFD, static routes (generated).
      Still open: diagnostics (read), BGP/OSPF route and neighbor status.

Monitoring and system
- [-] **Telegraf** (general, inputs, outputs, keys), **collectd**, **net-snmp** (+ users),
      **NRPE** (commands), **Zabbix agent/proxy**, **Netdata**, ~~**node_exporter**~~ (done), **Munin**,
      **lldpd**, **vnstat**, **ntopng**, **netflector**, **NUT**, **apcupsd**,
      **qemu-guest-agent**, **hw-probe**, **smart**, **beats**, **puppet-agent**. **S** each
- [x] **Mail**: Postfix (general, antispam, domains, senders, recipients, address maps, header checks,
      BCC maps) and Rspamd settings (generated). Still open: Rspamd rate limit tables (3 levels deep),
      queue/log read tools.
- [-] Tools: **iperf**, **redis**, **turnserver**, **siproxd**. **S** each

## 5. Status

Everything with a generator-friendly API is done (see the Done list and the `[x]` items). The
decision on 2026-10-17: **all remaining feature areas are skipped** and stay documented here as
`[-]`, to be picked up only when the homelab needs them:

- VPN: OpenVPN, IPsec, Tailscale, NetBird, ZeroTier, tinc and the other VPN plugins.
- Proxies and web: HAProxy, Nginx, Squid and friends (Caddy is the reverse proxy).
- DNS plugins: BIND, dnscrypt-proxy, chrony and the small DNS/addressing plugins.
- Security: CrowdSec, ClamAV, Tor, FreeRADIUS and the other security plugins.
- Monitoring plugins: Telegraf, net-snmp, Zabbix, Netdata and the rest.
- Small core extras: interface general settings, firewall advanced settings, filter/alias extras,
  NetFlow, NTP, router advertisements and DHCP relay, firmware options and service actions,
  diagnostics read tools.

Still open as quality work (section 0): the schema drift test, acceptance tests against a real
OPNsense VM, the raw `opnsense_setting` escape hatch, data sources and generated docs.

## Not configurable through an API (document, do not fake)

Anything without an MVC controller in the target release: system general/administration,
interface IP configuration (if still legacy), ISC DHCP settings, NTP settings, SNMP in core,
firewall schedules, repositories/mirrors beyond the firmware options. For these the repo should
say so in the resource docs and the MCP tool descriptions, and track the upstream issue.

## 6. Explore / verify / implement (project direction)

The repo was renamed `opnsense-agentic-toolkit` on 2026-10-18. MCP explores and may run trial
changes; Terraform implements. Open ideas to make the verify step safer:

- [ ] A trial-change session: the server records what the agent created or edited through write
      tools and offers a single `trial_revert` tool that undoes it, so nothing is left behind.
- [ ] A `trial_status` read tool that lists open trial changes and compares the config against the
      baseline backup.
- [ ] Refuse trial writes on lockout-prone areas (interfaces, management-network routes) unless
      explicitly allowed.
- [x] `terraform plan` helper: show which live objects are not in Terraform state (drift and
      leftovers from trials). `cmd/opnsense-unmanaged`, see the README.
