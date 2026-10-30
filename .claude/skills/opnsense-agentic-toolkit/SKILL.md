---
name: opnsense-agentic-toolkit
description: Change an OPNsense firewall the reviewable way. Explore live state with the MCP server, verify ideas with short-lived trial changes if needed, and implement every lasting change through Terraform (plan, review, apply). Use for any request to add, change or remove OPNsense config (aliases, DNS, WireGuard, routes, firewall rules, ACME, Caddy, plugins, WoL).
---

# OPNsense: explore with MCP, implement with Terraform

Three roles. **MCP explores**: read anything, as freely as needed. **MCP may verify**: a short-lived trial change to learn whether an idea works, then undone. **Terraform implements**: the proposed end state is HCL that the user plans, reviews and applies. A change made through MCP is never the deliverable; it has no plan, no review and no state.

## Onboarding: get to a working MCP connection

Run this first whenever the OPNsense MCP tools are missing, return errors, or the user is new. Do the steps in order and stop at the first failure; the `--check` output says what to fix. Never ask the user to paste the secret into the chat and never write it to a file in the repo.

1. **Is the MCP server connected?** If `firmware_status` (or any `opnsense` tool) is available and answers, skip to the Setup check below. Otherwise continue.
2. **Binary.** In the clone: `task build` (Go 1.24+ and Task; `mise install` sets both up). The binary is `bin/mcp-opnsense`.
3. **API user and key** (the user does this in the OPNsense UI; give them these steps): System > Access > Users > add `automation`; Effective Privileges > add only the areas they will use (search the list for *Firewall: Alias*, *Firewall: Rules [new]*, *Services: Unbound DNS*, *VPN: WireGuard*, *System: Gateways*, *System: Static Routes*, *System: Firmware*, ...); then API keys > **+** downloads a file with `key=` and `secret=` (the secret is shown once).
4. **Certificate.** If the firewall uses its own CA, export it (System > Trust > Authorities, PEM) to e.g. `~/.config/opnsense/ca.pem` and use `OPNSENSE_CA_FILE`. Do not use `OPNSENSE_INSECURE` except for a throwaway test.
5. **Credentials in the shell** (the user types these; you do not need to see them): `export OPNSENSE_URL=https://<address-of-the-web-ui> OPNSENSE_API_KEY=... OPNSENSE_API_SECRET=... OPNSENSE_CA_FILE=...`
6. **Check.** Run `bin/mcp-opnsense --check`. Each line is `ok`, `warn` or `FAIL`, with a hint. Typical fixes: 401 means wrong key/secret; "certificate is not trusted" means set `OPNSENSE_CA_FILE`; "connection refused" means wrong port or the web UI listens on another interface; `permissions: no access to ...` means add that privilege (or ignore it if the area is not needed). A version warning is not fatal. Repeat until it ends with "Setup looks good".
7. **Register with the MCP client, read-only first.**
   - Claude Code: `claude mcp add opnsense --scope user -e OPNSENSE_URL=... -e OPNSENSE_API_KEY=... -e OPNSENSE_API_SECRET=... -e OPNSENSE_CA_FILE=... -- <clone>/bin/mcp-opnsense --read-only`, then `claude mcp list` should show `opnsense` as connected. Credentials passed with `-e` are stored in the client's config in plain text; offer a wrapper script that reads them from a password manager as the tighter option.
   - Claude Desktop: copy `examples/mcp/claude_desktop_config.json`, fix the paths, restart the app.
   - New servers load in a new session: tell the user to restart the client or start a new chat, then call `firmware_status` to confirm.
8. **Terraform side.** The same API key can be used by the provider, but a separate user per front end can be revoked separately. Continue with First-time setup below.

## Setup check (once per session)

- Prefer the MCP server read-only: `mcp-opnsense --read-only` (only `*_get`, `*_list`, `*_fields`, `*_status` tools register). If write tools such as `*_create` or `*_apply` are visible, trial changes are possible; use them only under "Trial changes" below.
- Terraform: the provider in this repo, configured from `OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` (and `OPNSENSE_CA_FILE`). Actions (`opnsense_wol_wake`) need Terraform 1.14+.
- Work in the user's Terraform directory, not in `internal/`. If there is none, create one next to `examples/terraform/main.tf` and copy its provider block.
- If a tool answers "not found" for a whole area (Caddy, FRR, ACME, ...), the plugin is probably not installed: `bin/mcp-opnsense --check` lists installed plugins, and `opnsense_plugin` installs them.

## First-time setup (state in S3, provider from a local clone)

Do this once per Terraform directory. Ask the user for the bucket/endpoint; never write keys into files or chat.

**1. Build the provider from the clone** (no registry release exists):

```sh
cd <clone>            # e.g. ~/git/opnsense-agentic-toolkit
task install-tf       # builds terraform-provider-opnsense into $(go env GOPATH)/bin
```

Tell Terraform to use that binary instead of downloading it, in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides { "registry.terraform.io/smulis/opnsense" = "/Users/<you>/go/bin" }
  direct {}
}
```

With a dev override, skip `terraform init` for the provider (the "development overrides" warning is expected). Rebuild with `task install-tf` after every `git pull` or code change; Terraform picks up the new binary on the next run.

**2. Keep state in S3.** State holds sensitive values (API secrets, WireGuard keys), so it must not live in git or on a laptop disk only. Any S3-compatible store works (MinIO, Garage, AWS S3):

- Make a private bucket with versioning on (so a bad apply can be rolled back) and a key that can only read/write that bucket.
- Copy `examples/terraform/backend.tf.example` to `backend.tf` in the Terraform directory and set `bucket`, `key` and the endpoint. `use_lockfile = true` gives locking without DynamoDB (Terraform 1.10+; this project needs 1.14 anyway).
- Export the bucket key outside the repo: `export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...` (shell profile or a password manager, not a `.tf` file).
- Run `terraform init` (it configures the backend; if state already exists locally, add `-migrate-state`). Check with `terraform state list`.
- `.gitignore` the Terraform directory's `.terraform/`, `*.tfstate*`, `tfplan` and `terraform.tfvars`.

**3. Check the whole chain** before the first change: `terraform validate`, `terraform plan` (should show only what is in the `.tf` files), and one MCP read such as `firmware_status`. If the plan wants to recreate existing objects, import them first (see Workflow).

## Trial changes (optional, write mode only)

Use these only when reading cannot answer the question (does this rule match, does this record resolve, does the gateway come up). Rules:

1. Ask the user first and name what you will change. Do not touch anything the user has not seen.
2. Take a baseline: note `backup_list` and the objects you will touch.
3. Prefer new, clearly named, disabled or narrowly scoped objects over editing existing ones. Firewall rules start disabled; keep them that way unless the test needs them on.
4. Apply, observe with the read tools, then undo: delete what you created and restore what you edited. Confirm with `backup_diff_get` that the config is back at the baseline.
5. Carry the result into the Terraform change. Anything left behind from a trial collides with the Terraform-managed object of the same name.

If a trial could cut off access (firewall rules, interfaces, routes to the management network), do not run it; reason from the reads and let the Terraform plan carry the risk notes.

## Workflow

1. **Explore.** Find out what exists before writing anything. Use the list/get tools of the relevant toolset, e.g. `firewall_alias_list`, `routing_gateway_list`, `wireguard_status`, `firewall_rule_list`, `caddy_caddyfile_get`, `firmware_plugin_list`. `firewall_interface_list` gives interface names for rules. Provider-specific field discovery: `acme_challenge_type_fields`, `acme_automation_fields`.
2. **Compare with Terraform.** Read the existing `.tf` files and `terraform state list`. Things that exist on the firewall but not in state are either unmanaged on purpose or need importing; ask which when it is unclear.
3. **Write HCL.** Add or edit resources (table below). Reference other resources' ids (`opnsense_caddy_domain.x.id`, `opnsense_gateway.x.name`) instead of copying uuids, so ordering and destroy order are right. OPNsense refuses to delete items that others reference.
4. **Plan.** `terraform fmt`, `terraform validate`, `terraform plan -out=tfplan`. Summarise the plan in plain words: what is created, changed, destroyed, and anything risky (see Risk). Do not apply yet.
5. **Confirm, then apply.** Get an explicit yes from the user for this plan, then `terraform apply tfplan`. Each resource applies its own change on the firewall, so there is no separate apply step.
6. **Verify with MCP.** Read back the result: the list/get tool for the resource, plus `wireguard_status`, `routing_gateway_status`, `caddy_status` / `caddy_caddyfile_get`, `firmware_status`. After an apply, `backup_list` and `backup_diff_get` show exactly what changed in config.xml. Report what you saw, not what you expected.

Existing config to adopt: add the resource block, then `terraform import <addr> <id>`. The id is the uuid, or for most resources the name (`opnsense_route`: the network, `opnsense_caddy_domain`: the domain, `opnsense_caddy_handler`: its description). Settings singletons take any id. Run `plan` afterwards and fix the HCL until it shows no diff.

## Resources

| Area | Terraform | MCP read tools |
|---|---|---|
| Firewall aliases | `opnsense_firewall_alias` | `firewall_alias_{list,get}` |
| Firewall rules | `opnsense_firewall_rule` | `firewall_rule_{list,get}`, `firewall_interface_list` |
| Firewall categories | `opnsense_firewall_category` | `firewall_category_{list,get}` |
| Interface groups | `opnsense_firewall_interface_group` | `firewall_interface_group_{list,get}` |
| NAT (port forward, outbound, 1:1, NPTv6) | `opnsense_firewall_nat_{port_forward,outbound,one_to_one,npt}`, `opnsense_firewall_nat_outbound_mode` | `firewall_nat_*_{list,get}`, `firewall_nat_outbound_mode_get` |
| Traffic shaper | `opnsense_trafficshaper_{pipe,queue,rule}` (rules and queues refer to the pipe/queue `id`) | `trafficshaper_{pipe,queue,rule}_{list,get}` |
| Interface assignments | `opnsense_interface` (applied with a reachability check) | `interface_{list,get}` |
| VLANs, virtual IPs, other device types | `opnsense_vlan`, `opnsense_virtual_ip`, `opnsense_{bridge,lagg,gif,gre,vxlan,loopback}` (device names like `bridge0` are assigned by OPNsense; assign them with `opnsense_interface`), `opnsense_neighbor` (static ARP/NDP) | `<resource>_{list,get}` |
| Gateways, gateway groups, routes | `opnsense_gateway`, `opnsense_gateway_group`, `opnsense_route` | `routing_*_{list,get}` (also `routing_gateway_group_*`), `routing_gateway_status` |
| FRR (BGP, OSPF, OSPFv3, RIP, BFD, static) | `opnsense_frr_settings` (enable first), `opnsense_frr_bgp_*`, `opnsense_frr_ospf_*`, `opnsense_frr_ospf6_*`, `opnsense_frr_rip_settings`, `opnsense_frr_bfd_*`, `opnsense_frr_static_*`; refer to prefix lists/route maps/areas by `id` | `frr_*_{list,get}` |
| WireGuard | `opnsense_wireguard_{settings,instance,peer}` | `wireguard_*_{list,get}`, `wireguard_status` |
| Unbound DNS | `opnsense_unbound_host_override`, `opnsense_unbound_host_alias` | `unbound_host_{override,alias}_{list,get}` |
| Unbound settings, ACLs, forwards, DoT, DNSBL | `opnsense_unbound_{settings,advanced,acl_settings,forwarding,acl,forward,dot,blocklist}` | `unbound_{acl,forward,dot,blocklist}_{list,get}`, `unbound_*_get` for settings |
| Dnsmasq DNS & DHCP | `opnsense_dnsmasq_{settings,host,domain,tag,range,option,boot}` | `dnsmasq_*_{list,get}`, `dnsmasq_settings_get`, `dnsmasq_lease_list` |
| Kea DHCP | `opnsense_kea_dhcp4_*`, `opnsense_kea_dhcp6_*`, `opnsense_kea_ctrl_agent_settings` (do not serve the same interface as Dnsmasq DHCP) | `kea_*_{list,get}`, `kea_lease4_list`, `kea_lease6_list` |
| Dynamic DNS | `opnsense_dyndns_{settings,account}` (password is write-only) | `dyndns_account_{list,get}`, `dyndns_settings_get` |
| ACME client | `opnsense_acme_{settings,account,challenge_type,automation,certificate}` | `acme_*_{list,get}`, `acme_settings_get` |
| CAs, certificates | `opnsense_trust_{ca,cert,settings}` | `trust_{ca,cert}_{list,get}`, `trust_settings_get` |
| Users, groups, API keys | `opnsense_auth_{user,group,api_key}` | `auth_{user,group}_{list,get}`, `auth_api_key_list` |
| Caddy | `opnsense_caddy_{settings,domain,subdomain,handler,access_list,basic_auth,header,layer4_route}` | `caddy_*_{list,get}`, `caddy_status`, `caddy_caddyfile_get` |
| Captive portal | `opnsense_captive_portal_zone` (templates are uploaded in the UI) | `captive_portal_zone_{list,get}` |
| Intrusion detection | `opnsense_ids_{settings,policy,user_rule,ruleset}` (rulesets must be downloaded in the UI first; destroy disables) | `ids_{policy,user_rule}_{list,get}`, `ids_ruleset_list` |
| Mail (Postfix, Rspamd) | `opnsense_postfix_*` (settings, antispam_settings, domain, recipient, sender, header_check, recipient_bcc, sender_bcc, address), `opnsense_rspamd_settings` (SMTP passwords are sensitive) | `postfix_*_{list,get}`, `rspamd_settings_get` |
| Monit | `opnsense_monit_{settings,alert,test,service}` (a service lists `test_ids`) | `monit_*_{list,get}` |
| Prometheus node_exporter | `opnsense_node_exporter_settings` (also needs a pass rule for the scrape port) | `node_exporter_settings_get` |
| Wake on LAN | `opnsense_wol_host`, action `opnsense_wol_wake` | `wol_host_list` |
| High availability | `opnsense_hasync_settings` (pfsync + config sync; peer is configured separately) | `hasync_settings_get` |
| Cron, logging, tunables | `opnsense_cron_job`, `opnsense_syslog_destination`, `opnsense_syslog_settings`, `opnsense_tunable` | `cron_job_*`, `syslog_destination_*`, `syslog_settings_get`, `tunable_*` |
| Plugins | `opnsense_plugin` | `firmware_plugin_list`, `firmware_status` |

Generated resources (from `gen/specs`) document their OPNsense field name in each attribute description; `docs/TODO.md` lists what is missing.

Not covered by Terraform (say so instead of improvising): firmware updates and reboots, and every area marked `[-]` (skipped) in `docs/TODO.md` (OpenVPN, IPsec, HAProxy, CrowdSec, ...). For firmware updates and reboots tell the user to do it in the UI; never route around Terraform with MCP writes.

## Risk: flag these in the plan summary

- **Firewall rules** can cut off the API or the user's own access. New rules are risky near the LAN/management interface; the anti-lockout rule is the safety net. Prefer creating rules disabled (`enabled = false`), checking, then enabling in a second apply.
- **Gateways, routes, WireGuard** changes can drop tunnels; WireGuard needs a WAN rule for the listen port.
- **Caddy** on 80/443 needs the web GUI moved to another port first, and DNS for the names pointing at the firewall.
- **Interfaces**: bridges, LAGGs and assignments can take the management interface down; change them from a console-reachable path. **IDS** in IPS mode (netmap/divert) sits in the traffic path. **Captive portal** blocks every client on its interfaces until they log in.
- **DHCP**: never let Kea and Dnsmasq serve the same interface. **FRR** routes and redistribution can black-hole traffic; **HA sync** pushes configuration to the peer.
- **Destroys**: list every `-` in the plan by name. Deleting a plugin removes its config.
- **Trust**: changing anything but `description` on a CA or certificate replaces it (new key and certificate); services using it must be pointed at the new refid. **API keys** are replaced on any change.
- **Secrets** (WireGuard private keys, API secrets, DNS API tokens, EAB keys) live in Terraform state. Use variables or a secret source, never inline literals in committed files, and never print them from state or MCP output.
- MCP reads never return secrets: hand-written tools show `(set, hidden)`, generated ones a `<name>_set` flag. DynDNS and user passwords have neither: OPNsense does not say whether one is set. Do not try to recover them from the firewall.

## Rules

- No MCP write tools, even for "just a quick fix". If Terraform cannot express it, tell the user and stop.
- One plan per logical change; do not bundle unrelated edits.
- Never `terraform apply -auto-approve`, and never apply a plan the user has not seen summarised.
- If `plan` shows unexpected diffs on untouched resources, stop and report them: the firewall was changed outside Terraform. Show the MCP view of the drift and ask whether to import/adopt or revert.
- Keep answers short: what was read, the plan summary, the result.
