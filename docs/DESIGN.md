# opnsense-agentic-toolkit — design notes

One Go module, one OPNsense API client, two front ends. The split follows who is trusted with what:
the agent explores and may run trial changes through MCP, and the intended end state is
implemented in Terraform, where it is planned, reviewed and recorded in state.

- `mcp-opnsense` — a local (stdio) MCP server so an AI agent can explore OPNsense and verify ideas.
- `terraform-provider-opnsense` — a Terraform provider for declarative management.

Both call the same `internal/opnsense` package, so an endpoint, its JSON quirks and its
apply step are written once.

## What the reference projects do

### Terraform providers

**HashiCorp scaffolding (`terraform-provider-scaffolding-framework`)** — the official
template for new providers. It is built on the Terraform Plugin Framework (SDKv2 template is
archived). Layout: `main.go` at the root, everything else in `internal/provider/` (provider,
one file per resource and data source, `_test.go` next to each), `examples/` (HCL that also
feeds `tfplugindocs`), generated `docs/`, `GNUmakefile`, `.goreleaser.yml`.

**terraform-provider-aws** — the largest provider. Lessons that scale down well:
- One package per service: `internal/service/<service>/`, each resource in its own file,
  tests beside it.
- All new resources must use the Plugin Framework.
- Their contributor guide pushes "one concept per file", cohesive packages, and avoiding
  catch-all `helpers.go` files.
- Shared plumbing (types, flex conversions, validators) lives in small internal packages,
  not in the service packages.

**browningluke/terraform-provider-opnsense** — the existing OPNsense provider. Splits the API
client into its own module (`opnsense-go`, not this repo) and the provider into `internal/service/<name>`.
Every write is followed by the controller's `reconfigure` call.

### Go MCP servers

**Official SDK (`modelcontextprotocol/go-sdk`)** — `mcp.NewServer` + `mcp.AddTool` with a
typed handler `func(ctx, *CallToolRequest, In) (*CallToolResult, Out, error)`. The input and
output JSON schemas are inferred from the `In`/`Out` structs (`json` + `jsonschema` tags),
and returned errors become `isError` tool results. Run over `&mcp.StdioTransport{}`. Tests
can use `mcp.NewInMemoryTransports()` and a real `mcp.Client`.

**github/github-mcp-server** — the best-known Go MCP server. Patterns worth copying:
- `cmd/github-mcp-server` is a thin CLI; server wiring sits in its own package and API
  tools in `pkg/github/` with one `*_tools.go` file per area.
- Tools are grouped into **toolsets** (`--toolsets repos,issues`) so a client only sees what
  it needs.
- `--read-only` registers only read tools; read-only wins over any explicit tool list.
- Tool schemas are snapshotted (`__toolsnaps__`) so API-surface changes show up in review.

## Decisions for this project

| Topic | Decision | Why |
|---|---|---|
| Module | One module, `cmd/` per binary, `internal/` for the rest | Shared client, no publishing overhead yet |
| Client | `internal/opnsense`, one file per API controller | Mirrors OPNsense's `/api/<module>/<controller>` |
| Generic CRUD | `ItemController[T]` for the `addItem/getItem/setItem/delItem/searchItem/reconfigure` pattern | Most MVC controllers share it; a new resource is a model struct plus a few lines |
| TF framework | Plugin Framework, protocol v6 | Current HashiCorp recommendation |
| TF layout | `internal/provider/` until there are ~5 resources, then `internal/service/<area>/` | Scaffolding first, AWS-style split when it pays off |
| MCP SDK | Official `go-sdk`, stdio | Typed tools, schema inference, spec-tracking |
| MCP surface | Narrow tools per resource; toolsets; `--read-only` | Copied from github-mcp-server |
| Apply model | TF: apply after every write. MCP: writes are staged, `*_apply` tool activates | TF must converge per resource; an agent should get a review step |
| Auth | API key/secret via env (`OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`), CA file for self-signed certs | No secrets in config files; TLS verification stays on |

## The generator

Every area needs the same four artefacts (client struct, fake
collection, Terraform resource, MCP tools) and the same mistakes to avoid. OPNsense's model XML
already holds the facts: field types, defaults, option values, ranges, masks, uniqueness. So
`cmd/opnsense-gen` generates them from the XML plus a small JSON spec
([gen/README.md](../gen/README.md)).

- **Pinned input.** `gen/models` holds copies of the XML at the commits in `gen/models/REFS`.
  Upstream changes arrive as a reviewable diff of generated code, never silently.
- **No new runtime machinery.** Generated code instantiates the same `ItemController` and
  `itemCRUD` as hand-written areas, plus their settings counterparts (`SettingsController`,
  `settingsCRUD`, `Server.addSettings`), which are new and also usable by hand-written code.
- **Generated tests.** Each resource gets a create/update/read/import/delete test against the
  fake with example values; the fake enforces the XML's rules (required, options, ranges,
  masks, uniqueness) through `checkFields` and `checkUnique`, so a wrong default or mapping
  fails a test instead of a real apply.
- **Strict by default.** Unknown or custom field types, reserved Terraform names, duplicate
  attributes and spec typos stop generation with the fix to apply.
- **Read-only MCP.** Generated areas expose `_list`/`_get` only. Writes go through Terraform,
  as the `opnsense-iac` skill describes.
- Surprises the generator surfaced at once: the Syslog transport default (`udp`) is not one of
  its options; the cron masks exceed RE2's repeat limit (so `parameters` is only checked by
  OPNsense); VLAN device names are assigned by the server and must never be sent.

Pilot areas: VLANs, virtual IPs, firewall categories, cron jobs, syslog destinations and
settings, tunables.

## First resource: firewall alias

Chosen because it is a clean MVC controller (`/api/firewall/alias`), easy to test safely
(an unused alias affects nothing), and the natural building block for firewall rules later.

Fields handled: `name`, `type`, `content` (list), `description`, `enabled`, `proto`,
`categories`, `updatefreq`. Interface-scoped and GeoIP-specific fields come later.

OPNsense quirks the client absorbs:
- Writes are wrapped: `{"alias": {...}}`.
- `getItem` returns option fields as maps (`{"host": {"value": "Host(s)", "selected": 1}}`);
  the client decodes them to the selected key(s).
- Booleans are `"1"`/`"0"`; `content` is newline-separated on write.
- Validation failures come back as HTTP 200 with `{"result":"failed","validations":{...}}`;
  the client turns that into a `*ValidationError`.
- `delItem` fails while the alias is referenced by a rule.

## Second area: Unbound DNS overrides

The Overrides page is two models in `/api/unbound/settings`, both applied with
`/api/unbound/service/reconfigure` (source: `Unbound.xml` and `Api/SettingsController.php`):

- `hosts.host` via `{add,get,set,del,search}HostOverride`, key `host`. `rr` is A/AAAA/MX/TXT and
  each needs different fields (`server`; `mx`+`mxprio`; `txtdata`). `hostname` may be empty
  or `*`; `domain` is required. `ttl` and `mxprio` are optional integers sent as strings.
- `aliases.alias` via `…HostAlias`, key `alias`. `host` is a ModelRelationField (the host
  override UUID, read back as an option map). `delHostOverride` also deletes the aliases.
  `searchHostAlias` accepts a `host` filter.

What this changed in the shared code:

- `ItemController.Suffix` handles the non-`Item` action names; `SearchWith` passes filters.
- Reconfigure moved to `Client.Reconfigure`, with one lock per client, because two
  controllers now share one apply endpoint and Terraform runs resources in parallel.
- New field types: `Int` (optional integer, `""` when unset) and `Text` (lenient search rows).
- The fake became data-driven (`opnsensetest/collections.go`): each area is a declaration of
  fields, validation and hooks such as the delete cascade.
- The provider got `itemCRUD`, a generic Create/Read/Update/Delete, so a resource is now its
  schema plus `toAPI`/`fromAPI`. The alias resource was moved onto it.

Terraform choices: `host_override_id` on the alias `RequiresReplace`, because replacing the host
override has already deleted the alias server-side. Delete treats "not found" as success
for the same reason. `ValidateConfig` checks the per-type fields at plan time.

Version note: `ttl`, `txtdata` and `addptr` exist only in recent OPNsense releases. On older
ones OPNsense ignores them, and `add_ptr` will show a permanent diff.

## Third area: ACME client plugin

Source: opnsense/plugins `security/acme-client` 4.17 (`AcmeClient.xml`, `Api/*Controller.php`).

- One model, five parts: `settings` (singleton) and the arrays `accounts.account`,
  `validations.validation` (UI: Challenge Types), `actions.action` (UI: Automations) and
  `certificates.certificate`. Terraform and MCP use the UI names.
- Item actions are `add/get/update/del/search` with no suffix. `ItemController.Actions` maps
  the canonical verbs to these names.
- Settings are read with `settings/get` (the whole model) and written with
  `settings/set` as `{"acmeclient":{"settings":{...}}}`. OPNsense merges, so fields we do not
  model are left alone.
- Challenge types have 273 fields (credentials for 123 DNS providers) and automations 78. Only
  the common fields are modelled. Everything else goes through `Params`
  (`marshalWithParams`/`unmarshalWithParams`). Valid names and defaults come at run time
  from the blank template (`get` without a uuid), so no provider list is hard-coded. The
  "relevant" params for display are those under the method/provider prefix plus anything that
  differs from its default, because a few providers break the prefix convention (`dns_azure` →
  `dns_azuredns_*`).
- Status fields (`statusCode`, `lastUpdate`, `certRefId`) are maintained by the plugin. The
  `ReadOnly` type decodes them and, with an `omitzero` tag and an `IsZero` that always reports
  true, is never encoded. A read-modify-write therefore cannot clobber a status that changed in
  the meantime. The fake returns HTTP 400 for writes to read-only fields, to prove it.
- `certificates/sign` starts `lecert.php` through `daemon -f`, so issuing is asynchronous: the
  result appears later in `statusCode` (100 pending, 200 OK, 250 revoked, 300 config error, 400
  validation failed, 500 internal). `certificates/automation` always answers
  `{"result":"failed"}`, so its result is ignored.

Terraform choices:

- `params` is a sensitive map with "managed keys" semantics: read refreshes only configured
  keys, update clears keys removed since the prior state (via the optional `setPrior` hook in
  `itemCRUD`), and `ModifyPlan` checks names against the template so typos fail at plan time.
- Status attributes are computed with no plan modifier, because OPNsense changes them
  independently. `UseStateForUnknown` would promise a value the next apply might contradict.
- `opnsense_acme_settings` is a singleton resource; destroying it only disables the client.
- Certificates are configuration only. Issuing is an imperative action, left to the web UI or
  the MCP tool, not hidden inside a resource lifecycle.
- `alt_names` must be lower case, because OPNsense lower-cases them and Terraform would
  otherwise report an inconsistent result after apply.

MCP choices: credential-looking params are write-only (`(set, hidden)` on read); `*_fields`
tools let the agent discover provider fields instead of guessing; `issue` refuses while the
client is disabled; `issue`, `revoke` and `register` are marked open-world.

## Fourth area: WireGuard

Source: opnsense/core `models/OPNsense/Wireguard/{General,Server,Client}.xml`, the
`FieldTypes/ClientField.php` back-reference and `Api/{Server,Client,General,Service}Controller.php`.

- Three models: `general` (enabled), `server.servers.server` (instance), `client.clients.client`
  (peer). Actions are `{add,get,set,del,search}Server` / `…Client`; reconfigure answers
  `{"result":"ok"}`, so `Client.Reconfigure` accepts `status` or `result`.
- **Membership lives on the instance** (`server.peers`). The peer's `servers` field is
  volatile: `ClientField` computes it on load, and `setClientAction` rewrites every instance's
  peer list from the posted `servers`. Posting a peer *without* `servers` detaches it from all
  instances, and `delClient` removes it from all instances. Decision: the peer owns
  membership. `WireguardPeer.Instances` is always sent, while `WireguardInstance.Peers` is a
  `ReadOnlyList` (decoded, never encoded), so an instance update cannot clobber it. The fake
  implements these semantics with `Field.Virtual` and `Collection.OnWrite`.
- **OPNsense does not derive public keys.** The UI calls `server/keyPair` (and `client/psk`)
  and stores both halves. We generate and derive locally with `crypto/ecdh` X25519 (standard
  library, checked against the RFC 7748 test vector), so key material is never fetched over the
  API, and the stored `pubkey` always matches `privkey`.
- `searchClient` filters by `servers` as an *array*, so `SearchWith` filters became
  `map[string]any`.
- `service/show` is `wg show all dump` enriched with names and `peer-status` (online = handshake
  within 300 s), which makes a useful read-only status tool.
- `instance` (AutoNumber) and `interface` (volatile, `wgN`) are read-only.

Terraform choices: `private_key` is Optional+Computed+Sensitive and generated in Create when
omitted. `public_key` is computed and set in `ModifyPlan` from the planned private key, so a
key rotation shows the new public key in the plan. Custom validators (`validators.go`) check
CIDR notation and key format without echoing secrets.

MCP choices: `wireguard_peer_create` without a public key generates the device keys and returns
a wg-quick config once (the UI's "peer generator", minus storing the device private key on the
firewall). Secrets are never returned by `get` tools.
