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
