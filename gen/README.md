# Generator input

`cmd/opnsense-gen` turns these files into `zz_gen_*.go` (client, fake, Terraform resources and
tests, read-only MCP tools). Run `task gen` after editing; `task gen-check` (and the test
`TestGeneratedUpToDate`) fails when generated code is stale. `task verify-upstream` checks every
spec against the PHP API controllers at the pinned refs (actions, `key`/`node` used by
getBase/setBase/addBase, the settings root key, reconfigure endpoints). The fake server follows the
specs, so a wrong key passes every local test; run it after adding or changing a spec.

- `models/` — OPNsense model XML, pinned to the commits in `models/REFS`. `task fetch-models`
  downloads every model a spec mentions. To follow upstream, bump `REFS`, fetch, regenerate and
  review the diff: new fields, changed options and removed fields all show up there.
- `specs/<area>.json` — one file per area. The area name is the MCP toolset and, camel-cased,
  the client service (`client.Interfaces.VLANs`); set `service` when camel-casing gives an odd
  name (`ids` → `IDS`, `trafficshaper` → `TrafficShaper`).

## Spec

```json
{
  "area": "interfaces",
  "title": "shown in doc comments",
  "items": [{
    "resource": "vlan",                 // opnsense_vlan; MCP vlan_list, vlan_get
    "go_name": "VLAN",                  // optional; default camel-cased resource
    "plural": "VLANs",                  // optional; ItemController field name
    "description": "Terraform resource description",
    "model": "core/Interfaces/Vlan.xml",          // or plugins/<cat>/<plugin>/<Module>/<File>.xml
    "node": "vlan",                     // dotted path below <items>, e.g. "jobs.job"
    "base": "interfaces/vlan_settings", // controller URL
    "key": "vlan",                      // request/response wrapper (first arg of getBase/addBase)
    "suffix": "Item",                   // addItem, getItem, ...
    "actions": {"search": "searchJobs"},// verbs whose action name does not follow the suffix
    "reconfigure": "interfaces/vlan_settings/reconfigure",   // "" when nothing needs applying
    "name_field": "vlanif",             // import / MCP lookup by this field
    "fields": {
      "if":     {"attr": "parent", "type": "ref", "description": "..."},
      "vlanif": {"attr": "device", "computed": true, "fake_value": "vlan0.%d"},
      "secret": {"sensitive": true},
      "legacy": {"skip": true}
    },
    "example": {"if": "igb1", "tag": "10"},  // API values for the generated test
    "update":  {"tag": "20"}                 // changed in the update step
  }],
  "settings": [{
    "resource": "syslog_settings", "model": "core/Syslog/Syslog.xml", "node": "general",
    "get": "syslog/settings/get", "set": "syslog/settings/set", "path": ["syslog", "general"],
    "reconfigure": "syslog/service/reconfigure",
    "disable": "enabled"                // optional: set false on destroy
  }]
}
```

(JSON has no comments; they are for explanation only.)

### More options

Area: `embed` (a hand-written struct embedded in the service, for state its methods need —
ACME's challenge types), `mcp: false` (hand-written MCP tools cover the area).

Object: `suffix: ""` with `actions` for controllers whose verbs have no suffix (`auth/user/add`),
`zero_field` (field whose emptiness means "not found"; `-` for none), `mcp: false`,
`hooks` (`to_api`, `from_api`: hand-written model methods `hookToAPI`/`hookFromAPI` the
generated conversion calls — WireGuard key generation), `custom_import` (ImportState is
hand-written), `apply` (name of a hand-written `<Area>Service` method the resource calls
instead of the plain reconfigure — DNSBL refresh, interface reachability check), `no_test` (items whose test needs other items; a hand-written test covers them),
`id` (constant id of a settings resource), `plural` (service field name; for settings e.g.
`General`).

Field:

| option | effect |
|---|---|
| `attr`, `go_name` | Terraform attribute and client field names (the Terraform model uses the attribute's name) |
| `type`, `sep`, `tf_type` | kind override; list separator (`"\n"`); `set` or `list` in Terraform |
| `required`, `default`, `no_default` | Terraform only; the fake keeps the model's own default |
| `invert` | boolean exposed negated (`disabled` → `enabled`) |
| `as_bool` | two-value option as a boolean: `{"true": "0", "false": "1"}` |
| `values` | option values renamed: `{"https": "1"}` |
| `validators`, `plan_modifiers` | Go expressions appended to the attribute |
| `computed`, `include`, `tf: false` | OPNsense-maintained (never sent); generate a volatile field; leave a computed field out of Terraform |
| `tf_computed`, `tf_unstable` | computed only in Terraform (set by a hook, still sent); changes on its own (no UseStateForUnknown) |
| `write_only` | OPNsense does not return the value faithfully (volatile creation parameters, PEM payloads): reads keep what Terraform has and only fill an unknown or, for a secret with a default, a null value; sensitive write-only attributes without a default are optional only, so a generated private key never reaches the state |
| `sensitive` | an optional secret has no default: unset, it plans as the value in the state, since config generated by an import writes it as null; `""` clears it |
| `skip`, `fake_value` | |

Nested containers (one level, e.g. NAT `source`/`destination`): the field `source.network`
becomes the attribute `source_network` and the client field `Source.Network`. Children of
settings and ArrayFields inside an item are skipped; they are separate resources.

## Extending generated code

Generated types are ordinary Go types in their package, so hand-written files add methods to
them: `ValidateConfig`, `ModifyPlan` or `ImportState` on `gen<Name>Resource`, extra methods on
`<Area>Service`, `FQDN()` on a row. Hand-written fake code looks up a generated collection with
`s.collection(base, key)` and adds cross-item rules with `alsoValidate`, `CanDelete`,
`OnDelete`, virtual fields or fixed option lists. Hand-written tests start from
`gen<Name>Plan()` and change what they need.

## Field mapping

| XML | kind | Client | Terraform |
|---|---|---|---|
| BooleanField | bool | `Bool` | bool, default from XML |
| IntegerField | int | `Int` | number, range validator |
| OptionField | option / options (Multiple) | `Option` / `CSVList` | string / set, `OneOf` validator |
| ModelRelation, Interface, Certificate, JsonKeyValueStore, ... | ref / refs | `Option` / `CSVList` | string / set |
| Text-like fields | string, list (AsList) | `string` / `CSVList` | string (mask validator) / list |
| UpdateOnlyTextField | string, sensitive | `string` | sensitive string, kept when read back empty or unset |
| AutoNumberField or `computed` | computed | `ReadOnly` (never sent) | computed string |
| `volatile="true"`, nested containers | skipped | | |

Custom field types (`.\FooField`) need `"type"` in the spec: read the class in the model's
`FieldTypes/` directory and pick the base it extends. A required field without a default
becomes a required attribute; everything else is optional with the XML default. A default
that is not one of the field's options is ignored (the Syslog transport ships one).

Masks are translated from PCRE to Go when RE2 can express them; others are only enforced by
OPNsense. Like OPNsense, the validator accepts "" unless the field is required, so `= ""` clears
a field. `UniqueConstraint`s are enforced by the fake.

## What stays hand-written

The generic machinery (`ItemController`, `SettingsController`, `itemCRUD`, `settingsCRUD`, the
fake), whole areas a spec cannot describe — firewall rules (ordering, lockout check), firmware
(background jobs), ACME challenge types and automations (hundreds of provider fields, passed as
`params`) — and the extensions above. MCP tools of areas that had them before the generator
(alias, Unbound, ACME, WireGuard, routing, WoL, Caddy) stay hand-written, including their write
tools; generated areas get read-only tools, and changes go through Terraform (see
`.claude/skills/opnsense-agentic-toolkit`).
