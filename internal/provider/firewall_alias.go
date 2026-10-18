package provider

import "regexp"

// opnsense_firewall_alias is generated (gen/specs/firewall.json). aliasNameRe is its extra
// name validator, stricter than the model's custom AliasNameField can express in a spec.
var aliasNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
