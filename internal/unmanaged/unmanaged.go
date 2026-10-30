package unmanaged

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Object is a live object: its resource type, the id an import takes, and a name to recognise
// it by (empty when the object has none).
type Object struct {
	Type string
	ID   string
	Name string
}

// lister returns the live objects of one resource type. It only makes read calls.
type lister func(ctx context.Context, c *opnsense.Client) ([]Object, error)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// items lists the rows of an item controller. A row whose id is not a UUID is built in or
// automatic, and no resource can manage it: OPNsense gives the static children of a model
// (the bogons and sshlockout aliases, the __<if>_network aliases) their name as id, and
// automatic NAT rules an id like automatic_<service>_<n>.
func items[T any, S opnsense.NamedRow](ctx context.Context, ic *opnsense.ItemController[T, S]) ([]Object, error) {
	return named(ctx, ic, func(r S) string { _, name := r.RowRef(); return name })
}

// named is items with the name taken from name instead of RowRef.
func named[T any, S opnsense.NamedRow](ctx context.Context, ic *opnsense.ItemController[T, S], name func(S) string) ([]Object, error) {
	return rows(ctx, ic, func(r S) (Object, bool) {
		id, _ := r.RowRef()
		return Object{ID: id, Name: name(r)}, uuidRe.MatchString(id)
	})
}

// rows searches ic and keeps the rows keep accepts.
func rows[T, S any](ctx context.Context, ic *opnsense.ItemController[T, S], keep func(S) (Object, bool)) ([]Object, error) {
	res, err := ic.Search(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, r := range res.Rows {
		if o, ok := keep(r); ok {
			out = append(out, o)
		}
	}
	return out, nil
}

// listers returns every type Find can check: the generated item resources, with hand-written
// replacements where the generic search is not enough, and the hand-written resources.
func listers() map[string]lister {
	m := generatedListers()

	// Assignments use the interface identifier (wan, lan, opt3) as id, not a UUID.
	m["opnsense_interface"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return rows(ctx, c.Interfaces.Assignments, func(r opnsense.NetworkInterfaceRow) (Object, bool) {
			id, name := r.RowRef()
			return Object{ID: id, Name: name}, id != ""
		})
	}
	m["opnsense_firewall_alias"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return rows(ctx, c.Firewall.Aliases, func(r opnsense.AliasRow) (Object, bool) {
			return Object{ID: string(r.UUID), Name: string(r.Name)}, uuidRe.MatchString(string(r.UUID)) && r.Type != "internal"
		})
	}
	// Unnamed rows: show what tells them apart in the web UI.
	m["opnsense_unbound_host_override"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return named(ctx, c.Unbound.HostOverrides, func(r opnsense.HostOverrideRow) string { return join(r.FQDN(), string(r.RR)) })
	}
	m["opnsense_unbound_host_alias"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return named(ctx, c.Unbound.HostAliases, opnsense.HostAliasRow.FQDN)
	}
	m["opnsense_unbound_forward"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return named(ctx, c.Unbound.Forwards, func(r opnsense.UnboundForwardRow) string {
			return upstream(string(r.Domain), string(r.Server), string(r.Description))
		})
	}
	m["opnsense_unbound_dot"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return named(ctx, c.Unbound.DoTs, func(r opnsense.UnboundDoTRow) string {
			return upstream(string(r.Domain), string(r.Server), string(r.Description))
		})
	}

	// Hand-written resources.
	m["opnsense_firewall_rule"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		// The search also returns automatic and legacy rules, which the API cannot change;
		// RowRef gives them no id.
		return items(ctx, c.Filter.Rules)
	}
	m["opnsense_acme_challenge_type"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return items(ctx, c.Acme.ChallengeTypes)
	}
	m["opnsense_acme_automation"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		return items(ctx, c.Acme.Automations)
	}
	m["opnsense_plugin"] = func(ctx context.Context, c *opnsense.Client) ([]Object, error) {
		info, err := c.Firmware.Info(ctx)
		if err != nil {
			return nil, err
		}
		var out []Object
		for _, p := range info.Plugins {
			if p.IsInstalled() {
				out = append(out, Object{ID: string(p.Name), Name: string(p.Comment)})
			}
		}
		return out, nil
	}
	return m
}

func join(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func upstream(domain, server, description string) string {
	if domain == "" {
		domain = "(all domains)"
	}
	return join(domain, "->", server, description)
}

// Types returns the resource types Find can list, sorted.
func Types() []string {
	return slices.Sorted(maps.Keys(listers()))
}

// Report is the result of Find.
type Report struct {
	// Checked lists the types Find compared, sorted.
	Checked []string
	// Missing lists live objects that are not in the state, sorted by type and name.
	Missing []Object
	// Unchecked lists the types in the state that Find cannot list, such as API keys.
	// Settings resources are left out: each is one fixed object, which always exists.
	Unchecked []string
	// Errors holds one error per type whose list failed.
	Errors []error
}

// Find lists the live objects of every opnsense_* type in st, plus the extra types, and
// reports those whose id is not in st. It only makes read calls (searches and the firmware
// info), so an API user with read access to the checked pages is enough.
func Find(ctx context.Context, c *opnsense.Client, st *State, extra []string) Report {
	all := listers()
	var rep Report
	want := map[string]bool{}
	for t := range st.IDs {
		switch _, ok := all[t]; {
		case ok:
			want[t] = true
		case !settingsTypes[t]:
			rep.Unchecked = append(rep.Unchecked, t)
		}
	}
	for _, t := range extra {
		if _, ok := all[t]; !ok {
			rep.Errors = append(rep.Errors, fmt.Errorf("%s: cannot list this type (see -list-types)", t))
			continue
		}
		want[t] = true
	}
	rep.Checked = slices.Sorted(maps.Keys(want))
	slices.Sort(rep.Unchecked)

	// The searches are independent; run a few at a time rather than flood php-fpm.
	type result struct {
		objs []Object
		err  error
	}
	results := make([]result, len(rep.Checked))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, t := range rep.Checked {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i].objs, results[i].err = all[t](ctx, c)
		}()
	}
	wg.Wait()

	for i, t := range rep.Checked {
		if err := results[i].err; err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("%s: %w", t, err))
			continue
		}
		for _, o := range results[i].objs {
			if !st.IDs[t][o.ID] {
				o.Type = t
				rep.Missing = append(rep.Missing, o)
			}
		}
	}
	slices.SortFunc(rep.Missing, func(a, b Object) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return rep
}
