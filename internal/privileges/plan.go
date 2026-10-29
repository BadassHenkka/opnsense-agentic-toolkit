package privileges

import (
	"sort"
)

// Grant is a privilege picked for a set of endpoints.
type Grant struct {
	Privilege
	// For lists the needed endpoints it was picked for.
	For []string
	// AlsoAllows lists the endpoints known to the toolkit that it grants beyond those needed,
	// such as writes and service restarts. Its patterns may cover more.
	AlsoAllows []string
}

// Plan is a small set of privileges that grants a set of endpoints.
type Plan struct {
	Endpoints []string
	Grants    []Grant
	// Ungranted lists endpoints no privilege grants except "All pages".
	Ungranted []string
	// Optional lists endpoints that work without their privilege, with the reason.
	Optional map[string]string
}

// optional are endpoints a tool or resource calls that need no privilege of their own.
var optional = map[string]string{
	"core/firmware/running": "the lockout check after an apply; a 403 still proves the API answers",
}

// isAll reports whether p grants every page, like "All pages".
func isAll(p Privilege) bool {
	for _, pat := range p.Patterns {
		if pat == "*" {
			return true
		}
	}
	return false
}

// For picks privileges for endpoints. For each endpoint it takes a privilege already picked
// when one grants it, else the narrowest one: the privilege that grants the fewest endpoints
// the toolkit knows. Endpoints with the fewest candidates go first, so the narrow choices
// they force are reused.
func For(endpoints []string) Plan {
	set := map[string]bool{}
	plan := Plan{Optional: map[string]string{}}
	for _, e := range endpoints {
		if why, ok := optional[e]; ok {
			plan.Optional[e] = why
			continue
		}
		set[e] = true
	}
	plan.Endpoints = sortedKeys(set)
	all := known()
	breadth := map[string]int{}
	candidates := map[string][]Privilege{}
	for _, p := range acl {
		if isAll(p) {
			continue
		}
		for _, e := range all {
			if p.Grants(e) {
				breadth[p.Key]++
			}
		}
		for _, e := range plan.Endpoints {
			if p.Grants(e) {
				candidates[e] = append(candidates[e], p)
			}
		}
	}
	order := append([]string(nil), plan.Endpoints...)
	sort.SliceStable(order, func(i, j int) bool { return len(candidates[order[i]]) < len(candidates[order[j]]) })

	picked := map[string]*Grant{}
	var keys []string
	for _, e := range order {
		cands := candidates[e]
		if len(cands) == 0 {
			plan.Ungranted = append(plan.Ungranted, e)
			continue
		}
		sort.SliceStable(cands, func(i, j int) bool {
			_, pi := picked[cands[i].Key]
			_, pj := picked[cands[j].Key]
			if pi != pj {
				return pi
			}
			if breadth[cands[i].Key] != breadth[cands[j].Key] {
				return breadth[cands[i].Key] < breadth[cands[j].Key]
			}
			return cands[i].Name < cands[j].Name
		})
		p := cands[0]
		if picked[p.Key] == nil {
			picked[p.Key] = &Grant{Privilege: p}
			keys = append(keys, p.Key)
		}
		picked[p.Key].For = append(picked[p.Key].For, e)
	}
	for _, k := range keys {
		g := picked[k]
		sort.Strings(g.For)
		for _, e := range all {
			if !set[e] && g.Grants(e) {
				g.AlsoAllows = append(g.AlsoAllows, e)
			}
		}
		plan.Grants = append(plan.Grants, *g)
	}
	sort.Slice(plan.Grants, func(i, j int) bool { return plan.Grants[i].Name < plan.Grants[j].Name })
	sort.Strings(plan.Ungranted)
	return plan
}
