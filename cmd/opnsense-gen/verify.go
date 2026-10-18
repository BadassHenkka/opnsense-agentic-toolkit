package main

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

// verifyUpstream checks every spec against the PHP API controllers at the pinned refs: the
// item actions exist, getBase/setBase/addBase use the spec's key and node, settings responses
// use the expected root key, and the reconfigure endpoint exists. The fake server mirrors the
// specs, so a wrong key or action passes every local test and only fails on a real firewall;
// this catches that class of bug without one.
func verifyUpstream(root string) ([]string, error) {
	refs, err := readRefs(filepath.Join(root, "gen", "models", "REFS"))
	if err != nil {
		return nil, err
	}
	areas, err := loadSpecs(filepath.Join(root, "gen", "specs"), filepath.Join(root, "gen", "models"))
	if err != nil {
		return nil, err
	}
	return verifyAreas(areas, newControllerSource(refs, httpGet)), nil
}

func httpGet(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// controllerSource fetches controller PHP by model path and controller name, with its parent
// class appended when that parent lives in the same module (e.g. QuaggaControllerBase).
type controllerSource struct {
	refs  map[string]string
	get   func(url string) (string, error)
	cache map[string]string
	errs  []string
}

func newControllerSource(refs map[string]string, get func(string) (string, error)) *controllerSource {
	return &controllerSource{refs: refs, get: get, cache: map[string]string{}}
}

func (s *controllerSource) url(model, controller string) string {
	p := strings.Split(model, "/")
	if p[0] == "core" {
		return fmt.Sprintf("https://raw.githubusercontent.com/opnsense/core/%s/src/opnsense/mvc/app/controllers/OPNsense/%s/Api/%sController.php",
			s.refs["core"], p[1], controller)
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/opnsense/plugins/%s/%s/%s/src/opnsense/mvc/app/controllers/OPNsense/%s/Api/%sController.php",
		s.refs["plugins"], p[1], p[2], p[3], controller)
}

func (s *controllerSource) fetch(url string) string {
	if v, ok := s.cache[url]; ok {
		return v
	}
	v, err := s.get(url)
	if err != nil {
		s.errs = append(s.errs, err.Error())
	}
	s.cache[url] = v
	return v
}

var (
	extendsRe      = regexp.MustCompile(`class\s+\w+\s+extends\s+(\w+)`)
	modelName      = regexp.MustCompile(`internalModelName\s*=\s*['"]([^'"]+)`)
	frameworkBases = map[string]bool{
		"ApiControllerBase": true, "ApiMutableModelControllerBase": true,
		"ApiMutableServiceControllerBase": true, "ApiMutableTableModelControllerBase": true,
	}
)

// load returns the controller's own source and the source including a same-module parent;
// own is "" when the controller does not exist.
func (s *controllerSource) load(model, controller string) (own, full string) {
	own = s.fetch(s.url(model, controller))
	full = own
	if m := extendsRe.FindStringSubmatch(own); m != nil && !frameworkBases[m[1]] {
		full += s.fetch(s.url(model, strings.TrimSuffix(m[1], "Controller")))
	}
	return own, full
}

// controllerName maps a URL segment to the PHP class: reverse_proxy -> ReverseProxy.
func controllerName(seg string) string {
	var b strings.Builder
	for _, p := range strings.FieldsFunc(seg, func(r rune) bool { return r == '_' || r == '-' }) {
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}

func hasAction(src, action string) bool {
	return regexp.MustCompile(`(?i)function\s+` + regexp.QuoteMeta(action) + `Action\s*\(`).MatchString(src)
}

// actionBody returns the body of an action method, up to the closing brace at method indent.
func actionBody(src, action string) string {
	loc := regexp.MustCompile(`(?i)function\s+` + regexp.QuoteMeta(action) + `Action\s*\(`).FindStringIndex(src)
	if loc == nil {
		return ""
	}
	rest := src[loc[1]:]
	if end := strings.Index(rest, "\n    }"); end >= 0 {
		return rest[:end]
	}
	return rest
}

func (o *Object) action(verb string) string {
	if a, ok := o.Actions[verb]; ok {
		return a
	}
	suffix := o.Suffix
	if suffix == "" {
		suffix = "Item"
	}
	return verb + suffix
}

func verifyAreas(areas []*Area, src *controllerSource) []string {
	var problems []string
	bad := func(o *Object, format string, args ...any) {
		problems = append(problems, o.Resource+": "+fmt.Sprintf(format, args...))
	}
	checkReconfigure := func(o *Object) {
		if o.Reconfigure == "" {
			return
		}
		seg := strings.Split(o.Reconfigure, "/")
		if len(seg) != 3 {
			bad(o, "reconfigure %q is not module/controller/action", o.Reconfigure)
			return
		}
		model := o.Model
		if mod := strings.Split(model, "/")[modelModuleIndex(model)]; !strings.EqualFold(seg[0], mod) && strings.HasPrefix(model, "core/") {
			// Another core module, e.g. routes/routes/reconfigure for gateways (Routing).
			model = "core/" + controllerName(seg[0]) + "/x.xml"
		}
		own, full := src.load(model, controllerName(seg[1]))
		switch {
		case own == "":
			bad(o, "reconfigure controller for %s not found", o.Reconfigure)
		case !hasAction(full, seg[2]) && !strings.Contains(own, "ApiMutableServiceControllerBase"):
			bad(o, "no %sAction for %s", seg[2], o.Reconfigure)
		}
	}
	keyRe := func(fn string) *regexp.Regexp {
		return regexp.MustCompile(fn + `\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]`)
	}
	for _, a := range areas {
		for _, o := range a.Items {
			seg := strings.Split(o.Base, "/")
			if len(seg) != 2 {
				bad(o, "base %q is not module/controller", o.Base)
				continue
			}
			own, full := src.load(o.Model, controllerName(seg[1]))
			if own == "" {
				bad(o, "controller %s not found", o.Base)
				continue
			}
			// A __call handler (Unbound's Dot -> Forward) serves actions that are not methods.
			magic := strings.Contains(full, "function __call(")
			for _, verb := range []string{"add", "get", "set", "del", "search"} {
				if !hasAction(full, o.action(verb)) && !magic {
					bad(o, "%s has no %sAction", o.Base, o.action(verb))
				}
			}
			for verb, fn := range map[string]string{"get": "getBase", "set": "setBase", "add": "addBase"} {
				if m := keyRe(fn).FindStringSubmatch(actionBody(full, o.action(verb))); m != nil && (m[1] != o.Key || m[2] != o.Node) {
					bad(o, "%s uses key %q node %q, spec has key %q node %q", fn, m[1], m[2], o.Key, o.Node)
				}
			}
			checkReconfigure(o)
		}
		for _, o := range a.Settings {
			for _, ep := range []string{o.Get, o.Set} {
				seg := strings.Split(ep, "/")
				if len(seg) != 3 {
					bad(o, "endpoint %q is not module/controller/action", ep)
					continue
				}
				own, full := src.load(o.Model, controllerName(seg[1]))
				if own == "" {
					bad(o, "controller for %s not found", ep)
					continue
				}
				if seg[2] != "get" && seg[2] != "set" && !hasAction(full, seg[2]) {
					bad(o, "no %sAction for %s", seg[2], ep)
				}
				// The default getAction answers {internalModelName: ...}.
				if ep == o.Get && seg[2] == "get" && !hasAction(own, "get") {
					if m := modelName.FindStringSubmatch(full); m != nil && len(o.Path) > 0 && m[1] != o.Path[0] {
						bad(o, "path starts with %q but the controller's model name is %q", o.Path[0], m[1])
					}
				}
			}
			checkReconfigure(o)
		}
	}
	return append(problems, src.errs...)
}

// modelModuleIndex is the index of the module directory in a model path.
func modelModuleIndex(model string) int {
	if strings.HasPrefix(model, "plugins/") {
		return 3
	}
	return 1
}
