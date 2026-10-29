package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// fetchModels downloads every model XML the specs reference, at the commits pinned in
// gen/models/REFS ("core <sha>" and "plugins <sha>" lines). Model paths are
//
//	core/<Module>/<File>.xml                       -> opnsense/core    src/opnsense/mvc/app/models/OPNsense/...
//	plugins/<category>/<plugin>/<Module>/<File>.xml -> opnsense/plugins <category>/<plugin>/src/opnsense/mvc/app/models/OPNsense/...
//
// Update a pin by editing REFS, running -fetch, then regenerating and reviewing the diff.
func fetchModels(root string) error {
	refs, err := readRefs(filepath.Join(root, "gen", "models", "REFS"))
	if err != nil {
		return err
	}
	specs, err := filepath.Glob(filepath.Join(root, "gen", "specs", "*.json"))
	if err != nil {
		return err
	}
	models := map[string]bool{}
	for _, f := range specs {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if rest, ok := strings.CutPrefix(line, `"model": "`); ok {
				models[strings.TrimSuffix(strings.TrimSuffix(rest, ","), `"`)] = true
			}
		}
	}
	for _, m := range sortedKeys(models) {
		u, err := modelURL(m, refs)
		if err != nil {
			return err
		}
		resp, err := http.Get(u)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", u, resp.Status)
		}
		dst := filepath.Join(root, "gen", "models", filepath.FromSlash(m))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, body, 0o644); err != nil {
			return err
		}
		fmt.Println("fetched", m)
	}
	return fetchACLs(root, refs, models)
}

// fetchACLs downloads the ACL.xml of every core module, and of the plugins the specs use, next
// to the models: core/<Module>/ACL/ACL.xml and plugins/<cat>/<plugin>/<Module>/ACL/ACL.xml.
// They name the privileges an API user needs (see internal/privileges).
func fetchACLs(root string, refs map[string]string, models map[string]bool) error {
	plugins := map[string]bool{}
	for m := range models {
		if p := strings.Split(m, "/"); p[0] == "plugins" && len(p) >= 5 {
			plugins[p[1]+"/"+p[2]] = true
		}
	}
	const mvc = "src/opnsense/mvc/app/models/OPNsense/"
	for _, repo := range []string{"core", "plugins"} {
		paths, err := treePaths(repo, refs[repo])
		if err != nil {
			return err
		}
		for _, p := range paths {
			if !strings.HasSuffix(p, "/ACL/ACL.xml") {
				continue
			}
			var dst string
			switch rest, ok := strings.CutPrefix(p, mvc); {
			case repo == "core" && ok:
				dst = "core/" + rest
			case repo == "plugins":
				parts := strings.SplitN(p, "/", 3)
				sub, ok := strings.CutPrefix(parts[2], mvc)
				if len(parts) < 3 || !ok || !plugins[parts[0]+"/"+parts[1]] {
					continue
				}
				dst = "plugins/" + parts[0] + "/" + parts[1] + "/" + sub
			default:
				continue
			}
			body, err := download(fmt.Sprintf("https://raw.githubusercontent.com/opnsense/%s/%s/%s", repo, refs[repo], p))
			if err != nil {
				return err
			}
			out := filepath.Join(root, "gen", "models", filepath.FromSlash(dst))
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			fmt.Println("fetched", dst)
		}
	}
	return nil
}

// treePaths lists the files of a repository at ref through the GitHub API.
func treePaths(repo, ref string) ([]string, error) {
	body, err := download(fmt.Sprintf("https://api.github.com/repos/opnsense/%s/git/trees/%s?recursive=1", repo, ref))
	if err != nil {
		return nil, err
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil, err
	}
	if tree.Truncated {
		return nil, fmt.Errorf("%s tree at %s is truncated", repo, ref)
	}
	var out []string
	for _, t := range tree.Tree {
		out = append(out, t.Path)
	}
	return out, nil
}

func download(u string) ([]byte, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return body, nil
}

func readRefs(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && !strings.HasPrefix(f[0], "#") {
			refs[f[0]] = f[1]
		}
	}
	return refs, nil
}

func modelURL(model string, refs map[string]string) (string, error) {
	parts := strings.Split(model, "/")
	switch {
	case parts[0] == "core" && len(parts) >= 3:
		return fmt.Sprintf("https://raw.githubusercontent.com/opnsense/core/%s/src/opnsense/mvc/app/models/OPNsense/%s",
			refs["core"], strings.Join(parts[1:], "/")), nil
	case parts[0] == "plugins" && len(parts) >= 5:
		return fmt.Sprintf("https://raw.githubusercontent.com/opnsense/plugins/%s/%s/%s/src/opnsense/mvc/app/models/OPNsense/%s",
			refs["plugins"], parts[1], parts[2], strings.Join(parts[3:], "/")), nil
	}
	return "", fmt.Errorf("model %q: expected core/<Module>/<File>.xml or plugins/<cat>/<plugin>/<Module>/<File>.xml", model)
}
