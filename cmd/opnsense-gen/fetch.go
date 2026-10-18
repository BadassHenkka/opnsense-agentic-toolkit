package main

import (
	"bufio"
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
	return nil
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
