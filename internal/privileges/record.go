package privileges

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// EnvUpdate makes Recorder.Finish rewrite the endpoint file instead of checking it.
const EnvUpdate = "OPNSENSE_UPDATE_ENDPOINTS"

// Recorder collects the API endpoints each tool or resource calls while the tests of the MCP
// server and the provider run against the fake. The endpoint files are what it found.
type Recorder struct {
	mu   sync.Mutex
	seen map[string]map[string]bool
}

// Context returns ctx with a recorder that files each API call under owner, the tool or
// resource type.
func (r *Recorder) Context(ctx context.Context, owner string) context.Context {
	return opnsense.WithCallRecorder(ctx, func(path string) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.seen == nil {
			r.seen = map[string]map[string]bool{}
		}
		if r.seen[owner] == nil {
			r.seen[owner] = map[string]bool{}
		}
		r.seen[owner][Endpoint(path)] = true
	})
}

// Finish compares what the tests called with file. With OPNSENSE_UPDATE_ENDPOINTS=1 it
// rewrites file instead; run the whole test package then, or the file loses entries.
func (r *Recorder) Finish(file string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	got := map[string][]string{}
	for owner, eps := range r.seen {
		for ep := range eps {
			got[owner] = append(got[owner], ep)
		}
		sort.Strings(got[owner])
	}
	if os.Getenv(EnvUpdate) == "1" {
		if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" {
			return fmt.Errorf("%s=1 needs the whole test package; drop -run", EnvUpdate)
		}
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(file, append(b, '\n'), 0o644)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var want map[string][]string
	if err := json.Unmarshal(b, &want); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	var missing []string
	for owner, eps := range got {
		for _, ep := range eps {
			if !slices.Contains(want[owner], ep) {
				missing = append(missing, owner+": "+ep)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%s lacks endpoints the tests called; run the tests with %s=1:\n  %s",
			file, EnvUpdate, strings.Join(missing, "\n  "))
	}
	return nil
}

// Main is for TestMain: it runs the tests (m.Run) and returns the exit code, the tests' own
// or 1 when they pass but Finish fails.
func (r *Recorder) Main(run func() int, file string) int {
	code := run()
	if code == 0 {
		if err := r.Finish(file); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	return code
}

// Endpoint reduces an API path to <module>/<controller>/<action>, with each argument after it
// (a UUID, a package name) replaced by {arg}, so that the files don't depend on test data.
func Endpoint(path string) string {
	path, _, _ = strings.Cut(path, "?")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := 3; i < len(parts); i++ {
		parts[i] = "{arg}"
	}
	return strings.Join(parts, "/")
}
