package mcpserver_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

// connect starts the server on an in-memory transport and returns a client session.
func connect(t *testing.T, opts mcpserver.Options) (*mcp.ClientSession, *opnsensetest.Server) {
	t.Helper()
	ctx := context.Background()
	fake := opnsensetest.New(t)
	client := fake.Client(t)
	client.Firmware.PollInterval = 5 * time.Millisecond
	srv, err := mcpserver.New(client, opts)
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, fake
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		var msg string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg += tc.Text
			}
		}
		return map[string]any{"error": msg}, false
	}
	var out map[string]any
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)
	return out, true
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

func TestAliasToolsFlow(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{})

	out, ok := call(t, cs, "firewall_alias_create", map[string]any{
		"name": "iot_devices", "type": "host", "content": []string{"10.0.30.10", "10.0.30.11"},
	})
	if !ok || out["staged"] != true {
		t.Fatalf("create: %v", out)
	}
	id := out["uuid"].(string)
	if rec, _ := fake.Get("alias", id); rec["enabled"] != "1" {
		t.Fatalf("enabled should default to true, got %+v", rec)
	}

	out, ok = call(t, cs, "firewall_alias_update", map[string]any{
		"name": "iot_devices", "description": "Shelly plugs",
	})
	if !ok {
		t.Fatalf("update: %v", out)
	}
	rec, _ := fake.Get("alias", id)
	if rec["description"] != "Shelly plugs" || rec["content"] != "10.0.30.10\n10.0.30.11" {
		t.Fatalf("update should patch only description, got %+v", rec)
	}

	out, ok = call(t, cs, "firewall_alias_get", map[string]any{"uuid": id})
	if !ok || out["name"] != "iot_devices" || len(out["content"].([]any)) != 2 {
		t.Fatalf("get: %v", out)
	}

	out, ok = call(t, cs, "firewall_alias_list", map[string]any{"search": "iot"})
	if !ok || out["total"].(float64) != 1 {
		t.Fatalf("list: %v", out)
	}

	if _, ok := call(t, cs, "firewall_alias_apply", map[string]any{}); !ok || fake.Applies["firewall/alias/reconfigure"] != 1 {
		t.Fatalf("apply: applies=%d", fake.Applies["firewall/alias/reconfigure"])
	}

	if out, ok := call(t, cs, "firewall_alias_delete", map[string]any{"name": "iot_devices"}); !ok {
		t.Fatalf("delete: %v", out)
	}
	if _, exists := fake.Get("alias", id); exists {
		t.Fatal("alias still stored after delete")
	}
}

func TestAliasToolErrors(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{})

	for name, args := range map[string]map[string]any{
		"firewall_alias_get":    {"name": "missing"},
		"firewall_alias_delete": {},
		"firewall_alias_create": {"name": "", "type": "host"},
	} {
		out, ok := call(t, cs, name, args)
		if ok {
			t.Errorf("%s: want tool error, got %v", name, out)
		}
	}

	// The schema enum rejects unknown types before the handler runs.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "firewall_alias_create", Arguments: map[string]any{"name": "x", "type": "bogus"},
	})
	if err == nil && !res.IsError {
		t.Fatal("want error for unknown alias type")
	}
}

func TestReadOnlyAndToolsets(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{ReadOnly: true, Toolsets: []string{"firewall_alias"}})
	if got, want := toolNames(t, cs), []string{"firewall_alias_get", "firewall_alias_list"}; !slices.Equal(got, want) {
		t.Fatalf("read-only tools = %v, want %v", got, want)
	}

	cs, _ = connect(t, mcpserver.Options{Toolsets: []string{"firewall_alias"}})
	if got := toolNames(t, cs); len(got) != 6 {
		t.Fatalf("firewall_alias tools = %v", got)
	}

	cs, _ = connect(t, mcpserver.Options{ReadOnly: true})
	for _, name := range toolNames(t, cs) {
		if !isReadTool(name) {
			t.Errorf("read-only mode registered %s", name)
		}
	}

	fake := opnsensetest.New(t)
	if _, err := mcpserver.New(fake.Client(t), mcpserver.Options{Toolsets: []string{"nope"}}); err == nil ||
		!strings.Contains(err.Error(), "unknown toolset") {
		t.Fatalf("want unknown toolset error, got %v", err)
	}
}

func TestToolAnnotations(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Annotations == nil {
			t.Errorf("%s has no annotations", tl.Name)
			continue
		}
		write := !isReadTool(tl.Name)
		if tl.Annotations.ReadOnlyHint == write {
			t.Errorf("%s: readOnlyHint=%v", tl.Name, tl.Annotations.ReadOnlyHint)
		}
	}
}

// TestToolsetNames checks that every tool belongs to a listed toolset and every listed
// toolset has tools.
func TestToolsetNames(t *testing.T) {
	cs, _ := connect(t, mcpserver.Options{})
	all := toolNames(t, cs)
	var union []string
	for _, ts := range mcpserver.Toolsets() {
		cs, _ := connect(t, mcpserver.Options{Toolsets: []string{ts}})
		names := toolNames(t, cs)
		if len(names) == 0 {
			t.Errorf("toolset %s has no tools", ts)
		}
		union = append(union, names...)
	}
	slices.Sort(union)
	if !slices.Equal(union, all) {
		t.Fatalf("tools outside listed toolsets: all=%d, in toolsets=%d", len(all), len(union))
	}
}

// isReadTool is the naming convention for tools that only read.
func isReadTool(name string) bool {
	for _, suffix := range []string{"_get", "_list", "_fields", "_status"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
