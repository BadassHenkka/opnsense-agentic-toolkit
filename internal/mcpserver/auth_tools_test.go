package mcpserver_test

import (
	"context"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/mcpserver"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

func TestAuthAPIKeyList(t *testing.T) {
	cs, fake := connect(t, mcpserver.Options{Toolsets: []string{"auth"}})
	c := fake.Client(t)
	ctx := context.Background()
	if _, err := c.Auth.Users.Add(ctx, opnsense.User{Name: "bot"}); err != nil {
		t.Fatal(err)
	}
	k, err := c.Auth.AddAPIKey(ctx, "bot")
	if err != nil {
		t.Fatal(err)
	}
	out, ok := call(t, cs, "auth_api_key_list", map[string]any{})
	if !ok || out["total"].(float64) != 1 {
		t.Fatalf("list %v", out)
	}
	item := out["items"].([]any)[0].(map[string]any)
	if item["username"] != "bot" || item["key"] != k.Key || item["secret"] != nil {
		t.Fatalf("item %v", item)
	}
}
