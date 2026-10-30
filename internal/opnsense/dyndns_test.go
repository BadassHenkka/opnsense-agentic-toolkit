package opnsense_test

import (
	"context"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

// TestUpdateOnlyPassword checks that the fake treats an UpdateOnlyTextField like OPNsense:
// the DynDNS password reads back empty, and an empty write keeps it.
func TestUpdateOnlyPassword(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	client := fake.Client(t)
	accounts := client.DynDNS.Accounts

	acct := opnsense.DynDNSAccount{
		Enabled: true, Service: "cloudflare", Password: "token", Hostnames: opnsense.CSVList{"home.example.com"},
		Checkip: "web_icanhazip", CheckipTimeout: opnsense.IntOf(10), TTL: opnsense.IntOf(300), Description: "home",
	}
	id, err := accounts.Add(ctx, acct)
	if err != nil {
		t.Fatal(err)
	}
	stored := func() string {
		t.Helper()
		rec, _ := fake.Get("account", id)
		return rec["password"]
	}

	got, err := accounts.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "" {
		t.Errorf("get returned the password %q", got.Password)
	}
	var search struct {
		Rows []map[string]string `json:"rows"`
	}
	if err := client.Post(ctx, "dyndns/accounts/searchItem", map[string]any{}, &search); err != nil {
		t.Fatal(err)
	}
	if len(search.Rows) != 1 || search.Rows[0]["password"] != "" {
		t.Errorf("search rows %v, want one without the password", search.Rows)
	}

	acct.Password, acct.Description = "", "home2"
	if err := accounts.Set(ctx, id, acct); err != nil {
		t.Fatal(err)
	}
	if p := stored(); p != "token" {
		t.Errorf("empty write: stored %q, want token", p)
	}

	acct.Password = "new"
	if err := accounts.Set(ctx, id, acct); err != nil {
		t.Fatal(err)
	}
	if p := stored(); p != "new" {
		t.Errorf("stored %q, want new", p)
	}
}
