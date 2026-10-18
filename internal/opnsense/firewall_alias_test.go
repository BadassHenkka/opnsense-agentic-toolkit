package opnsense_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestAliasLifecycle(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	c := fake.Client(t)

	in := opnsense.Alias{
		Enabled:     true,
		Name:        "homelab_servers",
		Type:        "host",
		Content:     opnsense.LineList{"10.0.10.5", "10.0.10.6"},
		Description: "Proxmox and TrueNAS",
	}
	id, err := c.Firewall.Aliases.Add(ctx, in)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// The write form reached the API: newline-separated content, "1" for enabled.
	rec, _ := fake.Get("alias", id)
	if rec["content"] != "10.0.10.5\n10.0.10.6" || rec["enabled"] != "1" || rec["type"] != "host" {
		t.Fatalf("unexpected write form: %+v", rec)
	}

	got, err := c.Firewall.Aliases.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != in.Name || got.Type != "host" || !bool(got.Enabled) ||
		!slices.Equal(got.Content, in.Content) || len(got.Categories) != 0 {
		t.Fatalf("Get decoded %+v", got)
	}

	byName, err := c.Firewall.AliasUUIDByName(ctx, in.Name)
	if err != nil || byName != id {
		t.Fatalf("UUIDByName = %q, %v", byName, err)
	}

	got.Content = append(got.Content, "10.0.10.7")
	if err := c.Firewall.Aliases.Set(ctx, id, *got); err != nil {
		t.Fatalf("Set: %v", err)
	}
	res, err := c.Firewall.Aliases.Search(ctx, "homelab")
	if err != nil || res.Total != 1 || string(res.Rows[0].UUID) != id {
		t.Fatalf("Search = %+v, %v", res, err)
	}

	if err := c.Firewall.Aliases.Apply(ctx); err != nil || fake.Applies["firewall/alias/reconfigure"] != 1 {
		t.Fatalf("Apply: %v (applies=%d)", err, fake.Applies["firewall/alias/reconfigure"])
	}

	if err := c.Firewall.Aliases.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Firewall.Aliases.Get(ctx, id); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("Get after delete: want ErrNotFound, got %v", err)
	}
	if err := c.Firewall.Aliases.Delete(ctx, id); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("second Delete: want ErrNotFound, got %v", err)
	}
	if _, err := c.Firewall.AliasUUIDByName(ctx, in.Name); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("UUIDByName after delete: want ErrNotFound, got %v", err)
	}
}

func TestAliasValidationError(t *testing.T) {
	ctx := context.Background()
	c := opnsensetest.New(t).Client(t)

	if _, err := c.Firewall.Aliases.Add(ctx, opnsense.Alias{Name: "dup", Type: "host"}); err != nil {
		t.Fatal(err)
	}
	_, err := c.Firewall.Aliases.Add(ctx, opnsense.Alias{Name: "dup", Type: "host"})
	var ve *opnsense.ValidationError
	if !errors.As(err, &ve) || ve.Fields["alias.name"] == "" {
		t.Fatalf("want ValidationError on alias.name, got %v", err)
	}
}

func TestDeleteInUse(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	c := fake.Client(t)
	id, err := c.Firewall.Aliases.Add(ctx, opnsense.Alias{Name: "used", Type: "host"})
	if err != nil {
		t.Fatal(err)
	}
	fake.InUse[id] = true
	if err := c.Firewall.Aliases.Delete(ctx, id); err == nil {
		t.Fatal("want error deleting an alias in use")
	}
}

func TestAuthError(t *testing.T) {
	fake := opnsensetest.New(t)
	cfg := fake.Config()
	cfg.APISecret = "wrong"
	c, err := opnsense.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Firewall.Aliases.Search(context.Background(), "")
	var ae *opnsense.APIError
	if !errors.As(err, &ae) || ae.StatusCode != 401 {
		t.Fatalf("want 401 APIError, got %v", err)
	}
}

func TestNewClientValidation(t *testing.T) {
	for name, cfg := range map[string]opnsense.Config{
		"no url":    {APIKey: "k", APISecret: "s"},
		"no secret": {URL: "https://fw", APIKey: "k"},
		"bad url":   {URL: "fw.lan", APIKey: "k", APISecret: "s"},
	} {
		if _, err := opnsense.NewClient(cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestOptionDecoding(t *testing.T) {
	var v struct {
		Type    opnsense.Option   `json:"type"`
		Proto   opnsense.CSVList  `json:"proto"`
		Content opnsense.LineList `json:"content"`
		Empty   opnsense.CSVList  `json:"empty"`
		Blank   opnsense.CSVList  `json:"blank"`
		Indexed opnsense.Option   `json:"indexed"`
		On      opnsense.Bool     `json:"on"`
	}
	data := `{
		"type": {"host": {"value": "Host(s)", "selected": 0}, "network": {"value": "Network(s)", "selected": 1}},
		"proto": {"IPv4": {"value": "IPv4", "selected": "1"}, "IPv6": {"value": "IPv6", "selected": 1}},
		"content": "a\nb\n",
		"empty": [],
		"blank": {"": {"value": "", "selected": 1}},
		"indexed": [{"value": "https://", "selected": 0}, {"value": "http://", "selected": 1}],
		"on": "1"
	}`
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		t.Fatal(err)
	}
	if v.Type != "network" || !slices.Equal(v.Proto, []string{"IPv4", "IPv6"}) ||
		!slices.Equal(v.Content, []string{"a", "b"}) || v.Empty != nil || v.Blank != nil ||
		v.Indexed != "1" || !bool(v.On) {
		t.Fatalf("decoded %+v", v)
	}
	out, _ := json.Marshal(v)
	want := `{"type":"network","proto":"IPv4,IPv6","content":"a\nb","empty":"","blank":"","indexed":"1","on":"1"}`
	if string(out) != want {
		t.Fatalf("encoded %s\nwant    %s", out, want)
	}
}
