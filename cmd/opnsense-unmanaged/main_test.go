package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
	"github.com/smulis/opnsense-agentic-toolkit/internal/unmanaged"
)

func TestRun(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	c := fake.Client(t)
	t.Setenv(opnsense.EnvURL, fake.URL)
	t.Setenv(opnsense.EnvAPIKey, opnsensetest.Key)
	t.Setenv(opnsense.EnvAPISecret, opnsensetest.Secret)

	kept, err := c.Firewall.Aliases.Add(ctx, opnsense.Alias{Enabled: true, Name: "kept", Type: "host", Content: opnsense.LineList{"10.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	state := `{"values":{"root_module":{"resources":[{"address":"opnsense_firewall_alias.kept","mode":"managed","type":"opnsense_firewall_alias","values":{"id":"` + kept + `","content":["SECRET"]}}]}}}`

	exec := func(stdin string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := run(args, strings.NewReader(stdin), &out, &errOut)
		if strings.Contains(out.String()+errOut.String(), "SECRET") {
			t.Fatalf("printed a state value: %s %s", out.String(), errOut.String())
		}
		return code, out.String(), errOut.String()
	}

	if code, out, _ := exec(state); code != 0 || out != "" {
		t.Fatalf("in sync: %d %q", code, out)
	}

	added, err := c.Firewall.Aliases.Add(ctx, opnsense.Alias{Enabled: true, Name: "Kept", Type: "host", Content: opnsense.LineList{"10.0.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if code, out, _ := exec(state); code != 1 || out != "opnsense_firewall_alias\t"+added+"\tKept\n" {
		t.Fatalf("missing: %d %q", code, out)
	}
	// The label "kept" is taken by the managed alias.
	want := "# Kept\nimport {\n  to = opnsense_firewall_alias.kept_2\n  id = \"" + added + "\"\n}\n\n"
	if code, out, _ := exec(state, "-import"); code != 1 || out != want {
		t.Fatalf("import: %d %q", code, out)
	}
	if code, _, errOut := exec(state, "-types", "opnsense_nope"); code != 2 || !strings.Contains(errOut, "opnsense_nope") {
		t.Fatalf("unknown type: %d %q", code, errOut)
	}
	if code, _, errOut := exec(`{"values": SECRET`); code != 2 || errOut == "" {
		t.Fatalf("bad JSON: %d %q", code, errOut)
	}
}

func TestPrintImportLabels(t *testing.T) {
	for _, tc := range []struct {
		o    unmanaged.Object
		want string
	}{
		{unmanaged.Object{Type: "opnsense_firewall_rule", ID: "00000000-0000-4000-8000-000000000001", Name: "IoT: allow DNS"}, "opnsense_firewall_rule.iot_allow_dns"},
		{unmanaged.Object{Type: "opnsense_unbound_dot", ID: "ABCDEF01-0000-4000-8000-000000000001", Name: ""}, "opnsense_unbound_dot.unbound_dot_abcdef01"},
		{unmanaged.Object{Type: "opnsense_plugin", ID: "os-ddclient", Name: "10 things"}, "opnsense_plugin.plugin_10_things"},
	} {
		var b bytes.Buffer
		printImport(&b, tc.o, map[string]bool{})
		if !strings.Contains(b.String(), "to = "+tc.want+"\n") {
			t.Errorf("%+v: %s", tc.o, b.String())
		}
	}
	var b bytes.Buffer
	printImport(&b, unmanaged.Object{Type: "opnsense_x", ID: `a"${b}`}, map[string]bool{})
	if want := "# opnsense_x: skipped, unexpected id \"a\\\"${b}\"\n\n"; b.String() != want {
		t.Errorf("unsafe id: %q, want %q", b.String(), want)
	}
	if got := clean("a\x1b[2Jb\u202ec\nd"); got != "a?[2Jb?c?d" {
		t.Errorf("clean: %q", got)
	}
}
