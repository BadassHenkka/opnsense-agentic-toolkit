package opnsense_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestAcmeSettings(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	acme := fake.Client(t).Acme

	st, err := acme.Settings.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Environment != "prod" || st.ChallengePort != opnsense.IntOf(43580) {
		t.Fatalf("defaults: %+v", st)
	}
	st.Enabled, st.Environment = true, "stg"
	if err := acme.Settings.Set(ctx, *st); err != nil {
		t.Fatal(err)
	}
	// Plugin-managed fields (UpdateCron, haproxy*Ref) are read-only in the client; the fake
	// rejects a set that sends them.
	if got := fake.AcmeSettings(); got["enabled"] != "1" || got["environment"] != "stg" {
		t.Fatalf("stored %v", got)
	}
	st.Environment = "bogus"
	var ve *opnsense.ValidationError
	if err := acme.Settings.Set(ctx, *st); !errors.As(err, &ve) {
		t.Fatalf("want validation error, got %v", err)
	}
}

func TestAcmeChallengeTypeParams(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	acme := fake.Client(t).Acme

	id, err := acme.ChallengeTypes.Add(ctx, opnsense.AcmeChallengeType{
		Enabled: true, Name: "cloudflare", Method: "dns01", DNSService: "dns_cf",
		Params: opnsense.Params{"dns_cf_token": "secret-token", "dns_cf_account_id": "abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := fake.Get("validation", id)
	if rec["dns_cf_token"] != "secret-token" || rec["dns_service"] != "dns_cf" {
		t.Fatalf("params not written: %v", rec)
	}

	got, err := acme.ChallengeTypes.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// Every other model field comes back in Params, option maps reduced to their selection.
	if got.Params["dns_cf_token"] != "secret-token" || got.Params["http_service"] != "opnsense" {
		t.Fatalf("params decoded %v", got.Params)
	}
	if _, has := got.Params["id"]; has {
		t.Fatal("id should not be a param")
	}
	if _, has := got.Params["name"]; has {
		t.Fatal("modelled fields should not repeat in params")
	}

	tmpl, err := acme.ChallengeTypeTemplate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Defaults["dns_loopia_api"] == "" || !slices.Contains(tmpl.Choices["dns_service"], "dns_cf") {
		t.Fatalf("template %+v", tmpl)
	}
	rel := opnsense.RelevantParams(got.Params, got.ParamPrefixes(), tmpl.Defaults)
	if _, ok := rel["dns_cf_zone_id"]; !ok || rel["dns_cf_token"] == "" {
		t.Fatalf("relevant params should include all dns_cf_* fields: %v", rel)
	}
	if _, ok := rel["dns_loopia_api"]; ok {
		t.Fatalf("defaults of other providers should be left out: %v", rel)
	}

	// Clearing a param is done by sending it empty.
	got.Params = opnsense.Params{"dns_cf_token": ""}
	if err := acme.ChallengeTypes.Set(ctx, id, *got); err != nil {
		t.Fatal(err)
	}
	if rec, _ := fake.Get("validation", id); rec["dns_cf_token"] != "" || rec["dns_cf_account_id"] != "abc" {
		t.Fatalf("after clear: %v", rec)
	}
}

func TestAcmeCertificateFlow(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	acme := fake.Client(t).Acme

	acct, err := acme.Accounts.Add(ctx, opnsense.AcmeAccount{Enabled: true, Name: "le", Email: "a@example.com", CA: "letsencrypt"})
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := acme.ChallengeTypes.Add(ctx, opnsense.AcmeChallengeType{Enabled: true, Name: "cf", Method: "dns01", DNSService: "dns_cf"})
	auto, err := acme.Automations.Add(ctx, opnsense.AcmeAutomation{Enabled: true, Name: "restart-gui", Type: "configd_restart_gui"})
	if err != nil {
		t.Fatal(err)
	}

	cert := opnsense.AcmeCertificate{
		Enabled: true, Name: "fw.example.com", AltNames: opnsense.CSVList{"vpn.example.com"},
		Account: opnsense.Option(acct), ValidationMethod: opnsense.Option(ch), KeyLength: "key_ec256",
		RestartActions: opnsense.CSVList{auto}, AutoRenewal: true, RenewInterval: opnsense.IntOf(60), AliasMode: "none",
	}
	id, err := acme.Certificates.Add(ctx, cert)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	got, err := acme.Certificates.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Account) != acct || !slices.Equal(got.RestartActions, []string{auto}) || got.StatusCode != "100" {
		t.Fatalf("decoded %+v", got)
	}
	// Read-only fields are never sent back (the fake rejects that with HTTP 400).
	if err := acme.Certificates.Set(ctx, id, *got); err != nil {
		t.Fatalf("set after get: %v", err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "statusCode") {
		t.Fatalf("read-only field encoded: %s", b)
	}

	if _, err := acme.IssueCertificate(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, _ = acme.Certificates.Get(ctx, id)
	if got.StatusCode != opnsense.AcmeStatusOK || got.CertRefID == "" {
		t.Fatalf("after issue: %+v", got)
	}
	if err := acme.RunAutomations(ctx, id); err != nil {
		t.Fatalf("RunAutomations: %v", err)
	}
	if _, err := acme.RevokeCertificate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := acme.IssueCertificate(ctx, "00000000-0000-4000-8000-999999999999"); err == nil {
		t.Fatal("issue of unknown uuid should fail")
	}
	if _, err := acme.RegisterAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if ops := fake.Operations(); len(ops) != 4 {
		t.Fatalf("operations = %v", ops)
	}

	byName, err := opnsense.ResolveByName(ctx, acme.Certificates, "FW.example.com")
	if err != nil || byName != id {
		t.Fatalf("ResolveByName = %q, %v", byName, err)
	}
	if _, err := opnsense.ResolveByName(ctx, acme.Accounts, "nope"); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	if err := acme.Apply(ctx); err != nil || fake.Applies["acmeclient/service/reconfigure"] != 1 {
		t.Fatalf("apply: %v", err)
	}
}

func TestAcmeAutomationPrefixes(t *testing.T) {
	for typ, want := range map[string]string{
		"configd_upload_sftp": "sftp_", "acme_proxmoxve": "acme_proxmoxve_", "configd_restart_gui": "",
	} {
		a := opnsense.AcmeAutomation{Type: opnsense.Option(typ)}
		got := strings.Join(a.ParamPrefixes(), ",")
		if got != want {
			t.Errorf("%s: prefixes %q, want %q", typ, got, want)
		}
	}
}
