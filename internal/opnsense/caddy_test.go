package opnsense_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestCaddyGeneral(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	cd := fake.Client(t).Caddy

	g, err := cd.General.Get(ctx)
	if err != nil || bool(g.Enabled) || g.HTTPPort.Valid {
		t.Fatalf("defaults %+v, %v", g, err)
	}
	g.Enabled, g.TLSEmail, g.TLSDNSProvider, g.TLSDNSAPIKey = true, "me@example.com", "cloudflare", "secret"
	if err := cd.General.Set(ctx, *g); err != nil {
		t.Fatal(err)
	}
	stored := fake.CaddyGeneral()
	if stored["enabled"] != "1" || stored["TlsDnsProvider"] != "cloudflare" || stored["GracePeriod"] != "10" {
		t.Fatalf("stored %v (unmodelled fields must survive)", stored)
	}
	g.LogLevel = "LOUD"
	var ve *opnsense.ValidationError
	if err := cd.General.Set(ctx, *g); !errors.As(err, &ve) {
		t.Fatalf("bad log level: %v", err)
	}
	if err := cd.Apply(ctx); err != nil || fake.Applies["caddy/service/reconfigure"] != 1 {
		t.Fatalf("apply: %v %v", err, fake.Applies)
	}
	if st, err := cd.Status(ctx); err != nil || st != "running" {
		t.Fatalf("status %q, %v", st, err)
	}
}

func TestCaddyReverseProxy(t *testing.T) {
	ctx := context.Background()
	fake := opnsensetest.New(t)
	cd := fake.Client(t).Caddy

	acl, err := cd.AccessLists.Add(ctx, opnsense.CaddyAccessList{Name: "lan-only",
		ClientIPs: opnsense.CSVList{"192.168.1.0/24", "10.0.0.5"}, RequestMatcher: "client_ip"})
	if err != nil {
		t.Fatal(err)
	}
	wild, err := cd.Domains.Add(ctx, opnsense.CaddyDomain{Enabled: true, Domain: "*.example.com",
		DisableTLS: opnsense.CaddyDomainHTTPS, DNSChallenge: true})
	if err != nil {
		t.Fatal(err)
	}
	// Same domain on the default ports twice is rejected; on another port it is fine.
	if _, err := cd.Domains.Add(ctx, opnsense.CaddyDomain{Enabled: true, Domain: "*.example.com", DisableTLS: "0"}); err == nil ||
		!strings.Contains(err.Error(), "Duplicate entry") {
		t.Fatalf("duplicate domain: %v", err)
	}
	if _, err := cd.Domains.Add(ctx, opnsense.CaddyDomain{Domain: "x.example.com", DisableTLS: opnsense.CaddyDomainHTTP,
		DNSChallenge: true}); err == nil {
		t.Fatal("DNS challenge without TLS should fail")
	}

	if id, err := cd.WildcardFor(ctx, "app.example.com"); err != nil || id != wild {
		t.Fatalf("WildcardFor = %q, %v", id, err)
	}
	if _, err := cd.WildcardFor(ctx, "a.b.example.com"); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("two labels deeper: %v", err)
	}
	if _, err := cd.FindDomain(ctx, "app.example.com"); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("FindDomain: %v", err)
	}

	sub, err := cd.Subdomains.Add(ctx, opnsense.CaddySubdomain{Enabled: true, Domain: opnsense.Option(wild),
		Subdomain: "app.example.com", AccessList: opnsense.Option(acl)})
	if err != nil {
		t.Fatal(err)
	}
	scheme, err := opnsense.CaddySchemeValue("HTTPS")
	if err != nil || scheme != opnsense.CaddyUpstreamHTTPS {
		t.Fatalf("scheme %q, %v", scheme, err)
	}
	h, err := cd.Handlers.Add(ctx, opnsense.CaddyHandler{Enabled: true, Domain: opnsense.Option(wild),
		Subdomain: opnsense.Option(sub), HandleType: "handle", Directive: "reverse_proxy",
		Upstreams: opnsense.CSVList{"192.168.1.20", "192.168.1.21"}, UpstreamPort: opnsense.IntOf(8443),
		UpstreamScheme: scheme, TLSInsecureSkipVerify: true, Description: "app"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cd.Handlers.Get(ctx, h)
	if err != nil || got.Domain != opnsense.Option(wild) || len(got.Upstreams) != 2 ||
		opnsense.CaddySchemeName(got.UpstreamScheme) != "https" || got.UpstreamPort.Value != 8443 {
		t.Fatalf("handler %+v, %v", got, err)
	}
	if id, err := opnsense.ResolveByName(ctx, cd.Handlers, "app"); err != nil || id != h {
		t.Fatalf("handler by description: %q %v", id, err)
	}
	if _, err := cd.Handlers.Add(ctx, opnsense.CaddyHandler{Domain: opnsense.Option(wild), Upstreams: opnsense.CSVList{"h"},
		HandleType: "handle", Directive: "reverse_proxy", UpstreamScheme: "0", Path: "api"}); err == nil {
		t.Fatal("path without leading / should fail")
	}

	// Safe delete: referenced items stay until their users are gone.
	for _, del := range []func() error{
		func() error { return cd.Domains.Delete(ctx, wild) },
		func() error { return cd.Subdomains.Delete(ctx, sub) },
		func() error { return cd.AccessLists.Delete(ctx, acl) },
	} {
		if err := del(); err == nil || !strings.Contains(err.Error(), "in use") {
			t.Fatalf("delete in-use item: %v", err)
		}
	}

	file, err := cd.Caddyfile(ctx)
	if err != nil || !strings.Contains(file, "https://192.168.1.20:8443") {
		t.Fatalf("caddyfile %q, %v", file, err)
	}

	for _, del := range []func() error{
		func() error { return cd.Handlers.Delete(ctx, h) },
		func() error { return cd.Subdomains.Delete(ctx, sub) },
		func() error { return cd.Domains.Delete(ctx, wild) },
		func() error { return cd.AccessLists.Delete(ctx, acl) },
	} {
		if err := del(); err != nil {
			t.Fatal(err)
		}
	}
}
