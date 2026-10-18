package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func strList(vals ...string) types.List {
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

// The generated tests cover each resource on its own; this one covers how they fit together
// and the value mappings (tls, strip_path, upstream_scheme).
func TestCaddyProxyResources(t *testing.T) {
	fake := opnsensetest.New(t)
	acls := newHarness(t, fake, NewCaddyAccessListResource())
	domains := newHarness(t, fake, NewCaddyDomainResource())
	subs := newHarness(t, fake, NewCaddySubdomainResource())
	handlers := newHarness(t, fake, NewCaddyHandlerResource())

	var acl genCaddyAccessListModel
	aclState, ok := acls.create(genCaddyAccessListPlan(), &acl)
	if !ok {
		t.Fatal("access list create failed")
	}

	domainPlan := genCaddyDomainPlan() // *.example.com with DNS-01
	var dom genCaddyDomainModel
	domState, ok := domains.create(domainPlan, &dom)
	if !ok || !dom.TLS.ValueBool() {
		t.Fatalf("domain create: %+v", dom)
	}
	if rec, _ := fake.Get("reverse", dom.ID.ValueString()); rec["DisableTls"] != "0" || rec["DnsChallenge"] != "1" {
		t.Fatalf("domain stored %v", rec)
	}
	// Plain HTTP with a DNS challenge is rejected by OPNsense.
	bad := domainPlan
	bad.Domain, bad.TLS = types.StringValue("other.example.com"), types.BoolValue(false)
	if _, ok := domains.create(bad, &genCaddyDomainModel{}); ok {
		t.Fatal("http domain with dns challenge should fail")
	}

	subPlan := genCaddySubdomainPlan()
	subPlan.DomainID, subPlan.Subdomain, subPlan.AccessListID = dom.ID, types.StringValue("app.example.com"), acl.ID
	var sub genCaddySubdomainModel
	subState, ok := subs.create(subPlan, &sub)
	if !ok || sub.DomainID != dom.ID {
		t.Fatalf("subdomain create: %+v", sub)
	}

	handlerPlan := genCaddyHandlerPlan()
	handlerPlan.DomainID, handlerPlan.SubdomainID = dom.ID, sub.ID
	handlerPlan.Path, handlerPlan.StripPath = types.StringValue("/api/*"), types.BoolValue(true)
	handlerPlan.Upstreams = strList("192.168.1.20", "192.168.1.21")
	handlerPlan.UpstreamPort, handlerPlan.UpstreamScheme = types.Int64Value(8443), types.StringValue("https")
	handlerPlan.TLSInsecureSkipVerify, handlerPlan.Description = types.BoolValue(true), types.StringValue("app api")
	var hd genCaddyHandlerModel
	hdState, ok := handlers.create(handlerPlan, &hd)
	if !ok {
		t.Fatal("handler create failed")
	}
	rec, _ := fake.Get("handle", hd.ID.ValueString())
	if rec["HttpTls"] != "1" || rec["HandleType"] != "handle_path" || rec["ToDomain"] != "192.168.1.20,192.168.1.21" {
		t.Fatalf("handler stored %v", rec)
	}
	if hd.UpstreamScheme.ValueString() != "https" || !hd.StripPath.ValueBool() || len(hd.Upstreams.Elements()) != 2 {
		t.Fatalf("handler state %+v", hd)
	}
	if id, ok := handlers.importID("app api"); !ok || id != hd.ID.ValueString() {
		t.Fatalf("import handler = %q", id)
	}

	handlerPlan.ID, handlerPlan.UpstreamScheme, handlerPlan.Upstreams = hd.ID, types.StringValue("h2c"), strList("10.0.0.9")
	hdState = handlers.update(hdState, handlerPlan, &hd)
	if rec, _ := fake.Get("handle", hd.ID.ValueString()); rec["HttpTls"] != "2" || rec["ToDomain"] != "10.0.0.9" {
		t.Fatalf("handler after update %v", rec)
	}
	if !handlers.validateStrings(func() genCaddyHandlerModel { p := handlerPlan; p.UpstreamScheme = types.StringValue("1"); return p }()).HasError() {
		t.Fatal("raw API value 1 should not be accepted for upstream_scheme")
	}

	// Referenced items cannot go first; Terraform's dependency order destroys users first.
	if d := domains.deleteResp(domState); !d.HasError() || !strings.Contains(d.Errors()[0].Detail(), "in use") {
		t.Fatalf("delete in-use domain: %v", d)
	}
	handlers.delete(hdState)
	subs.delete(subState)
	domains.delete(domState)
	acls.delete(aclState)

	badIPs := genCaddyAccessListPlan()
	badIPs.ClientIPs = strSet("not-an-ip")
	if !acls.validateAttrs(badIPs).HasError() {
		t.Fatal("invalid client IP should fail validation")
	}
}
