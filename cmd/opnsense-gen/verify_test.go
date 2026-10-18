package main

import (
	"strings"
	"testing"
)

const domainController = `<?php
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'dnsmasq';
    public function searchDomainAction()
    {
        return $this->searchBase('domainoverrides');
    }
    public function getDomainAction($uuid = null)
    {
        return $this->getBase('domainoverride', 'domainoverrides', $uuid);
    }
    public function setDomainAction($uuid)
    {
        return $this->setBase('domainoverride', 'domainoverrides', $uuid);
    }
    public function addDomainAction()
    {
        return $this->addBase('domainoverride', 'domainoverrides');
    }
    public function delDomainAction($uuid)
    {
        return $this->delBase('domainoverrides', $uuid);
    }
}
`

const serviceController = `<?php
class ServiceController extends ApiMutableServiceControllerBase
{
}
`

func TestVerifyAreas(t *testing.T) {
	src := newControllerSource(map[string]string{"core": "x"}, func(url string) (string, error) {
		switch {
		case strings.HasSuffix(url, "/Dnsmasq/Api/SettingsController.php"):
			return domainController, nil
		case strings.HasSuffix(url, "/Dnsmasq/Api/ServiceController.php"):
			return serviceController, nil
		}
		return "", nil
	})
	obj := func(key, suffix, reconfigure string) *Object {
		return &Object{ObjectSpec: ObjectSpec{Resource: "dnsmasq_domain", Model: "core/Dnsmasq/Dnsmasq.xml", Node: "domainoverrides",
			Base: "dnsmasq/settings", Key: key, Suffix: suffix, Reconfigure: reconfigure}}
	}
	settings := &Object{Settings: true, ObjectSpec: ObjectSpec{Resource: "dnsmasq_settings", Model: "core/Dnsmasq/Dnsmasq.xml",
		Get: "dnsmasq/settings/get", Set: "dnsmasq/settings/set", Path: []string{"dnsmasq"}}}

	good := []*Area{{Items: []*Object{obj("domainoverride", "Domain", "dnsmasq/service/reconfigure")}, Settings: []*Object{settings}}}
	if p := verifyAreas(good, src); len(p) != 0 {
		t.Fatalf("matching spec reported %v", p)
	}

	wrongRoot := *settings
	wrongRoot.Path = []string{"settings"}
	bad := []*Area{{
		Items: []*Object{
			obj("domain", "Domain", "dnsmasq/service/reconfigure"), // wrong key
			obj("domainoverride", "Item", ""),                      // wrong action suffix
			obj("domainoverride", "Domain", "dnsmasq/nope/reconfigure"),
		},
		Settings: []*Object{&wrongRoot},
	}}
	got := strings.Join(verifyAreas(bad, src), "\n")
	for _, want := range []string{
		`getBase uses key "domainoverride"`, `setBase uses key "domainoverride"`, `addBase uses key "domainoverride"`,
		"has no addItemAction", "has no searchItemAction",
		"reconfigure controller for dnsmasq/nope/reconfigure not found",
		`model name is "dnsmasq"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestControllerName(t *testing.T) {
	for in, want := range map[string]string{"reverse_proxy": "ReverseProxy", "settings": "Settings", "d_nat": "DNat", "group-settings": "GroupSettings"} {
		if got := controllerName(in); got != want {
			t.Errorf("controllerName(%q) = %q, want %q", in, got, want)
		}
	}
}
