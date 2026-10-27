package opnsense_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func checkOf(checks []opnsense.Check, name string) opnsense.Check {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return opnsense.Check{}
}

func TestDiagnoseMissingConfig(t *testing.T) {
	checks := opnsense.Diagnose(context.Background(), opnsense.Config{})
	if len(checks) != 1 || checks[0].Status != opnsense.CheckFail || !strings.Contains(checks[0].Detail, "OPNSENSE_URL") {
		t.Fatalf("got %+v", checks)
	}
}

func TestDiagnoseAgainstFake(t *testing.T) {
	s := opnsensetest.New(t)
	cfg := s.Config()
	checks := opnsense.Diagnose(context.Background(), cfg)
	for _, name := range []string{"connection", "permissions", "plugins"} {
		if checkOf(checks, name).Status != opnsense.CheckOK {
			t.Errorf("%s: %+v", name, checks)
		}
	}
	// The fake reports 26.7.3, the tested series.
	if checkOf(checks, "version").Status != opnsense.CheckOK {
		t.Errorf("version: %+v", checks)
	}
}

func TestDiagnoseWrongSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	checks := opnsense.Diagnose(context.Background(), opnsense.Config{URL: srv.URL, APIKey: "k", APISecret: "s"})
	last := checks[len(checks)-1]
	if last.Name != "connection" || last.Status != opnsense.CheckFail || !strings.Contains(last.Hint, "secret") {
		t.Fatalf("got %+v", checks)
	}
}

func TestDiagnoseForbiddenIsAuthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	checks := opnsense.Diagnose(context.Background(), opnsense.Config{URL: srv.URL, APIKey: "k", APISecret: "s"})
	if checkOf(checks, "connection").Status != opnsense.CheckOK || checkOf(checks, "permissions").Status != opnsense.CheckWarn {
		t.Fatalf("got %+v", checks)
	}
	// The hint names the 26.x API privilege, not the legacy "Firewall: Rules" page.
	if d := checkOf(checks, "permissions").Detail; !strings.Contains(d, "firewall rules (Firewall: Rules [new])") {
		t.Errorf("permissions detail: %q", d)
	}
}
