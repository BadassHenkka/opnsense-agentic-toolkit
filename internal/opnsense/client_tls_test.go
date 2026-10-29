package opnsense_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// The httptest certificate lists example.com and 127.0.0.1, so a name it does not list must
// fail and example.com must pass, both reached at 127.0.0.1.
func TestTLSServerName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, serverName, wantErr string
	}{
		{"URL host", "", ""},
		{"name in the certificate", "example.com", ""},
		{"name not in the certificate", "opnsense.internal", "opnsense.internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := opnsense.NewClient(opnsense.Config{URL: srv.URL, APIKey: "k", APISecret: "s", CAFile: ca, TLSServerName: tc.serverName})
			if err != nil {
				t.Fatal(err)
			}
			err = c.Get(context.Background(), "core/firmware/info", nil)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("got %v, want an error about %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfigFromEnvTLSServerName(t *testing.T) {
	t.Setenv(opnsense.EnvTLSServerName, "OPNsense.internal")
	if got := opnsense.ConfigFromEnv().TLSServerName; got != "OPNsense.internal" {
		t.Fatalf("got %q", got)
	}
}
