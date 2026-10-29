package opnsense_test

import (
	"context"
	"errors"
	"testing"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

// Query forwarding and DNS over TLS servers share dots.dot; getForward returns a DoT too.
func TestUnboundForwardRefusesDoT(t *testing.T) {
	ctx := context.Background()
	c := opnsensetest.New(t).Client(t)
	fwd, err := c.Unbound.Forwards.Add(ctx, opnsense.UnboundForward{Enabled: true, Server: "192.0.2.53", Domain: "corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	dot, err := c.Unbound.DoTs.Add(ctx, opnsense.UnboundDoT{Enabled: true, Server: "1.1.1.1", Verify: "cloudflare-dns.com"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Unbound.Forwards.Get(ctx, fwd); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if _, err := c.Unbound.DoTs.Get(ctx, dot); err != nil {
		t.Fatalf("dot: %v", err)
	}
	var wrong *opnsense.WrongKindError
	if _, err := c.Unbound.Forwards.Get(ctx, dot); !errors.As(err, &wrong) || wrong.Got != "dot" || wrong.Want != "forward" {
		t.Fatalf("Forwards.Get(dot) = %v", err)
	}
	if _, err := c.Unbound.DoTs.Get(ctx, fwd); !errors.As(err, &wrong) || wrong.Got != "forward" {
		t.Fatalf("DoTs.Get(forward) = %v", err)
	}

	for name, search := range map[string]func() (int, string, error){
		"forward": func() (int, string, error) {
			r, err := c.Unbound.Forwards.Search(ctx, "")
			if err != nil || len(r.Rows) == 0 {
				return 0, "", err
			}
			return len(r.Rows), string(r.Rows[0].UUID), nil
		},
		"dot": func() (int, string, error) {
			r, err := c.Unbound.DoTs.Search(ctx, "")
			if err != nil || len(r.Rows) == 0 {
				return 0, "", err
			}
			return len(r.Rows), string(r.Rows[0].UUID), nil
		},
	} {
		want := map[string]string{"forward": fwd, "dot": dot}[name]
		if n, id, err := search(); err != nil || n != 1 || id != want {
			t.Errorf("search %s = %d rows, first %q, %v", name, n, id, err)
		}
	}
}
