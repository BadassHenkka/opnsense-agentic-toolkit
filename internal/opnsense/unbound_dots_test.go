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

	if r, err := c.Unbound.Forwards.Search(ctx, ""); err != nil || len(r.Rows) != 1 || string(r.Rows[0].UUID) != fwd {
		t.Errorf("search forwards = %+v, %v", r, err)
	}
	if r, err := c.Unbound.DoTs.Search(ctx, ""); err != nil || len(r.Rows) != 1 || string(r.Rows[0].UUID) != dot {
		t.Errorf("search DoTs = %+v, %v", r, err)
	}
}
