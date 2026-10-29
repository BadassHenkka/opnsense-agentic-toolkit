package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// An ID of a DNS over TLS server in an opnsense_unbound_forward fails the read, as on
// import, instead of an apply turning the server into plain DNS forwarding.
func TestUnboundForwardImportOfDoTFails(t *testing.T) {
	h := newHarness(t, nil, NewUnboundForwardResource())
	dot, err := h.fake.Client(t).Unbound.DoTs.Add(context.Background(),
		opnsense.UnboundDoT{Enabled: true, Server: "1.1.1.1", Verify: "cloudflare-dns.com"})
	if err != nil {
		t.Fatal(err)
	}
	var got genUnboundForwardModel
	st, ok := h.create(genUnboundForwardPlan(), &got)
	if !ok {
		t.Fatal("create failed")
	}
	if d := st.SetAttribute(h.ctx, pathID, dot); d.HasError() {
		t.Fatal(d)
	}
	resp := resource.ReadResponse{State: st}
	h.r.Read(h.ctx, resource.ReadRequest{State: st}, &resp)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics[0].Detail(), `"dot"`) {
		t.Fatalf("read of a DoT as a forward: %v", resp.Diagnostics)
	}
	if rec, _ := h.fake.Get("dot", dot); rec["type"] != "dot" {
		t.Fatalf("stored %v", rec)
	}
}
