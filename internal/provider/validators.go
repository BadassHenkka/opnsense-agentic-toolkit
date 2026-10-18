package provider

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Custom validators. The framework's validator interfaces are small: a description and a
// Validate method that adds diagnostics.

// cidr validates a string in CIDR notation, e.g. 10.10.10.2/32.
type cidr struct{}

func (cidr) Description(context.Context) string {
	return "value must be in CIDR notation, e.g. 10.10.10.2/32"
}
func (c cidr) MarkdownDescription(ctx context.Context) string { return c.Description(ctx) }

func (cidr) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, _, err := net.ParseCIDR(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CIDR",
			fmt.Sprintf("%q is not in CIDR notation (e.g. 10.10.10.2/32).", req.ConfigValue.ValueString()))
	}
}

// ipOrCIDR validates an IP address or a network in CIDR notation.
type ipOrCIDR struct{}

func (ipOrCIDR) Description(context.Context) string {
	return "value must be an IP address or a network in CIDR notation"
}
func (v ipOrCIDR) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (ipOrCIDR) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if net.ParseIP(v) != nil {
		return
	}
	if _, _, err := net.ParseCIDR(v); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address or network",
			fmt.Sprintf("%q is neither an IP address nor a network in CIDR notation.", v))
	}
}

// wireguardKey validates a base64 encoded 32-byte WireGuard key.
type wireguardKey struct{}

func (wireguardKey) Description(context.Context) string {
	return "value must be a WireGuard key: 32 bytes, base64 encoded"
}
func (w wireguardKey) MarkdownDescription(ctx context.Context) string { return w.Description(ctx) }

func (wireguardKey) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return
	}
	if _, err := opnsense.DecodeWireguardKey(req.ConfigValue.ValueString()); err != nil {
		// Do not echo the value: it may be a private key.
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid WireGuard key",
			"The value is not a WireGuard key (32 bytes, base64 encoded, like the output of `wg genkey`).")
	}
}
