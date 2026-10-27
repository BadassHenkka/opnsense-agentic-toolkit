package provider

import (
	"context"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestOptionalMask(t *testing.T) {
	v := optionalMask(regexp.MustCompile("(?i)^0x([a-f,0-9]){0,30}$"))
	for _, tc := range []struct {
		name  string
		value types.String
		ok    bool
	}{
		{"empty", types.StringValue(""), true},
		{"null", types.StringNull(), true},
		{"unknown", types.StringUnknown(), true},
		{"match", types.StringValue("0x1a"), true},
		{"no match", types.StringValue("1a"), false},
	} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("ifid"), ConfigValue: tc.value}, resp)
		if resp.Diagnostics.HasError() == tc.ok {
			t.Errorf("%s: accepted = %v, want %v (%v)", tc.name, !resp.Diagnostics.HasError(), tc.ok, resp.Diagnostics)
		}
	}
	if d := v.Description(context.Background()); d != "must match the OPNsense model mask" {
		t.Errorf("description %q", d)
	}
}
