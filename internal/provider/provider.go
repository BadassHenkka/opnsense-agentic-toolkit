// Package provider implements the OPNsense Terraform provider on the Plugin Framework.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

var (
	_ provider.Provider            = (*opnsenseProvider)(nil)
	_ provider.ProviderWithActions = (*opnsenseProvider)(nil)
)

type opnsenseProvider struct {
	version string
}

// New returns a constructor for the provider, as providerserver.Serve expects.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &opnsenseProvider{version: version} }
}

type providerModel struct {
	URL       types.String `tfsdk:"url"`
	APIKey    types.String `tfsdk:"api_key"`
	APISecret types.String `tfsdk:"api_secret"`
	CAFile    types.String `tfsdk:"ca_file"`
	Insecure  types.Bool   `tfsdk:"insecure"`

	TLSServerName types.String `tfsdk:"tls_server_name"`
}

func (p *opnsenseProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "opnsense"
	resp.Version = p.version
}

func (p *opnsenseProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage an OPNsense firewall through its REST API.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional:    true,
				Description: "Base URL of the OPNsense web UI, e.g. https://opnsense.lan. Env: " + opnsense.EnvURL + ".",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "API key. Env: " + opnsense.EnvAPIKey + ".",
			},
			"api_secret": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "API secret. Env: " + opnsense.EnvAPISecret + ".",
			},
			"ca_file": schema.StringAttribute{
				Optional:    true,
				Description: "PEM file used to verify a self-signed certificate. Env: " + opnsense.EnvCAFile + ".",
			},
			"insecure": schema.BoolAttribute{
				Optional:    true,
				Description: "Skip TLS verification. Prefer ca_file. Env: " + opnsense.EnvInsecure + ".",
			},
			"tls_server_name": schema.StringAttribute{
				Optional: true,
				Description: "Name the certificate must be valid for, if it differs from the host in url. " +
					"The provider still connects to that host. Env: " + opnsense.EnvTLSServerName + ".",
			},
		},
	}
}

func (p *opnsenseProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Values may come from other resources and be unknown during plan.
	for attr, v := range map[string]types.String{"url": cfg.URL, "api_key": cfg.APIKey, "api_secret": cfg.APISecret} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(attr), "Unknown provider configuration",
				"The provider cannot be configured with a value that is only known after apply.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Explicit configuration wins over the environment.
	c := opnsense.ConfigFromEnv()
	override(&c.URL, cfg.URL)
	override(&c.APIKey, cfg.APIKey)
	override(&c.APISecret, cfg.APISecret)
	override(&c.CAFile, cfg.CAFile)
	override(&c.TLSServerName, cfg.TLSServerName)
	if !cfg.Insecure.IsNull() && !cfg.Insecure.IsUnknown() {
		c.Insecure = cfg.Insecure.ValueBool()
	}

	for attr, v := range map[string]string{"url": c.URL, "api_key": c.APIKey, "api_secret": c.APISecret} {
		if v == "" {
			resp.Diagnostics.AddAttributeError(path.Root(attr), "Missing provider configuration",
				"Set "+attr+" in the provider block or the matching OPNSENSE_* environment variable.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := opnsense.NewClient(c)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create OPNsense client", err.Error())
		return
	}
	client.SetUserAgent("terraform-provider-opnsense/" + p.version)
	resp.ResourceData = client
	resp.DataSourceData = client
	resp.ActionData = client
}

func override(dst *string, v types.String) {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		*dst = v.ValueString()
	}
}

func (p *opnsenseProvider) Resources(context.Context) []func() resource.Resource {
	return append([]func() resource.Resource{
		NewAcmeChallengeTypeResource,
		NewAcmeAutomationResource,
		NewFirewallRuleResource,
		NewPluginResource,
		NewAuthAPIKeyResource,
		NewIDSRulesetResource,
	}, generatedResources()...) // zz_gen_*.go
}

// Actions are imperative operations (Terraform 1.14+), such as sending a Wake on LAN packet.
func (p *opnsenseProvider) Actions(context.Context) []func() action.Action {
	return []func() action.Action{
		NewWolWakeAction,
	}
}

func (p *opnsenseProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

// clientFrom extracts the client passed from Configure, or nil before configuration.
func clientFrom(data any) (*opnsense.Client, bool) {
	if data == nil {
		return nil, true
	}
	c, ok := data.(*opnsense.Client)
	return c, ok
}
