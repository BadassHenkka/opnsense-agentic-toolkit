package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

const acmeToolset = "acme"

const acmeStagedNote = "Change saved to the configuration. Call acme_apply to regenerate the ACME client " +
	"configuration (needed for settings and HTTP/TLS-ALPN challenge changes)."

// secretParam matches field names whose values are credentials. Ids (…id) are not secret.
var secretParam = regexp.MustCompile(`(?i)(token|secret|pass|key|hmac|credential|private|apikey)`)

func isSecretParam(name string) bool {
	return secretParam.MatchString(name) && !strings.HasSuffix(strings.ToLower(name), "id")
}

const redacted = "(set, hidden)"

// redactParams hides credential values. The model can set them but never reads them back.
func redactParams(p opnsense.Params) map[string]string {
	out := make(map[string]string, len(p))
	for k, v := range p {
		if v != "" && isSecretParam(k) {
			v = redacted
		}
		out[k] = v
	}
	return out
}

// mergeParams applies a patch: keys with values are set, keys with "" are cleared.
func mergeParams(patch map[string]string) opnsense.Params {
	out := opnsense.Params{}
	for k, v := range patch {
		out[k] = v
	}
	return out
}

func unixTime(s opnsense.ReadOnly) string {
	n, err := strconv.ParseInt(string(s), 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

// ---- settings ----

type acmeSettingsView struct {
	Enabled            bool   `json:"enabled"`
	AutoRenewal        bool   `json:"auto_renewal"`
	Environment        string `json:"environment" jsonschema:"prod or stg (staging CA endpoints)"`
	ChallengePort      *int64 `json:"challenge_port,omitempty"`
	TLSChallengePort   *int64 `json:"tls_challenge_port,omitempty"`
	RestartTimeout     *int64 `json:"restart_timeout,omitempty"`
	LogLevel           string `json:"log_level"`
	HAProxyIntegration bool   `json:"haproxy_integration"`
}

type acmeSettingsIn struct {
	Enabled            *bool   `json:"enabled,omitempty" jsonschema:"turn the ACME client on or off"`
	AutoRenewal        *bool   `json:"auto_renewal,omitempty"`
	Environment        *string `json:"environment,omitempty"`
	ChallengePort      *int64  `json:"challenge_port,omitempty" jsonschema:"local port for HTTP-01 challenges"`
	TLSChallengePort   *int64  `json:"tls_challenge_port,omitempty" jsonschema:"local port for TLS-ALPN-01 challenges"`
	RestartTimeout     *int64  `json:"restart_timeout,omitempty" jsonschema:"seconds to wait for automations"`
	LogLevel           *string `json:"log_level,omitempty"`
	HAProxyIntegration *bool   `json:"haproxy_integration,omitempty"`
}

func settingsView(s *opnsense.AcmeSettings) acmeSettingsView {
	return acmeSettingsView{
		Enabled: bool(s.Enabled), AutoRenewal: bool(s.AutoRenewal), Environment: string(s.Environment),
		ChallengePort: intPtr(s.ChallengePort), TLSChallengePort: intPtr(s.TLSChallengePort),
		RestartTimeout: intPtr(s.RestartTimeout), LogLevel: string(s.LogLevel),
		HAProxyIntegration: bool(s.HAProxyIntegration),
	}
}

// ---- accounts ----

type acmeAccountView struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Email        string `json:"email,omitempty"`
	CA           string `json:"ca"`
	CustomCA     string `json:"custom_ca,omitempty"`
	EABKID       string `json:"eab_kid,omitempty"`
	EABHMACSet   bool   `json:"eab_hmac_set" jsonschema:"whether an EAB HMAC key is stored; the key itself is never shown"`
	Enabled      bool   `json:"enabled"`
	Status       string `json:"status"`
	StatusCode   string `json:"status_code"`
	StatusUpdate string `json:"status_updated,omitempty"`
}

type acmeAccountCreateIn struct {
	Name        string `json:"name"`
	Email       string `json:"email,omitempty" jsonschema:"contact address the CA sends expiry notices to"`
	CA          string `json:"ca,omitempty" jsonschema:"certificate authority; defaults to letsencrypt. *_test CAs issue untrusted test certificates"`
	CustomCA    string `json:"custom_ca,omitempty" jsonschema:"ACME directory URL, when ca is custom"`
	EABKID      string `json:"eab_kid,omitempty" jsonschema:"External Account Binding key id (ZeroSSL, Google, ...)"`
	EABHMAC     string `json:"eab_hmac,omitempty" jsonschema:"External Account Binding HMAC key"`
	Description string `json:"description,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type acmeAccountUpdateIn struct {
	NameRef
	NewName     *string `json:"new_name,omitempty"`
	Email       *string `json:"email,omitempty"`
	CA          *string `json:"ca,omitempty"`
	CustomCA    *string `json:"custom_ca,omitempty"`
	EABKID      *string `json:"eab_kid,omitempty"`
	EABHMAC     *string `json:"eab_hmac,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

func accountView(id string, a *opnsense.AcmeAccount) acmeAccountView {
	return acmeAccountView{
		UUID: id, Name: a.Name, Description: a.Description, Email: a.Email, CA: string(a.CA),
		CustomCA: a.CustomCA, EABKID: a.EABKID, EABHMACSet: a.EABHMAC != "", Enabled: bool(a.Enabled),
		Status: opnsense.AcmeStatusText(string(a.StatusCode)), StatusCode: string(a.StatusCode),
		StatusUpdate: unixTime(a.StatusLastUpdate),
	}
}

// ---- challenge types ----

type acmeChallengeView struct {
	UUID        string            `json:"uuid"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Method      string            `json:"method"`
	DNSService  string            `json:"dns_service,omitempty"`
	DNSSleep    *int64            `json:"dns_sleep,omitempty"`
	Enabled     bool              `json:"enabled"`
	Params      map[string]string `json:"params" jsonschema:"method/provider settings that apply; credentials are hidden"`
}

type acmeChallengeCreateIn struct {
	Name        string            `json:"name"`
	Method      string            `json:"method,omitempty" jsonschema:"dns01 (default), http01 or tlsalpn01"`
	DNSService  string            `json:"dns_service,omitempty" jsonschema:"DNS provider for dns01, e.g. dns_cf; see acme_challenge_type_fields"`
	DNSSleep    *int64            `json:"dns_sleep,omitempty" jsonschema:"seconds to wait for DNS propagation; 0 = automatic"`
	Params      map[string]string `json:"params,omitempty" jsonschema:"provider/method fields, e.g. {\"dns_cf_token\": \"...\"}; see acme_challenge_type_fields"`
	Description string            `json:"description,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type acmeChallengeUpdateIn struct {
	NameRef
	NewName     *string           `json:"new_name,omitempty"`
	Method      *string           `json:"method,omitempty"`
	DNSService  *string           `json:"dns_service,omitempty"`
	DNSSleep    *int64            `json:"dns_sleep,omitempty"`
	Params      map[string]string `json:"params,omitempty" jsonschema:"fields to change; other params keep their value; an empty string clears a field"`
	Description *string           `json:"description,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
}

type fieldsIn struct {
	Method     string `json:"method,omitempty" jsonschema:"challenge method: dns01, http01 or tlsalpn01"`
	DNSService string `json:"dns_service,omitempty" jsonschema:"DNS provider, e.g. dns_cf; omit to list providers"`
	Type       string `json:"type,omitempty" jsonschema:"automation type; omit to list types"`
	Search     string `json:"search,omitempty" jsonschema:"substring to filter field or provider names"`
}

type fieldInfo struct {
	Name    string   `json:"name"`
	Default string   `json:"default,omitempty"`
	Choices []string `json:"choices,omitempty"`
	Secret  bool     `json:"secret,omitempty"`
}

type fieldsOut struct {
	// Options lists DNS providers or automation types when none was given.
	Options []string    `json:"options,omitempty"`
	Fields  []fieldInfo `json:"fields"`
}

// templateFields lists template fields under the prefixes (or matching search).
func templateFields(t *opnsense.AcmeTemplate, prefixes []string, search string, skip []string) []fieldInfo {
	var out []fieldInfo
	for name, def := range t.Defaults {
		if slices.Contains(skip, name) {
			continue
		}
		match := false
		for _, p := range prefixes {
			if p != "" && strings.HasPrefix(name, p) {
				match = true
			}
		}
		if search != "" {
			match = strings.Contains(name, strings.ToLower(search)) && (len(prefixes) == 0 || match)
		}
		if !match {
			continue
		}
		out = append(out, fieldInfo{Name: name, Default: def, Choices: t.Choices[name], Secret: isSecretParam(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if out == nil {
		out = []fieldInfo{}
	}
	return out
}

func filterOptions(opts []string, search string) []string {
	if search == "" {
		return opts
	}
	var out []string
	for _, o := range opts {
		if strings.Contains(o, strings.ToLower(search)) {
			out = append(out, o)
		}
	}
	return out
}

// ---- automations ----

type acmeAutomationView struct {
	UUID        string            `json:"uuid"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	Params      map[string]string `json:"params" jsonschema:"type-specific settings; credentials are hidden"`
}

type acmeAutomationCreateIn struct {
	Name        string            `json:"name"`
	Type        string            `json:"type" jsonschema:"automation type, e.g. configd_restart_gui, configd_upload_sftp, acme_proxmoxve; see acme_automation_fields"`
	Params      map[string]string `json:"params,omitempty" jsonschema:"type-specific fields; see acme_automation_fields"`
	Description string            `json:"description,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type acmeAutomationUpdateIn struct {
	NameRef
	NewName     *string           `json:"new_name,omitempty"`
	Type        *string           `json:"type,omitempty"`
	Params      map[string]string `json:"params,omitempty" jsonschema:"fields to change; an empty string clears a field"`
	Description *string           `json:"description,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
}

// ---- certificates ----

type acmeCertificateView struct {
	UUID            string   `json:"uuid"`
	Name            string   `json:"name" jsonschema:"common name"`
	AltNames        []string `json:"alt_names"`
	Description     string   `json:"description,omitempty"`
	AccountUUID     string   `json:"account_uuid"`
	ChallengeUUID   string   `json:"challenge_type_uuid"`
	AutomationUUIDs []string `json:"automation_uuids"`
	KeyLength       string   `json:"key_length"`
	OCSP            bool     `json:"ocsp"`
	AutoRenewal     bool     `json:"auto_renewal"`
	RenewInterval   *int64   `json:"renew_interval_days,omitempty"`
	AliasMode       string   `json:"alias_mode"`
	DomainAlias     string   `json:"domain_alias,omitempty"`
	ChallengeAlias  string   `json:"challenge_alias,omitempty"`
	Enabled         bool     `json:"enabled"`
	Status          string   `json:"status"`
	StatusCode      string   `json:"status_code"`
	StatusUpdated   string   `json:"status_updated,omitempty"`
	LastIssued      string   `json:"last_issued,omitempty"`
	CertRefID       string   `json:"cert_ref_id,omitempty" jsonschema:"refid in System → Trust → Certificates once issued"`
}

type acmeCertificateCreateIn struct {
	Name           string    `json:"name" jsonschema:"common name, e.g. fw.example.com"`
	AltNames       []string  `json:"alt_names,omitempty" jsonschema:"additional names (SANs)"`
	Account        NameRef   `json:"account"`
	ChallengeType  NameRef   `json:"challenge_type"`
	Automations    []NameRef `json:"automations,omitempty" jsonschema:"automations to run after issue/renewal"`
	KeyLength      string    `json:"key_length,omitempty" jsonschema:"defaults to key_4096"`
	OCSP           bool      `json:"ocsp,omitempty" jsonschema:"request OCSP must-staple"`
	AutoRenewal    *bool     `json:"auto_renewal,omitempty" jsonschema:"defaults to true"`
	RenewInterval  *int64    `json:"renew_interval_days,omitempty" jsonschema:"days between renewals; defaults to 60"`
	AliasMode      string    `json:"alias_mode,omitempty" jsonschema:"DNS alias mode; defaults to none"`
	DomainAlias    string    `json:"domain_alias,omitempty"`
	ChallengeAlias string    `json:"challenge_alias,omitempty"`
	Description    string    `json:"description,omitempty"`
	Enabled        *bool     `json:"enabled,omitempty" jsonschema:"defaults to true"`
}

type acmeCertificateUpdateIn struct {
	NameRef
	NewName        *string    `json:"new_name,omitempty" jsonschema:"new common name"`
	AltNames       *[]string  `json:"alt_names,omitempty" jsonschema:"replaces the whole list"`
	Account        *NameRef   `json:"account,omitempty"`
	ChallengeType  *NameRef   `json:"challenge_type,omitempty"`
	Automations    *[]NameRef `json:"automations,omitempty" jsonschema:"replaces the whole list"`
	KeyLength      *string    `json:"key_length,omitempty"`
	OCSP           *bool      `json:"ocsp,omitempty"`
	AutoRenewal    *bool      `json:"auto_renewal,omitempty"`
	RenewInterval  *int64     `json:"renew_interval_days,omitempty"`
	AliasMode      *string    `json:"alias_mode,omitempty"`
	DomainAlias    *string    `json:"domain_alias,omitempty"`
	ChallengeAlias *string    `json:"challenge_alias,omitempty"`
	Description    *string    `json:"description,omitempty"`
	Enabled        *bool      `json:"enabled,omitempty"`
}

type acmeOperationOut struct {
	UUID     string `json:"uuid"`
	Started  bool   `json:"started"`
	Response string `json:"response,omitempty"`
	Note     string `json:"note"`
}

func certificateView(id string, c *opnsense.AcmeCertificate) acmeCertificateView {
	return acmeCertificateView{
		UUID: id, Name: c.Name, AltNames: nonNil([]string(c.AltNames)), Description: c.Description,
		AccountUUID: string(c.Account), ChallengeUUID: string(c.ValidationMethod),
		AutomationUUIDs: nonNil([]string(c.RestartActions)), KeyLength: string(c.KeyLength), OCSP: bool(c.OCSP),
		AutoRenewal: bool(c.AutoRenewal), RenewInterval: intPtr(c.RenewInterval), AliasMode: string(c.AliasMode),
		DomainAlias: c.DomainAlias, ChallengeAlias: c.ChallengeAlias, Enabled: bool(c.Enabled),
		Status: opnsense.AcmeStatusText(string(c.StatusCode)), StatusCode: string(c.StatusCode),
		StatusUpdated: unixTime(c.StatusLastUpdate), LastIssued: unixTime(c.LastUpdate), CertRefID: string(c.CertRefID),
	}
}

func optionPtr(v *string) *opnsense.Option {
	if v == nil {
		return nil
	}
	o := opnsense.Option(*v)
	return &o
}

func boolPtr(v *bool) *opnsense.Bool {
	if v == nil {
		return nil
	}
	b := opnsense.Bool(*v)
	return &b
}

func checkOneOf(field, v string, allowed []string) error {
	if v != "" && !slices.Contains(allowed, v) {
		return fmt.Errorf("%s %q is not one of %s", field, v, strings.Join(allowed, ", "))
	}
	return nil
}

func acmeTools(c *opnsense.Client) []tool {
	acme := c.Acme
	resolveAutomations := func(ctx context.Context, refs []NameRef) (opnsense.CSVList, error) {
		var ids opnsense.CSVList
		for _, r := range refs {
			id, err := resolveNamed(ctx, acme.Automations, r, "automation")
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, nil
	}

	return []tool{
		// settings
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_settings_get",
				Description: "Get the ACME client's global settings (Services → ACME Client → Settings).",
				Annotations: &mcp.ToolAnnotations{Title: "Get ACME settings", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, acmeSettingsView, error) {
				st, err := acme.Settings.Get(ctx)
				if err != nil {
					return nil, acmeSettingsView{}, err
				}
				return nil, settingsView(st), nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_settings_update",
				Description: "Change ACME client global settings; only the fields given change. " +
					"enabled must be true for certificates to be issued. Call acme_apply afterwards.",
				Annotations: &mcp.ToolAnnotations{Title: "Update ACME settings", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeSettingsIn) (*mcp.CallToolResult, acmeSettingsView, error) {
				if in.Environment != nil {
					if err := checkOneOf("environment", *in.Environment, []string{"prod", "stg"}); err != nil {
						return nil, acmeSettingsView{}, err
					}
				}
				st, err := acme.Settings.Get(ctx)
				if err != nil {
					return nil, acmeSettingsView{}, err
				}
				setAs(&st.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				setAs(&st.AutoRenewal, in.AutoRenewal, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				setAs(&st.Environment, in.Environment, func(v string) opnsense.Option { return opnsense.Option(v) })
				setAs(&st.ChallengePort, in.ChallengePort, opnsense.IntOf)
				setAs(&st.TLSChallengePort, in.TLSChallengePort, opnsense.IntOf)
				setAs(&st.RestartTimeout, in.RestartTimeout, opnsense.IntOf)
				setAs(&st.LogLevel, in.LogLevel, func(v string) opnsense.Option { return opnsense.Option(v) })
				setAs(&st.HAProxyIntegration, in.HAProxyIntegration, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				if err := acme.Settings.Set(ctx, *st); err != nil {
					return nil, acmeSettingsView{}, err
				}
				return nil, settingsView(st), nil
			})
		}},

		// accounts
		listTool(acmeToolset, "acme_account_list", "List ACME accounts", "List ACME accounts (Services → ACME Client → Accounts).", acme.Accounts),
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_account_get",
				Description: "Get an ACME account by UUID or name, including its registration status.",
				Annotations: &mcp.ToolAnnotations{Title: "Get ACME account", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeAccountView, error) {
				id, err := resolveNamed(ctx, acme.Accounts, in, "account")
				if err != nil {
					return nil, acmeAccountView{}, err
				}
				a, err := acme.Accounts.Get(ctx, id)
				if err != nil {
					return nil, acmeAccountView{}, notFoundAs(err, "account", id)
				}
				return nil, accountView(id, a), nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_account_create",
				Description: "Create an ACME account with a certificate authority. Register it with acme_account_register, " +
					"or let the first certificate issue do it.",
				InputSchema: withEnum[acmeAccountCreateIn]("ca", opnsense.AcmeCAs),
				Annotations: &mcp.ToolAnnotations{Title: "Create ACME account", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeAccountCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				ca := in.CA
				if ca == "" {
					ca = "letsencrypt"
				}
				if ca == "custom" && in.CustomCA == "" {
					return nil, stagedOut{}, errors.New("ca custom needs custom_ca (the ACME directory URL)")
				}
				id, err := acme.Accounts.Add(ctx, opnsense.AcmeAccount{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Name: in.Name, Description: in.Description,
					Email: in.Email, CA: opnsense.Option(ca), CustomCA: in.CustomCA, EABKID: in.EABKID, EABHMAC: in.EABHMAC,
				})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: acmeStagedNote}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_account_update",
				Description: "Change an ACME account, by UUID or name; only the fields given change.",
				InputSchema: withEnum[acmeAccountUpdateIn]("ca", opnsense.AcmeCAs),
				Annotations: &mcp.ToolAnnotations{Title: "Update ACME account", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeAccountUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, acme.Accounts, in.NameRef, "account")
				if err != nil {
					return nil, stagedOut{}, err
				}
				a, err := acme.Accounts.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "account", id)
				}
				set(&a.Name, in.NewName)
				set(&a.Email, in.Email)
				setAs(&a.CA, in.CA, func(v string) opnsense.Option { return opnsense.Option(v) })
				set(&a.CustomCA, in.CustomCA)
				set(&a.EABKID, in.EABKID)
				set(&a.EABHMAC, in.EABHMAC)
				set(&a.Description, in.Description)
				setAs(&a.Enabled, in.Enabled, func(v bool) opnsense.Bool { return opnsense.Bool(v) })
				if err := acme.Accounts.Set(ctx, id, *a); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: acmeStagedNote}, nil
			})
		}},
		deleteTool(acmeToolset, "acme_account_delete", "Delete ACME account", "ACME account",
			" Certificates that use it stop renewing.", acmeStagedNote, acme.Accounts),
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_account_register",
				Description: "Register an ACME account with its certificate authority now. Contacts the CA. Confirm with the user first.",
				Annotations: &mcp.ToolAnnotations{Title: "Register ACME account", DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeAccountView, error) {
				id, err := resolveNamed(ctx, acme.Accounts, in, "account")
				if err != nil {
					return nil, acmeAccountView{}, err
				}
				if _, err := acme.RegisterAccount(ctx, id); err != nil {
					return nil, acmeAccountView{}, err
				}
				a, err := acme.Accounts.Get(ctx, id)
				if err != nil {
					return nil, acmeAccountView{}, err
				}
				return nil, accountView(id, a), nil
			})
		}},

		// challenge types
		listTool(acmeToolset, "acme_challenge_type_list", "List ACME challenge types",
			"List ACME challenge types: how domain ownership is proven (DNS-01 with a DNS provider, HTTP-01, TLS-ALPN-01).",
			acme.ChallengeTypes),
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_challenge_type_get",
				Description: "Get an ACME challenge type by UUID or name, with the settings for its method/provider. Credentials are hidden.",
				Annotations: &mcp.ToolAnnotations{Title: "Get ACME challenge type", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeChallengeView, error) {
				id, err := resolveNamed(ctx, acme.ChallengeTypes, in, "challenge type")
				if err != nil {
					return nil, acmeChallengeView{}, err
				}
				v, err := acme.ChallengeTypes.Get(ctx, id)
				if err != nil {
					return nil, acmeChallengeView{}, notFoundAs(err, "challenge type", id)
				}
				tmpl, err := acme.ChallengeTypeTemplate(ctx)
				if err != nil {
					return nil, acmeChallengeView{}, err
				}
				out := acmeChallengeView{
					UUID: id, Name: v.Name, Description: v.Description, Method: string(v.Method),
					DNSSleep: intPtr(v.DNSSleep), Enabled: bool(v.Enabled),
					Params: redactParams(opnsense.RelevantParams(v.Params, v.ParamPrefixes(), tmpl.Defaults)),
				}
				if v.Method == "dns01" {
					out.DNSService = string(v.DNSService)
				}
				return nil, out, nil
			})
		}},
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_challenge_type_fields",
				Description: "Discover challenge type settings. With method=dns01 and no dns_service, lists DNS providers " +
					"(filter with search). With a dns_service, lists that provider's fields (e.g. dns_cf_token). " +
					"With http01 or tlsalpn01, lists that method's fields.",
				Annotations: &mcp.ToolAnnotations{Title: "List ACME challenge fields", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in fieldsIn) (*mcp.CallToolResult, fieldsOut, error) {
				tmpl, err := acme.ChallengeTypeTemplate(ctx)
				if err != nil {
					return nil, fieldsOut{}, err
				}
				probe := opnsense.AcmeChallengeType{Method: opnsense.Option(in.Method), DNSService: opnsense.Option(in.DNSService)}
				if in.Method == "" {
					probe.Method = "dns01"
				}
				if probe.Method == "dns01" && in.DNSService == "" {
					return nil, fieldsOut{Options: filterOptions(tmpl.Choices["dns_service"], in.Search), Fields: []fieldInfo{}}, nil
				}
				return nil, fieldsOut{Fields: templateFields(tmpl, probe.ParamPrefixes(), in.Search, nil)}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_challenge_type_create",
				Description: "Create an ACME challenge type. For DNS-01, pick dns_service and pass the provider's fields in " +
					"params (find them with acme_challenge_type_fields). Ask the user for credentials; never invent them.",
				InputSchema: withEnum[acmeChallengeCreateIn]("method", opnsense.AcmeChallengeMethods),
				Annotations: &mcp.ToolAnnotations{Title: "Create ACME challenge type", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeChallengeCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				method := in.Method
				if method == "" {
					method = "dns01"
				}
				if method == "dns01" && in.DNSService == "" {
					return nil, stagedOut{}, errors.New("dns01 needs dns_service; list providers with acme_challenge_type_fields")
				}
				v := opnsense.AcmeChallengeType{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Name: in.Name, Description: in.Description,
					Method: opnsense.Option(method), DNSService: opnsense.Option(in.DNSService), DNSSleep: toInt(in.DNSSleep),
					Params: mergeParams(in.Params),
				}
				if v.DNSService == "" {
					v.DNSService = "dns_freedns" // the model default; required even when unused
				}
				if !v.DNSSleep.Valid {
					v.DNSSleep = opnsense.IntOf(0)
				}
				if err := checkParams(ctx, acme.ChallengeTypeTemplate, in.Params); err != nil {
					return nil, stagedOut{}, err
				}
				id, err := acme.ChallengeTypes.Add(ctx, v)
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: acmeStagedNote}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_challenge_type_update",
				Description: "Change an ACME challenge type, by UUID or name; only the fields given change.",
				InputSchema: withEnum[acmeChallengeUpdateIn]("method", opnsense.AcmeChallengeMethods),
				Annotations: &mcp.ToolAnnotations{Title: "Update ACME challenge type", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeChallengeUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, acme.ChallengeTypes, in.NameRef, "challenge type")
				if err != nil {
					return nil, stagedOut{}, err
				}
				v, err := acme.ChallengeTypes.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "challenge type", id)
				}
				if err := checkParams(ctx, acme.ChallengeTypeTemplate, in.Params); err != nil {
					return nil, stagedOut{}, err
				}
				set(&v.Name, in.NewName)
				setAs(&v.Method, in.Method, func(x string) opnsense.Option { return opnsense.Option(x) })
				setAs(&v.DNSService, in.DNSService, func(x string) opnsense.Option { return opnsense.Option(x) })
				setAs(&v.DNSSleep, in.DNSSleep, opnsense.IntOf)
				set(&v.Description, in.Description)
				setAs(&v.Enabled, in.Enabled, func(x bool) opnsense.Bool { return opnsense.Bool(x) })
				// Send only the changed params; OPNsense keeps the rest.
				v.Params = mergeParams(in.Params)
				if err := acme.ChallengeTypes.Set(ctx, id, *v); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: acmeStagedNote}, nil
			})
		}},
		deleteTool(acmeToolset, "acme_challenge_type_delete", "Delete ACME challenge type", "ACME challenge type",
			" Certificates that use it can no longer renew.", acmeStagedNote, acme.ChallengeTypes),

		// automations
		listTool(acmeToolset, "acme_automation_list", "List ACME automations",
			"List ACME automations: actions run after a certificate is issued or renewed (restart a service, upload by SFTP, deploy to Proxmox, ...).",
			acme.Automations),
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_automation_get",
				Description: "Get an ACME automation by UUID or name, with its type-specific settings. Credentials are hidden.",
				Annotations: &mcp.ToolAnnotations{Title: "Get ACME automation", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeAutomationView, error) {
				id, err := resolveNamed(ctx, acme.Automations, in, "automation")
				if err != nil {
					return nil, acmeAutomationView{}, err
				}
				a, err := acme.Automations.Get(ctx, id)
				if err != nil {
					return nil, acmeAutomationView{}, notFoundAs(err, "automation", id)
				}
				tmpl, err := acme.AutomationTemplate(ctx)
				if err != nil {
					return nil, acmeAutomationView{}, err
				}
				return nil, acmeAutomationView{
					UUID: id, Name: a.Name, Description: a.Description, Type: string(a.Type), Enabled: bool(a.Enabled),
					Params: redactParams(opnsense.RelevantParams(a.Params, a.ParamPrefixes(), tmpl.Defaults)),
				}, nil
			})
		}},
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_automation_fields",
				Description: "Discover automation settings. Without type, lists automation types; with a type, lists its fields.",
				Annotations: &mcp.ToolAnnotations{Title: "List ACME automation fields", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in fieldsIn) (*mcp.CallToolResult, fieldsOut, error) {
				tmpl, err := acme.AutomationTemplate(ctx)
				if err != nil {
					return nil, fieldsOut{}, err
				}
				if in.Type == "" {
					return nil, fieldsOut{Options: filterOptions(tmpl.Choices["type"], in.Search), Fields: []fieldInfo{}}, nil
				}
				probe := opnsense.AcmeAutomation{Type: opnsense.Option(in.Type)}
				return nil, fieldsOut{Fields: templateFields(tmpl, probe.ParamPrefixes(), in.Search, nil)}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_automation_create",
				Description: "Create an ACME automation. Pass type-specific fields in params (find them with acme_automation_fields). " +
					"Ask the user for credentials; never invent them.",
				Annotations: &mcp.ToolAnnotations{Title: "Create ACME automation", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeAutomationCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				if err := checkParams(ctx, acme.AutomationTemplate, in.Params); err != nil {
					return nil, stagedOut{}, err
				}
				id, err := acme.Automations.Add(ctx, opnsense.AcmeAutomation{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Name: in.Name, Description: in.Description,
					Type: opnsense.Option(in.Type), Params: mergeParams(in.Params),
				})
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: acmeStagedNote}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_automation_update",
				Description: "Change an ACME automation, by UUID or name; only the fields given change.",
				Annotations: &mcp.ToolAnnotations{Title: "Update ACME automation", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeAutomationUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, acme.Automations, in.NameRef, "automation")
				if err != nil {
					return nil, stagedOut{}, err
				}
				a, err := acme.Automations.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "automation", id)
				}
				if err := checkParams(ctx, acme.AutomationTemplate, in.Params); err != nil {
					return nil, stagedOut{}, err
				}
				set(&a.Name, in.NewName)
				setAs(&a.Type, in.Type, func(x string) opnsense.Option { return opnsense.Option(x) })
				set(&a.Description, in.Description)
				setAs(&a.Enabled, in.Enabled, func(x bool) opnsense.Bool { return opnsense.Bool(x) })
				a.Params = mergeParams(in.Params)
				if err := acme.Automations.Set(ctx, id, *a); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: acmeStagedNote}, nil
			})
		}},
		deleteTool(acmeToolset, "acme_automation_delete", "Delete ACME automation", "ACME automation", "", acmeStagedNote, acme.Automations),

		// certificates
		listTool(acmeToolset, "acme_certificate_list", "List ACME certificates",
			"List ACME certificates with their last status (statusCode 200 = OK, 300 = configuration error, 400 = validation failed).",
			acme.Certificates),
		{toolset: acmeToolset, readOnly: true, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_certificate_get",
				Description: "Get an ACME certificate by UUID or name (common name), with status and last issue time.",
				Annotations: &mcp.ToolAnnotations{Title: "Get ACME certificate", ReadOnlyHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeCertificateView, error) {
				id, err := resolveNamed(ctx, acme.Certificates, in, "certificate")
				if err != nil {
					return nil, acmeCertificateView{}, err
				}
				cert, err := acme.Certificates.Get(ctx, id)
				if err != nil {
					return nil, acmeCertificateView{}, notFoundAs(err, "certificate", id)
				}
				return nil, certificateView(id, cert), nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_certificate_create",
				Description: "Create an ACME certificate. It is not issued until acme_certificate_issue runs or the renewal job picks it up.",
				InputSchema: withEnum[acmeCertificateCreateIn]("key_length", opnsense.AcmeKeyLengths),
				Annotations: &mcp.ToolAnnotations{Title: "Create ACME certificate", DestructiveHint: ptr(false)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeCertificateCreateIn) (*mcp.CallToolResult, stagedOut, error) {
				if err := checkOneOf("alias_mode", in.AliasMode, opnsense.AcmeAliasModes); err != nil {
					return nil, stagedOut{}, err
				}
				acct, err := resolveNamed(ctx, acme.Accounts, in.Account, "account")
				if err != nil {
					return nil, stagedOut{}, err
				}
				ch, err := resolveNamed(ctx, acme.ChallengeTypes, in.ChallengeType, "challenge type")
				if err != nil {
					return nil, stagedOut{}, err
				}
				autos, err := resolveAutomations(ctx, in.Automations)
				if err != nil {
					return nil, stagedOut{}, err
				}
				cert := opnsense.AcmeCertificate{
					Enabled: opnsense.Bool(in.Enabled == nil || *in.Enabled), Name: in.Name, Description: in.Description,
					AltNames: in.AltNames, Account: opnsense.Option(acct), ValidationMethod: opnsense.Option(ch),
					KeyLength: "key_4096", OCSP: opnsense.Bool(in.OCSP), RestartActions: autos,
					AutoRenewal: opnsense.Bool(in.AutoRenewal == nil || *in.AutoRenewal), RenewInterval: opnsense.IntOf(60),
					AliasMode: "none", DomainAlias: in.DomainAlias, ChallengeAlias: in.ChallengeAlias,
				}
				if in.KeyLength != "" {
					cert.KeyLength = opnsense.Option(in.KeyLength)
				}
				if in.RenewInterval != nil {
					cert.RenewInterval = opnsense.IntOf(*in.RenewInterval)
				}
				if in.AliasMode != "" {
					cert.AliasMode = opnsense.Option(in.AliasMode)
				}
				id, err := acme.Certificates.Add(ctx, cert)
				if err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: "Certificate saved. Call acme_certificate_issue to issue it now."}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_certificate_update",
				Description: "Change an ACME certificate, by UUID or name; only the fields given change. " +
					"Name/SAN changes take effect at the next issue or renewal.",
				InputSchema: withEnum[acmeCertificateUpdateIn]("key_length", opnsense.AcmeKeyLengths),
				Annotations: &mcp.ToolAnnotations{Title: "Update ACME certificate", IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in acmeCertificateUpdateIn) (*mcp.CallToolResult, stagedOut, error) {
				id, err := resolveNamed(ctx, acme.Certificates, in.NameRef, "certificate")
				if err != nil {
					return nil, stagedOut{}, err
				}
				cert, err := acme.Certificates.Get(ctx, id)
				if err != nil {
					return nil, stagedOut{}, notFoundAs(err, "certificate", id)
				}
				if in.AliasMode != nil {
					if err := checkOneOf("alias_mode", *in.AliasMode, opnsense.AcmeAliasModes); err != nil {
						return nil, stagedOut{}, err
					}
				}
				if in.Account != nil {
					acct, err := resolveNamed(ctx, acme.Accounts, *in.Account, "account")
					if err != nil {
						return nil, stagedOut{}, err
					}
					cert.Account = opnsense.Option(acct)
				}
				if in.ChallengeType != nil {
					ch, err := resolveNamed(ctx, acme.ChallengeTypes, *in.ChallengeType, "challenge type")
					if err != nil {
						return nil, stagedOut{}, err
					}
					cert.ValidationMethod = opnsense.Option(ch)
				}
				if in.Automations != nil {
					autos, err := resolveAutomations(ctx, *in.Automations)
					if err != nil {
						return nil, stagedOut{}, err
					}
					cert.RestartActions = autos
				}
				set(&cert.Name, in.NewName)
				setAs(&cert.AltNames, in.AltNames, func(v []string) opnsense.CSVList { return v })
				if p := optionPtr(in.KeyLength); p != nil {
					cert.KeyLength = *p
				}
				if p := boolPtr(in.OCSP); p != nil {
					cert.OCSP = *p
				}
				if p := boolPtr(in.AutoRenewal); p != nil {
					cert.AutoRenewal = *p
				}
				setAs(&cert.RenewInterval, in.RenewInterval, opnsense.IntOf)
				if p := optionPtr(in.AliasMode); p != nil {
					cert.AliasMode = *p
				}
				set(&cert.DomainAlias, in.DomainAlias)
				set(&cert.ChallengeAlias, in.ChallengeAlias)
				set(&cert.Description, in.Description)
				if p := boolPtr(in.Enabled); p != nil {
					cert.Enabled = *p
				}
				if err := acme.Certificates.Set(ctx, id, *cert); err != nil {
					return nil, stagedOut{}, err
				}
				return nil, stagedOut{UUID: id, Staged: true, Note: "Certificate saved."}, nil
			})
		}},
		deleteTool(acmeToolset, "acme_certificate_delete", "Delete ACME certificate", "ACME certificate",
			" The issued certificate stays in System → Trust → Certificates but is no longer renewed.", acmeStagedNote, acme.Certificates),
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_certificate_issue",
				Description: "Issue or force-renew an ACME certificate now. Contacts the CA and runs in the background on the " +
					"firewall; check acme_certificate_get after a minute (status ok, or the error). The ACME client must be " +
					"enabled (acme_settings_update) and acme_apply run after config changes. Confirm with the user first: " +
					"CAs rate-limit issuance.",
				Annotations: &mcp.ToolAnnotations{Title: "Issue ACME certificate", DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeOperationOut, error) {
				id, err := resolveNamed(ctx, acme.Certificates, in, "certificate")
				if err != nil {
					return nil, acmeOperationOut{}, err
				}
				st, err := acme.Settings.Get(ctx)
				if err != nil {
					return nil, acmeOperationOut{}, err
				}
				if !st.Enabled {
					return nil, acmeOperationOut{}, errors.New("the ACME client is disabled; enable it with acme_settings_update and run acme_apply first")
				}
				resp, err := acme.IssueCertificate(ctx, id)
				if err != nil {
					return nil, acmeOperationOut{}, err
				}
				return nil, acmeOperationOut{UUID: id, Started: true, Response: resp,
					Note: "Issuing runs in the background. Check acme_certificate_get for status in a minute."}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_certificate_revoke",
				Description: "Revoke an ACME certificate with its CA. Irreversible: services using it will show it as invalid. " +
					"Confirm with the user first.",
				Annotations: &mcp.ToolAnnotations{Title: "Revoke ACME certificate", DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeOperationOut, error) {
				id, err := resolveNamed(ctx, acme.Certificates, in, "certificate")
				if err != nil {
					return nil, acmeOperationOut{}, err
				}
				resp, err := acme.RevokeCertificate(ctx, id)
				if err != nil {
					return nil, acmeOperationOut{}, err
				}
				return nil, acmeOperationOut{UUID: id, Started: true, Response: resp, Note: "Revocation requested."}, nil
			})
		}},
		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_certificate_run_automations",
				Description: "Run a certificate's automations again (e.g. redeploy it) without renewing it.",
				Annotations: &mcp.ToolAnnotations{Title: "Run ACME automations", DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, in NameRef) (*mcp.CallToolResult, acmeOperationOut, error) {
				id, err := resolveNamed(ctx, acme.Certificates, in, "certificate")
				if err != nil {
					return nil, acmeOperationOut{}, err
				}
				if err := acme.RunAutomations(ctx, id); err != nil {
					return nil, acmeOperationOut{}, err
				}
				return nil, acmeOperationOut{UUID: id, Started: true, Note: "Automations started."}, nil
			})
		}},

		{toolset: acmeToolset, register: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{Name: "acme_apply",
				Description: "Apply ACME client changes: regenerate its configuration and restart its challenge web server. " +
					"Confirm with the user before calling.",
				Annotations: &mcp.ToolAnnotations{Title: "Apply ACME changes", DestructiveHint: ptr(true), IdempotentHint: true},
			}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, applyOut, error) {
				if err := acme.Apply(ctx); err != nil {
					return nil, applyOut{}, err
				}
				return nil, applyOut{Applied: true}, nil
			})
		}},
	}
}

// checkParams rejects param names the model does not have; OPNsense would silently drop them.
func checkParams(ctx context.Context, template func(context.Context) (*opnsense.AcmeTemplate, error), params map[string]string) error {
	if len(params) == 0 {
		return nil
	}
	t, err := template(ctx)
	if err != nil {
		return err
	}
	var unknown []string
	for k := range params {
		if _, ok := t.Defaults[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown params %s; list valid fields with the *_fields tool", strings.Join(unknown, ", "))
	}
	return nil
}
