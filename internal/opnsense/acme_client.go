package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Services → ACME Client (plugin os-acme-client). The API lives under /api/acmeclient and is
// one model, AcmeClient.xml, with a settings section and four arrays:
//
//	UI name          API controller  model array               key
//	Accounts         accounts        accounts.account          account
//	Challenge Types  validations     validations.validation    validation
//	Automations      actions         actions.action            action
//	Certificates     certificates    certificates.certificate  certificate
//
// Settings, accounts, certificates and AcmeService are generated (gen/specs/acme.json);
// challenge types and automations are hand-written here (see acmeManual).
//
// Item actions are add/get/update/del/search (no suffix, "update" instead of "set"). All of
// them are applied with /api/acmeclient/service/reconfigure.

// ACME status codes, shared by accounts and certificates (statusCode).
const (
	AcmeStatusPending       = "100" // not registered / not issued yet
	AcmeStatusOK            = "200"
	AcmeStatusRevoked       = "250" // certificate revoked, or account deactivated
	AcmeStatusConfigError   = "300"
	AcmeStatusFailed        = "400" // certificate validation failed, or account registration failed
	AcmeStatusInternalError = "500"
)

// AcmeStatusText describes a statusCode.
func AcmeStatusText(code string) string {
	switch code {
	case "", AcmeStatusPending:
		return "pending"
	case AcmeStatusOK:
		return "ok"
	case AcmeStatusRevoked:
		return "revoked or deactivated"
	case AcmeStatusConfigError:
		return "configuration error"
	case AcmeStatusFailed:
		return "validation or registration failed"
	case AcmeStatusInternalError:
		return "internal error"
	default:
		return "unknown (" + code + ")"
	}
}

// AcmeCAs lists the certificate authorities an account can use.
var AcmeCAs = []string{
	"letsencrypt", "letsencrypt_test", "zerossl", "buypass", "buypass_test",
	"google", "google_test", "sslcom", "custom",
}

// AcmeKeyLengths lists the certificate key types.
var AcmeKeyLengths = []string{"key_2048", "key_3072", "key_4096", "key_ec256", "key_ec384"}

// AcmeChallengeMethods lists the challenge methods.
var AcmeChallengeMethods = []string{"dns01", "http01", "tlsalpn01"}

// AcmeAliasModes lists the DNS alias modes of a certificate.
var AcmeAliasModes = []string{"none", "automatic", "domain", "challenge"}

// AcmeChallengeType is a challenge type (API: validation). Method-specific settings, such as
// http_* fields or a DNS provider's dns_<provider>_* credentials, are in Params.
type AcmeChallengeType struct {
	Enabled     Bool   `json:"enabled"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Method      Option `json:"method"`      // dns01, http01, tlsalpn01
	DNSService  Option `json:"dns_service"` // e.g. dns_cf; used with dns01
	DNSSleep    Int    `json:"dns_sleep"`   // seconds to wait for DNS propagation; 0 = automatic
	Params      Params `json:"-"`
}

type acmeChallengeTypeFields AcmeChallengeType // same fields, without the methods below

func (v AcmeChallengeType) MarshalJSON() ([]byte, error) {
	return marshalWithParams(acmeChallengeTypeFields(v), v.Params)
}

func (v *AcmeChallengeType) UnmarshalJSON(data []byte) error {
	var f acmeChallengeTypeFields
	p, err := unmarshalWithParams(data, &f, "id")
	if err != nil {
		return err
	}
	*v = AcmeChallengeType(f)
	v.Params = p
	return nil
}

func (v *AcmeChallengeType) IsZero() bool { return v.Name == "" }

// ParamPrefixes returns the field prefixes that belong to this challenge type's method, used
// to pick its relevant params out of the full field set.
func (v *AcmeChallengeType) ParamPrefixes() []string {
	switch v.Method {
	case "http01":
		return []string{"http_"}
	case "tlsalpn01":
		return []string{"tlsalpn_"}
	default:
		return []string{string(v.DNSService) + "_"}
	}
}

// AcmeAutomation is an automation (API: action) that runs after a certificate is issued or
// renewed. Type-specific settings (sftp_*, acme_proxmoxve_*, ...) are in Params.
type AcmeAutomation struct {
	Enabled     Bool   `json:"enabled"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        Option `json:"type"`
	Params      Params `json:"-"`
}

type acmeAutomationFields AcmeAutomation

func (a AcmeAutomation) MarshalJSON() ([]byte, error) {
	return marshalWithParams(acmeAutomationFields(a), a.Params)
}

func (a *AcmeAutomation) UnmarshalJSON(data []byte) error {
	var f acmeAutomationFields
	p, err := unmarshalWithParams(data, &f, "id")
	if err != nil {
		return err
	}
	*a = AcmeAutomation(f)
	a.Params = p
	return nil
}

func (a *AcmeAutomation) IsZero() bool { return a.Name == "" }

// ParamPrefixes returns the field prefixes that belong to this automation's type.
func (a *AcmeAutomation) ParamPrefixes() []string {
	t := string(a.Type)
	switch {
	case t == "configd_upload_sftp":
		return []string{"sftp_"}
	case t == "configd_remote_ssh":
		return []string{"remote_ssh_"}
	case t == "configd_generic":
		return []string{"configd_generic"}
	case strings.HasPrefix(t, "acme_"):
		return []string{t + "_"}
	default:
		return nil // restart actions have no settings
	}
}

// Search rows. The plugin's search returns only a few columns.
type (
	AcmeChallengeTypeRow struct {
		UUID        Text `json:"uuid"`
		Enabled     Text `json:"enabled"`
		Name        Text `json:"name"`
		Method      Text `json:"method"`
		Description Text `json:"description"`
	}
	AcmeAutomationRow struct {
		UUID        Text `json:"uuid"`
		Enabled     Text `json:"enabled"`
		Name        Text `json:"name"`
		Type        Text `json:"type"`
		Description Text `json:"description"`
	}
)

// NamedRow is implemented by search rows that have a uuid and a unique-ish name.
type NamedRow interface{ RowRef() (uuid, name string) }

func (r AcmeChallengeTypeRow) RowRef() (string, string) { return string(r.UUID), string(r.Name) }
func (r AcmeAutomationRow) RowRef() (string, string)    { return string(r.UUID), string(r.Name) }

// acmeManual is the hand-written part of AcmeService (generated from gen/specs/acme.json,
// which embeds it): challenge types and automations, whose provider-specific fields are passed
// through as Params, and the cached field templates.
type acmeManual struct {
	ChallengeTypes *ItemController[AcmeChallengeType, AcmeChallengeTypeRow]
	Automations    *ItemController[AcmeAutomation, AcmeAutomationRow]

	templateMu sync.Mutex
	templates  map[string]*AcmeTemplate
}

const acmeReconfigure = "acmeclient/service/reconfigure"

var acmeActions = map[string]string{"add": "add", "get": "get", "set": "update", "del": "del", "search": "search"}

func newAcmeManual(c *Client) *acmeManual {
	return &acmeManual{
		ChallengeTypes: &ItemController[AcmeChallengeType, AcmeChallengeTypeRow]{
			c: c, Base: "acmeclient/validations", Key: "validation", Actions: acmeActions, ReconfigurePath: acmeReconfigure,
		},
		Automations: &ItemController[AcmeAutomation, AcmeAutomationRow]{
			c: c, Base: "acmeclient/actions", Key: "action", Actions: acmeActions, ReconfigurePath: acmeReconfigure,
		},
		templates: map[string]*AcmeTemplate{},
	}
}

// Apply regenerates the plugin configuration and restarts its challenge web server.
func (s *AcmeService) Apply(ctx context.Context) error { return s.c.Reconfigure(ctx, acmeReconfigure) }

// actionResponse is what the plugin's operation endpoints return.
type actionResponse struct {
	Result   string `json:"result"`
	Response string `json:"response"`
}

func (s *AcmeService) operation(ctx context.Context, path, uuid string) (string, error) {
	var resp actionResponse
	if err := s.c.Post(ctx, path+"/"+url.PathEscape(uuid), nil, &resp); err != nil {
		return "", err
	}
	if resp.Result == "failed" {
		return "", fmt.Errorf("opnsense: %s failed (unknown uuid %s?)", path, uuid)
	}
	return strings.TrimSpace(resp.Response), nil
}

// RegisterAccount registers an account with its CA. It runs synchronously; the outcome is
// recorded in the account's StatusCode.
func (s *AcmeService) RegisterAccount(ctx context.Context, uuid string) (string, error) {
	return s.operation(ctx, "acmeclient/accounts/register", uuid)
}

// IssueCertificate starts issuing (or force-renewing) a certificate. It runs in the
// background on the firewall: poll the certificate's StatusCode and LastUpdate.
func (s *AcmeService) IssueCertificate(ctx context.Context, uuid string) (string, error) {
	return s.operation(ctx, "acmeclient/certificates/sign", uuid)
}

// RevokeCertificate revokes a certificate with its CA.
func (s *AcmeService) RevokeCertificate(ctx context.Context, uuid string) (string, error) {
	return s.operation(ctx, "acmeclient/certificates/revoke", uuid)
}

// RunAutomations runs a certificate's automations again, e.g. to redeploy it.
func (s *AcmeService) RunAutomations(ctx context.Context, uuid string) error {
	// This endpoint always answers {"result":"failed"}, even when it ran (see
	// CertificatesController::automationAction), so only transport errors count.
	return s.c.Post(ctx, "acmeclient/certificates/automation/"+url.PathEscape(uuid), nil, nil)
}

// AcmeTemplate describes the fields of a new item: defaults and option choices.
type AcmeTemplate struct {
	Defaults Params
	Choices  map[string][]string
}

// ChallengeTypeTemplate returns the challenge type fields with defaults and choices. It is
// fetched once per client.
func (s *AcmeService) ChallengeTypeTemplate(ctx context.Context) (*AcmeTemplate, error) {
	return s.template(ctx, "validation", s.ChallengeTypes.Template)
}

// AutomationTemplate returns the automation fields with defaults and choices.
func (s *AcmeService) AutomationTemplate(ctx context.Context) (*AcmeTemplate, error) {
	return s.template(ctx, "action", s.Automations.Template)
}

func (s *AcmeService) template(ctx context.Context, key string, fetch func(context.Context) (map[string]json.RawMessage, error)) (*AcmeTemplate, error) {
	s.templateMu.Lock()
	defer s.templateMu.Unlock()
	if t, ok := s.templates[key]; ok {
		return t, nil
	}
	raw, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	d, ch := DecodeTemplate(raw)
	delete(d, "id")
	t := &AcmeTemplate{Defaults: d, Choices: ch}
	s.templates[key] = t
	return t, nil
}

// RelevantParams picks the params worth showing: those under the given prefixes, plus any
// other field that differs from its default.
func RelevantParams(p Params, prefixes []string, defaults Params) Params {
	out := Params{}
	for k, v := range p {
		under := false
		for _, pre := range prefixes {
			if pre != "" && strings.HasPrefix(k, pre) {
				under = true
				break
			}
		}
		if under || (v != "" && v != defaults[k]) {
			out[k] = v
		}
	}
	return out
}

// ResolveByName finds the uuid of the item whose name equals name (case-insensitive).
func ResolveByName[T any, S NamedRow](ctx context.Context, ic *ItemController[T, S], name string) (string, error) {
	res, err := ic.Search(ctx, name)
	if err != nil {
		return "", err
	}
	var hits []string
	for _, r := range res.Rows {
		id, n := r.RowRef()
		if strings.EqualFold(n, name) {
			hits = append(hits, id)
		}
	}
	switch len(hits) {
	case 0:
		return "", ErrNotFound
	case 1:
		return hits[0], nil
	default:
		return "", fmt.Errorf("opnsense: %d items are named %q; use a uuid", len(hits), name)
	}
}
