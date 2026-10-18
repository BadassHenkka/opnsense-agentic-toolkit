package mcpserver

import (
	"context"
	"regexp"
	"strings"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// secretElement matches config.xml element names that hold credentials. A backup diff shows
// them verbatim, so their content is replaced. Public keys (pubkey), privilege lists (priv)
// and flags such as passive or bypass are not secret and stay visible.
var secretElement = regexp.MustCompile(`(?i)^(` +
	`privkey|psk|prv|prv_payload|password|scrambled_password|passwd|secret|authkey|` +
	`basicauthpass|eab_hmac|ddns_domain_key_secret|otp_seed|poolopts_sourcehashkey|` +
	`tlsdnsapikey|smtpauth_password|apikey|` +
	`.*_(password|passwd|secret|token|apikey)|dns_.*(token|key|secret|pass|api).*|.*tokenkey` +
	`)$`)

var xmlElement = regexp.MustCompile(`<([A-Za-z_][\w.:-]*)>([^<]+)</([A-Za-z_][\w.:-]*)>`)

// redactDiffLine hides the content of credential elements in one line of a config.xml diff.
func redactDiffLine(line string) string {
	return xmlElement.ReplaceAllStringFunc(line, func(m string) string {
		sub := xmlElement.FindStringSubmatch(m)
		if sub[1] != sub[3] || !secretElement.MatchString(sub[1]) {
			return m
		}
		return "<" + sub[1] + ">" + redacted + "</" + sub[1] + ">"
	})
}

func redactDiff(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = redactDiffLine(l)
	}
	return out
}

// redactCaddyfile removes the credentials the generated Caddyfile embeds: the DNS provider's
// API key and the password hashes of basic auth users.
func redactCaddyfile(ctx context.Context, cd *opnsense.CaddyService, text string) string {
	var secrets []string
	if g, err := cd.General.Get(ctx); err == nil && g.TLSDNSAPIKey != "" {
		secrets = append(secrets, g.TLSDNSAPIKey)
	}
	if res, err := cd.BasicAuths.Search(ctx, ""); err == nil {
		for _, r := range res.Rows {
			if a, err := cd.BasicAuths.Get(ctx, string(r.UUID)); err == nil && a.Password != "" {
				secrets = append(secrets, a.Password)
			}
		}
	}
	for _, s := range secrets {
		text = strings.ReplaceAll(text, s, redacted)
	}
	return text
}
