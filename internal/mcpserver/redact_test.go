package mcpserver

import "testing"

func TestRedactDiffLine(t *testing.T) {
	for in, want := range map[string]string{
		"+      <privkey>SENTINEL-SECRET-1</privkey>": "+      <privkey>(set, hidden)</privkey>",
		"-      <psk>SENTINEL-SECRET-2</psk>":         "-      <psk>(set, hidden)</psk>",
		"+<prv>SENTINEL-SECRET-3</prv>":               "+<prv>(set, hidden)</prv>",
		"+<password>$2y$10$SENTINEL</password>":       "+<password>(set, hidden)</password>",
		"+<authkey>SENTINEL</authkey><x>1</x>":        "+<authkey>(set, hidden)</authkey><x>1</x>",
		"+<dns_cf_token>SENTINEL</dns_cf_token>":      "+<dns_cf_token>(set, hidden)</dns_cf_token>",
		"+<otp_seed>SENTINEL</otp_seed>":              "+<otp_seed>(set, hidden)</otp_seed>",
		"+<TlsDnsApiKey>SENTINEL</TlsDnsApiKey>":      "+<TlsDnsApiKey>(set, hidden)</TlsDnsApiKey>",
		"+<pubkey>PUBLIC</pubkey>":                    "+<pubkey>PUBLIC</pubkey>",
		"+<priv>page-all</priv>":                      "+<priv>page-all</priv>",
		"+<passive>1</passive>":                       "+<passive>1</passive>",
		"+<descr>my password rotation</descr>":        "+<descr>my password rotation</descr>",
		"@@ -1,1 +1,2 @@":                             "@@ -1,1 +1,2 @@",
		"+<secret>SENTINEL</secret></item></apikeys>": "+<secret>(set, hidden)</secret></item></apikeys>",
	} {
		if got := redactDiffLine(in); got != want {
			t.Errorf("redactDiffLine(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}
