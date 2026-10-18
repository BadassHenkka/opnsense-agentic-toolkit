package opnsense

import (
	"context"
	"fmt"
	"net/url"
)

// Services → Intrusion Detection, beyond the generated policies, user rules and settings.
//
//	listRulesets                  rows {filename, description, enabled, modified_local, ...}
//	toggleRuleset/<file>/<0|1>    {"status":"1"} / {"status":"0"}; "error" for unknown files
//
// A ruleset is a downloaded rule file. It only shows up after `ids/service/updateRules`
// (System → Services, or the UI button) has fetched it, so Terraform cannot create one.
// Changes take effect after ids/service/reconfigure.

// IDSRuleset is one downloadable rule file.
type IDSRuleset struct {
	Filename    string `json:"filename"`
	Description string `json:"description"`
	Enabled     Bool   `json:"enabled"`
}

// Rulesets lists every known ruleset with its enabled state.
func (s *IDSService) Rulesets(ctx context.Context) ([]IDSRuleset, error) {
	var res SearchResult[IDSRuleset]
	if err := s.c.Post(ctx, "ids/settings/listRulesets", map[string]any{"current": 1, "rowCount": -1}, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// Ruleset returns the ruleset with this file name, or ErrNotFound.
func (s *IDSService) Ruleset(ctx context.Context, filename string) (*IDSRuleset, error) {
	all, err := s.Rulesets(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.Filename == filename {
			return &r, nil
		}
	}
	return nil, ErrNotFound
}

// SetRulesetEnabled enables or disables a ruleset and reloads the engine.
func (s *IDSService) SetRulesetEnabled(ctx context.Context, filename string, enabled bool) error {
	flag := "0"
	if enabled {
		flag = "1"
	}
	var res struct {
		Status string `json:"status"`
	}
	if err := s.c.Post(ctx, "ids/settings/toggleRuleset/"+url.PathEscape(filename)+"/"+flag, nil, &res); err != nil {
		return err
	}
	if res.Status != flag {
		return fmt.Errorf("opnsense: ruleset %q not changed (status %q); download the rules first", filename, res.Status)
	}
	return s.c.Reconfigure(ctx, "ids/service/reconfigure")
}
