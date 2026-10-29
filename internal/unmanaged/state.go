// Package unmanaged finds live OPNsense objects that no resource in an OpenTofu or Terraform
// state manages. A plan only compares the resources it knows, so an object added in the web
// UI never shows up there.
package unmanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// State holds what Find needs from a state: the type, address and id of each managed
// resource. It never holds other attribute values.
type State struct {
	// IDs maps each opnsense_* resource type to the ids in the state.
	IDs map[string]map[string]bool
	// Addresses holds every resource address, so import blocks don't reuse one.
	Addresses map[string]bool
}

// The decoder fills only these fields and skips the rest of the document, which holds
// secrets in plain text (`tofu show -json` prints sensitive values).
type showJSON struct {
	Values     *stateValues `json:"values"` // tofu show -json
	PriorState *struct {
		Values *stateValues `json:"values"`
	} `json:"prior_state"` // tofu show -json <planfile>
}

type stateValues struct {
	RootModule moduleJSON `json:"root_module"`
}

type moduleJSON struct {
	Resources    []resourceJSON `json:"resources"`
	ChildModules []moduleJSON   `json:"child_modules"`
}

type resourceJSON struct {
	Address string `json:"address"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Values  struct {
		ID string `json:"id"`
	} `json:"values"`
}

// ReadState reads the JSON of `tofu show -json` or `terraform show -json`, of a state or of a
// saved plan (its prior state).
func ReadState(r io.Reader) (*State, error) {
	var doc showJSON
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, decodeError(err)
	}
	vals := doc.Values
	if vals == nil && doc.PriorState != nil {
		vals = doc.PriorState.Values
	}
	st := &State{IDs: map[string]map[string]bool{}, Addresses: map[string]bool{}}
	if vals != nil {
		st.add(vals.RootModule)
	}
	return st, nil
}

func (st *State) add(m moduleJSON) {
	for _, r := range m.Resources {
		st.Addresses[r.Address] = true
		if r.Mode != "managed" || !strings.HasPrefix(r.Type, "opnsense_") || r.Values.ID == "" {
			continue
		}
		if st.IDs[r.Type] == nil {
			st.IDs[r.Type] = map[string]bool{}
		}
		st.IDs[r.Type][r.Values.ID] = true
	}
	for _, c := range m.ChildModules {
		st.add(c)
	}
}

// decodeError describes a JSON error without quoting the input, which may be a secret.
func decodeError(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("state: invalid JSON at byte %d; pass the output of `tofu show -json`", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("state: unexpected %s at %s; pass the output of `tofu show -json`", typ.Value, typ.Field)
	case errors.Is(err, io.EOF):
		return errors.New("state: no input; pass the output of `tofu show -json`")
	}
	return errors.New("state: cannot read the JSON; pass the output of `tofu show -json`")
}
