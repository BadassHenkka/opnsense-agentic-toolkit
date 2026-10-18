package opnsense

import (
	"context"
	"fmt"
	"strings"
)

// NamedRow is implemented by search rows that have a uuid and a unique-ish name.
type NamedRow interface{ RowRef() (uuid, name string) }

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
