package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
)

// Small helpers shared by the *_tools.go files.

func ptr[T any](v T) *T { return &v }

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// notFoundAs turns ErrNotFound into a message the model can act on.
func notFoundAs(err error, what, id string) error {
	if errors.Is(err, opnsense.ErrNotFound) {
		return fmt.Errorf("no %s with uuid %s", what, id)
	}
	return err
}

// set copies *v into *dst when v is non-nil (a field the caller supplied in a patch).
func set[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

func setAs[S, D any](dst *D, v *S, conv func(S) D) {
	if v != nil {
		*dst = conv(*v)
	}
}

// withEnum infers the input schema for T and restricts one string property to values.
func withEnum[T any](prop string, values []string) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	p, ok := s.Properties[prop]
	if !ok {
		panic(fmt.Sprintf("withEnum: %T has no property %q", *new(T), prop))
	}
	for _, v := range values {
		p.Enum = append(p.Enum, v)
	}
	return s
}

// NameRef identifies an object by UUID or name.
type NameRef struct {
	UUID string `json:"uuid,omitempty" jsonschema:"UUID; give this or name"`
	Name string `json:"name,omitempty" jsonschema:"name; give this or uuid"`
}

func resolveNamed[T any, S opnsense.NamedRow](ctx context.Context, ic *opnsense.ItemController[T, S], ref NameRef, what string) (string, error) {
	switch {
	case ref.UUID != "":
		return ref.UUID, nil
	case ref.Name != "":
		id, err := opnsense.ResolveByName(ctx, ic, ref.Name)
		if errors.Is(err, opnsense.ErrNotFound) {
			return "", fmt.Errorf("no %s named %q", what, ref.Name)
		}
		return id, err
	default:
		return "", fmt.Errorf("%s: give either uuid or name", what)
	}
}

type listIn struct {
	Search string `json:"search,omitempty" jsonschema:"substring to filter by; empty lists all"`
}

type listOut[S any] struct {
	Items []S `json:"items"`
	Total int `json:"total"`
}

// listTool is a generic list tool.
func listTool[T any, S any](toolset, name, title, desc string, ic *opnsense.ItemController[T, S]) tool {
	return tool{toolset: toolset, readOnly: true, register: func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{Name: name, Description: desc,
			Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, listOut[S], error) {
			res, err := ic.Search(ctx, in.Search)
			if err != nil {
				return nil, listOut[S]{}, err
			}
			return nil, listOut[S]{Items: nonNil(res.Rows), Total: res.Total}, nil
		})
	}}
}
