package opnsense

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ErrNotFound is returned when an item does not exist.
var ErrNotFound = errors.New("opnsense: not found")

// ErrForbidden matches a 403: the API user lacks the privilege for the page.
var ErrForbidden = errors.New("opnsense: forbidden")

// APIError is a non-2xx HTTP response.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("opnsense: %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	switch e.StatusCode {
	case http.StatusUnauthorized:
		msg += " (check API key and secret)"
	case http.StatusForbidden:
		msg += " (the API user lacks the privilege for this page)"
	}
	if m := userMessage(e.Body); m != "" {
		msg += ": " + m
	} else if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// Is lets errors.Is(err, ErrNotFound) match a 404 and errors.Is(err, ErrForbidden) a 403.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound ||
		target == ErrForbidden && e.StatusCode == http.StatusForbidden
}

// ValidationError is OPNsense rejecting a write: HTTP 200 with result "failed".
type ValidationError struct {
	// Fields maps a model path (e.g. "alias.name") to the message OPNsense returned.
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return "opnsense: request failed validation"
	}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", k, e.Fields[k]))
	}
	return "opnsense: validation failed: " + strings.Join(parts, "; ")
}

// userMessage extracts errorMessage from a UserException response body, if present.
func userMessage(body string) string {
	var v struct {
		ErrorMessage string `json:"errorMessage"`
	}
	if json.Unmarshal([]byte(body), &v) == nil {
		return v.ErrorMessage
	}
	return ""
}
