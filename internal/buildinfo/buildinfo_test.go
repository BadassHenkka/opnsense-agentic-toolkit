package buildinfo

import "testing"

func TestVersion(t *testing.T) {
	for _, tc := range []struct{ name, set, module, want string }{
		{"ldflags win", "v1.2.0-3-gabc1234", "v1.1.0", "v1.2.0-3-gabc1234"},
		{"go install at a tag", "dev", "v1.1.0", "v1.1.0"},
		{"go install at a commit", "dev", "v0.0.0-20261026120000-6b5a0ac0e5f1", "v0.0.0-20261026120000-6b5a0ac0e5f1"},
		{"go run without VCS info", "dev", "(devel)", "dev"},
		{"no build info", "dev", "", "dev"},
	} {
		if got := version(tc.set, tc.module); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
