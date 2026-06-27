package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveWorkDirPosture proves the posture-aware work-dir resolver
// (deliverable v2 CRITICAL): root (euid 0) keeps the root-owned DefaultWorkDir,
// while the unprivileged _k3sm control plane (euid != 0) gets a path UNDER its
// home — never the root const, which would EACCES.
func TestResolveWorkDirPosture(t *testing.T) {
	cases := []struct {
		name    string
		euid    int
		home    string
		want    string
		wantErr error
	}{
		{name: "root keeps the root const", euid: 0, home: "/var/root", want: DefaultWorkDir},
		{name: "root ignores home", euid: 0, home: "", want: DefaultWorkDir},
		{name: "unprivileged uses home/server", euid: 1000, home: "/var/lib/k3sm", want: "/var/lib/k3sm/server"},
		{name: "unprivileged dev home", euid: 501, home: "/Users/dev", want: "/Users/dev/server"},
		{name: "unprivileged without home errors", euid: 1000, home: "", wantErr: ErrNoServiceUserHome},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveWorkDir(tc.euid, tc.home)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("resolveWorkDir err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveWorkDir: unexpected err %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveWorkDir(%d, %q) = %q, want %q", tc.euid, tc.home, got, tc.want)
			}
			// The unprivileged posture must resolve UNDER the service-user home (a
			// _k3sm-owned, writable location) rather than hardcoding the root const —
			// proven directly for a dev home whose path differs from /var/lib/k3sm.
			if tc.euid != 0 && !strings.HasPrefix(got, tc.home+string(filepath.Separator)) {
				t.Errorf("unprivileged work-dir %q must live under the service-user home %q", got, tc.home)
			}
		})
	}
}

// TestRuntimeRoot confirms the runtimed root is the work-dir's parent, so the
// SBPL Posture.WorkDir resides under the daemon home (containment check active).
func TestRuntimeRoot(t *testing.T) {
	cases := map[string]string{
		"/var/lib/k3sm/server":  "/var/lib/k3sm",
		"/Users/dev/server":     "/Users/dev",
		"/var/lib/k3sm/server/": "/var/lib/k3sm",
	}
	for in, want := range cases {
		if got := RuntimeRoot(in); got != want {
			t.Errorf("RuntimeRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEnsureWorkDirWritable proves the fail-fast writability check: a writable
// dir is created+probed OK; a path whose parent is a regular file (not a dir)
// fails fast rather than silently proceeding.
func TestEnsureWorkDirWritable(t *testing.T) {
	t.Run("writable temp dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "server")
		if err := EnsureWorkDirWritable(dir); err != nil {
			t.Fatalf("EnsureWorkDirWritable(%q): %v", dir, err)
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("work-dir not created: stat err=%v", err)
		}
	})
	t.Run("unwritable (parent is a file) errors", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "afile")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A child of a regular file cannot be a directory → MkdirAll errors.
		if err := EnsureWorkDirWritable(filepath.Join(file, "server")); err == nil {
			t.Error("EnsureWorkDirWritable must fail fast when the path is not creatable")
		}
	})
}

// TestWithDefaultsAnonymousAuthOff proves the user-space hardening: withDefaults
// closes the anonymous surface (AnonymousAuth → false) so the rendered apiserver
// argv carries --anonymous-auth=false, while an explicit setting is preserved.
func TestWithDefaultsAnonymousAuthOff(t *testing.T) {
	c := Config{}.withDefaults()
	if c.AnonymousAuth == nil || *c.AnonymousAuth {
		t.Fatalf("withDefaults must set AnonymousAuth=false, got %v", c.AnonymousAuth)
	}
	if !hasArg(apiServerArgs(c), "--anonymous-auth=false") {
		t.Errorf("rendered apiserver argv must carry --anonymous-auth=false, args=%v", apiServerArgs(c))
	}

	on := true
	c2 := Config{AnonymousAuth: &on}.withDefaults()
	if c2.AnonymousAuth == nil || !*c2.AnonymousAuth {
		t.Errorf("withDefaults must preserve an explicit AnonymousAuth=true, got %v", c2.AnonymousAuth)
	}
}
