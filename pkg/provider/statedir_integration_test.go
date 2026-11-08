//go:build integration && darwin

/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TestCustomWorkDirLeafIsDenied is the kernel's verdict on a work dir whose leaf
// is neither server nor agent: <data root>/cp holds a planted server-ca.key, the
// provider builds the runtime config through dataRootOf and runtimedConfigOf, and
// a pod confined by the posture runtimed builds from that config cannot read it
// through an ancestor grant, under a custom pod root and under the default one.
func TestCustomWorkDirLeafIsDenied(t *testing.T) {
	for name, podRoot := range map[string]func(base, data string) string{
		"custom pod root":  func(base, _ string) string { return filepath.Join(base, "pods-root") },
		"default pod root": func(_, data string) string { return data },
	} {
		t.Run(name, func(t *testing.T) {
			assertWorkDirSecretDenied(t, func(t *testing.T, base, data string) (string, string, string) {
				t.Helper()
				workDir := filepath.Join(data, "cp")
				if err := os.MkdirAll(workDir, 0o700); err != nil {
					t.Fatal(err)
				}
				return podRoot(base, data), workDir, workDir
			})
		})
	}
}

// TestSymlinkedDefaultWorkDirLeafIsDenied is the same verdict for a default leaf
// behind a symlink: <data root>/server links to a directory holding server-ca.key,
// and the fixed server deny matches nothing the kernel resolves, so only the
// resolved target the provider passes as the state dir keeps the read out.
func TestSymlinkedDefaultWorkDirLeafIsDenied(t *testing.T) {
	assertWorkDirSecretDenied(t, func(t *testing.T, base, data string) (string, string, string) {
		t.Helper()
		target := filepath.Join(base, "elsewhere")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		workDir := filepath.Join(data, "server")
		if err := os.Symlink(target, workDir); err != nil {
			t.Fatal(err)
		}
		return data, workDir, target
	})
}

// assertWorkDirSecretDenied plants server-ca.key in the directory layout returns
// (the pod root, the configured work dir, and the directory the secret is written
// to), builds the posture from the provider's config, and asserts a sandboxed read
// of the secret fails while the controls show the grant reaches it otherwise.
func assertWorkDirSecretDenied(t *testing.T, layout func(t *testing.T, base, data string) (podRoot, workDir, secretDir string)) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	tmp, err := os.MkdirTemp("/tmp", "k3sm-wd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	base, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(base, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	podRoot, workDir, secretDir := layout(t, base, data)
	secret, sibling := filepath.Join(secretDir, "server-ca.key"), filepath.Join(data, "sibling")
	const original = "private-key\n"
	for _, f := range []string{secret, sibling} {
		if err := os.WriteFile(f, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := RuntimedConfig{Root: podRoot, DataRoot: data, StateDir: workDir}
	dataRoot, stateDir, err := dataRootOf(cfg)
	if err != nil {
		t.Fatalf("dataRootOf: %v", err)
	}
	rc := runtimedConfigOf(cfg, slog.New(slog.DiscardHandler), "", dataRoot, stateDir)
	// The fields runtimed's pod setup copies into the Posture.
	posture := sandbox.Posture{WorkDir: rc.Root, DataRoot: rc.DataRoot, StateDir: rc.StateDir}
	unfixed := posture
	unfixed.StateDir = ""

	read := func(posture sandbox.Posture, target string) ([]byte, string, error) {
		t.Helper()
		prof, err := sandbox.Generate(&runtimev1.SandboxProfile{
			DataVolumePath: filepath.Join(rc.Root, "pods", "p1", "rootfs"),
			ExtraReadPaths: []string{base},
		}, sandbox.GenerateOptions{Posture: posture})
		if err != nil {
			t.Fatalf("sandbox.Generate: %v", err)
		}
		sb := filepath.Join(t.TempDir(), "workdir.sb")
		if err := os.WriteFile(sb, []byte(prof), 0o600); err != nil {
			t.Fatal(err)
		}
		// Stdout alone: the shell's startup noise goes to stderr.
		out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/sh", "-c",
			`IFS= read -r line < "$1" && printf '%s' "$line"`, "sh", target).Output()
		return out, prof, err
	}

	// The controls: the ancestor grant reaches the sibling, and the secret
	// itself without the state dir, so a refusal below is that deny.
	if out, prof, err := read(posture, sibling); err != nil || string(out) != "private-key" {
		t.Fatalf("the ancestor grant did not read %s, so the deny is unproven: %v %q\n--- profile ---\n%s", sibling, err, out, prof)
	}
	if out, prof, err := read(unfixed, secret); err != nil || string(out) != "private-key" {
		t.Fatalf("without the state dir the secret was not readable, so this proves nothing: %v %q\n--- profile ---\n%s", err, out, prof)
	}

	viaWorkDir := filepath.Join(workDir, "server-ca.key")
	for _, target := range []string{secret, strings.TrimPrefix(secret, "/private"), viaWorkDir} {
		if out, prof, err := read(posture, target); err == nil || strings.Contains(string(out), "private-key") {
			t.Errorf("a sandboxed read of %s succeeded: %q\n--- profile ---\n%s", target, out, prof)
		}
	}
}
