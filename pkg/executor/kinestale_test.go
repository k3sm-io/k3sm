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

package executor

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKineVariantUpgradeOnAPackagedNode drives the boot's two kine steps (seedBinDir,
// then ensureKine) on a packaged node, which has no Go toolchain, after a release
// that changes kineBuildVariant. With the new payload staged by `sudo k3sm install`
// the work dir is re-seeded from it and nothing is built. With only the binary
// swapped, the old payload cannot supply the new build, and the boot fails with
// ErrKinePayloadStale (wrapping ErrNoGoToolchain, so the breaker parks on it at
// once) naming the install as the fix, and leaves the staged kine untouched.
func TestKineVariantUpgradeOnAPackagedNode(t *testing.T) {
	const oldVariant = "nocgo" // the unpatched build every node staged before kinePatches
	if kineBuildVariant == oldVariant {
		t.Fatal("kineBuildVariant still names the unpatched build")
	}
	stage := func(t *testing.T, dir, body, marker string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, kineBinaryName), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, KineMarkerName), []byte(marker), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := DefaultKineVersion + " " + oldVariant + "\n"
	for _, tc := range []struct {
		name          string
		payloadMarker string
		wantStale     bool
	}{
		{name: "the install staged the new payload: re-seeded, nothing built", payloadMarker: kineMarkerContent(DefaultKineVersion)},
		{name: "only the binary was swapped: refused, naming the install", payloadMarker: old, wantStale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", t.TempDir()) // a packaged node: no `go`
			work, payload := t.TempDir(), t.TempDir()
			bd := binDir(work)
			stage(t, bd, "unpatched-kine", old)
			stage(t, payload, "payload-kine", tc.payloadMarker)

			if err := seedBinDir(slog.New(slog.DiscardHandler), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
				t.Fatalf("seedBinDir: %v", err)
			}
			err := ensureKine(t.Context(), work, payload, DefaultKineVersion)
			body, _ := os.ReadFile(kinePath(bd))
			if !tc.wantStale {
				if err != nil {
					t.Fatalf("ensureKine = %v, want nil", err)
				}
				if string(body) != "payload-kine" || !kineStaged(bd, DefaultKineVersion) {
					t.Errorf("work dir kine = %q staged=%v, want the payload's, marked current", body, kineStaged(bd, DefaultKineVersion))
				}
				return
			}
			if !errors.Is(err, ErrKinePayloadStale) || !errors.Is(err, ErrNoGoToolchain) {
				t.Fatalf("ensureKine = %v, want ErrKinePayloadStale wrapping ErrNoGoToolchain", err)
			}
			for _, want := range []string{"sudo k3sm install", DefaultKineVersion + " " + kineBuildVariant, DefaultKineVersion + " " + oldVariant} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
			if string(body) != "unpatched-kine" {
				t.Errorf("the staged kine was touched: %q", body)
			}
			if m, _ := os.ReadFile(kineMarkerPath(bd)); string(m) != old {
				t.Errorf("the staged marker was touched: %q", m)
			}
		})
	}
}
