//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// helperBins maps a conformance helper name (hello-http, conftool) to the
// absolute path TestMain built it at. It is the set of native "images" the
// conformance pods exec; empty until TestMain builds them (only when a cluster is
// targeted — see TestMain).
var helperBins = map[string]string{}

// conformanceHelpers are the helper binaries built from e2e/testdata/cmd. They are
// stdlib-only native Mach-O binaries (the workload's "image" in k3sm's native
// model), built once and ad-hoc-signed so they exec under the default-deny
// Seatbelt profile.
var conformanceHelpers = []string{"hello-http", "conftool"}

// helperBin returns the absolute path of a built conformance helper, skipping the
// test when TestMain did not build it (no $KUBECONFIG → the compile-smoke, where
// every test already skips in Up). It never returns an empty path to a pod spec.
func helperBin(t *testing.T, name string) string {
	t.Helper()
	p := helperBins[name]
	if p == "" {
		t.Skipf("conformance helper %q not built (no $KUBECONFIG — compile-smoke run)", name)
	}
	return p
}

// TestMain builds + ad-hoc-signs the conformance helper binaries ONCE before the
// suite, but ONLY when a cluster is targeted ($KUBECONFIG set). The no-$KUBECONFIG
// compile-smoke (workspace hack/ci.sh --e2e) skips every test in Up, so building —
// and codesign, which is macOS-only — would be wasted work and a portability
// hazard. Determinism: CGO_ENABLED=0, a fixed output dir (helperBinDir), one
// ad-hoc signature per binary.
func TestMain(m *testing.M) {
	if os.Getenv("KUBECONFIG") != "" {
		if err := buildHelperBins(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: build conformance helpers: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// helperBinDir is where the conformance helpers are built. It honors
// $K3SM_CONFORMANCE_BIN so the integration gate can place them on a path the
// Seatbelt profile admits for exec; otherwise a stable per-host temp dir.
func helperBinDir() string {
	if d := os.Getenv("K3SM_CONFORMANCE_BIN"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "k3sm-conformance-bin")
}

// buildHelperBins builds each helper under testdata/cmd to helperBinDir, ad-hoc
// signs it (best-effort: codesign is macOS-only and only matters on the
// integration host), and records the path in helperBins. A build failure is fatal
// (the suite cannot run without its workloads).
func buildHelperBins() error {
	dir := helperBinDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir helper bin dir %s: %w", dir, err)
	}
	for _, name := range conformanceHelpers {
		out := filepath.Join(dir, name)
		build := exec.Command("go", "build", "-o", out, "./testdata/cmd/"+name)
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := build.CombinedOutput(); err != nil {
			return fmt.Errorf("build helper %s: %w\n%s", name, err, b)
		}
		// Ad-hoc sign so the binary execs under the default-deny Seatbelt profile.
		// Best-effort: a non-macOS host has no codesign and skips every Seatbelt
		// test anyway; on the integration Mac a real failure surfaces as the pod
		// failing to exec (caught by the per-criterion gate).
		if out, err := exec.Command("codesign", "-s", "-", "-f", out).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: codesign %s (non-fatal): %v\n%s\n", name, err, out)
		}
		helperBins[name] = out
	}
	return nil
}
