package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// cpBinaries are the prebuilt control-plane binaries downloaded from kwok-ci/k8s.
var cpBinaries = []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "kubectl"}

// binDir is the per-workdir directory holding the control-plane binaries.
func binDir(workDir string) string { return filepath.Join(workDir, "bin") }

// dbDir is the kine SQLite directory (WAL state.db lives here).
func dbDir(workDir string) string { return filepath.Join(workDir, "db") }

// certDir is where the apiserver writes its self-signed serving certs.
func certDir(workDir string) string { return filepath.Join(workDir, "apiserver-certs") }

// kubeconfigPath is the admin kubeconfig the executor writes.
func kubeconfigPath(workDir string) string { return filepath.Join(workDir, "k3sm.kubeconfig") }

// tokenFilePath is the static token-auth CSV.
func tokenFilePath(workDir string) string { return filepath.Join(workDir, "tokens.csv") }

// saKeyPath / saPubPath are the service-account signing keypair.
func saKeyPath(workDir string) string { return filepath.Join(workDir, "sa.key") }
func saPubPath(workDir string) string { return filepath.Join(workDir, "sa.pub") }

// KubeconfigPath returns the admin kubeconfig path the executor writes for a
// given work dir. Exported so the `k3sm kubectl`/`kubeconfig` subcommands resolve
// the same path the server emits, single-sourcing the layout.
func KubeconfigPath(workDir string) string { return kubeconfigPath(workDir) }

// KubectlPath returns the bundled kubectl binary path for a given work dir
// (downloaded alongside the control-plane binaries by ensureControlPlaneBinaries).
func KubectlPath(workDir string) string { return filepath.Join(binDir(workDir), "kubectl") }

// apiServerURL is the loopback HTTPS URL clients use to reach the apiserver.
func apiServerURL(port int) string {
	return "https://127.0.0.1:" + strconv.Itoa(port)
}

// ensureWorkDirs creates the workdir subtree (bin, db, certs).
func ensureWorkDirs(workDir string) error {
	for _, d := range []string{binDir(workDir), dbDir(workDir), certDir(workDir)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

// ensureControlPlaneBinaries downloads the prebuilt darwin/arm64 control-plane
// binaries from kwok-ci/k8s (upstream does not ship them — k/k#118359) and
// ad-hoc signs each so arm64 Mach-O can exec. It is a no-op if they already
// exist. Mirrors clusterup.sh step 1.
func ensureControlPlaneBinaries(ctx context.Context, workDir, kubeVersion string) error {
	bd := binDir(workDir)
	if _, err := os.Stat(filepath.Join(bd, "kube-apiserver")); err == nil {
		return signBinaries(ctx, bd, cpBinaries) // already downloaded; ensure signed
	}
	tag := kubeVersion + "-kwok.0-darwin-arm64"
	cmd := exec.CommandContext(ctx, "gh", "release", "download", tag,
		"--repo", "kwok-ci/k8s", "--dir", bd, "--clobber")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("download control-plane binaries %s: %w: %s", tag, err, out)
	}
	if err := chmodExec(bd); err != nil {
		return err
	}
	return signBinaries(ctx, bd, cpBinaries)
}

// ensureKine builds kine from source with cgo (mattn/go-sqlite3 — the no-cgo
// build disables SQLite, a validated M0 finding) into the workdir bin and ad-hoc
// signs it. No-op if already present. Mirrors clusterup.sh step 2.
func ensureKine(ctx context.Context, workDir, kineVersion string) error {
	bd := binDir(workDir)
	kine := filepath.Join(bd, "kine")
	if _, err := os.Stat(kine); err == nil {
		return signBinaries(ctx, bd, []string{"kine"})
	}
	cmd := exec.CommandContext(ctx, "go", "install", "github.com/k3s-io/kine@"+kineVersion)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOWORK=off", "GOBIN="+bd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build kine %s (CGO_ENABLED=1): %w: %s", kineVersion, err, out)
	}
	return signBinaries(ctx, bd, []string{"kine"})
}

// chmodExec makes every file in dir executable.
func chmodExec(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read bin dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Chmod(filepath.Join(dir, e.Name()), 0o755); err != nil {
			return fmt.Errorf("chmod %s: %w", e.Name(), err)
		}
	}
	return nil
}

// signBinaries ad-hoc signs (codesign -s - -f) each named binary so an arm64
// Mach-O can exec on macOS — the same codesign-on-pull discipline k3sm uses for
// pulled images. Signing failures are tolerated (best-effort: an already-valid
// signature or a non-macOS CI host should not block bring-up); the binary fails
// loudly at exec if it truly cannot run.
func signBinaries(ctx context.Context, dir string, names []string) error {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = exec.CommandContext(ctx, "codesign", "-s", "-", "-f", p).Run()
	}
	return nil
}

// writeServiceAccountKeys generates the SA RSA keypair (used by apiserver to
// sign and verify tokens) if absent. Mirrors clusterup.sh step 3.
func writeServiceAccountKeys(ctx context.Context, workDir string) error {
	if _, err := os.Stat(saKeyPath(workDir)); err == nil {
		return nil
	}
	gen := exec.CommandContext(ctx, "openssl", "genrsa", "-out", saKeyPath(workDir), "2048")
	if out, err := gen.CombinedOutput(); err != nil {
		return fmt.Errorf("openssl genrsa: %w: %s", err, out)
	}
	pub := exec.CommandContext(ctx, "openssl", "rsa", "-in", saKeyPath(workDir), "-pubout", "-out", saPubPath(workDir))
	if out, err := pub.CombinedOutput(); err != nil {
		return fmt.Errorf("openssl rsa pubout: %w: %s", err, out)
	}
	return nil
}

// writeTokenFile writes the static bearer token CSV (token,user,uid,groups) the
// apiserver loads via --token-auth-file, granting system:masters for the M1
// AlwaysAllow posture.
func writeTokenFile(workDir, token string) error {
	line := fmt.Sprintf("%s,admin,admin-uid,\"system:masters\"\n", token)
	if err := os.WriteFile(tokenFilePath(workDir), []byte(line), 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}

// writeKubeconfig writes an admin kubeconfig pointing at the apiserver with the
// static token and TLS verification skipped (the apiserver self-signs its
// serving cert in M1).
func writeKubeconfig(workDir string, port int, token string) error {
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %q
    insecure-skip-tls-verify: true
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: admin
current-context: k3sm
users:
- name: admin
  user:
    token: %s
`, apiServerURL(port), token)
	if err := os.WriteFile(kubeconfigPath(workDir), []byte(content), 0o600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	return nil
}

// generateToken returns a random hex bearer token.
func generateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return "k3sm-" + hex.EncodeToString(b), nil
}
