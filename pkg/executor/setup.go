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
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// componentCertValidity is the lifetime of a per-component client cert (the scheduler /
// controller-manager identities). One year matches the admin client cert; the certs are
// re-minted on every server boot (provisionComponentCerts), so the control plane never
// runs near expiry.
const componentCertValidity = 365 * 24 * time.Hour

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

// schedulerKubeconfigPath / controllerManagerKubeconfigPath are the per-component
// client-cert kubeconfigs the scheduler and controller-manager authenticate with (their
// OWN system: identities, not the shared system:masters admin kubeconfig).
func schedulerKubeconfigPath(workDir string) string {
	return filepath.Join(workDir, "kube-scheduler.kubeconfig")
}
func controllerManagerKubeconfigPath(workDir string) string {
	return filepath.Join(workDir, "kube-controller-manager.kubeconfig")
}

// tokenFilePath is the static token-auth CSV.
func tokenFilePath(workDir string) string { return filepath.Join(workDir, "tokens.csv") }

// saKeyPath / saPubPath are the service-account signing keypair.
func saKeyPath(workDir string) string { return filepath.Join(workDir, "sa.key") }
func saPubPath(workDir string) string { return filepath.Join(workDir, "sa.pub") }

// KubeconfigPath returns the admin kubeconfig path the executor writes for a
// given work dir. Exported so the `k3sm kubectl`/`kubeconfig` subcommands resolve
// the same path the server emits, single-sourcing the layout.
func KubeconfigPath(workDir string) string { return kubeconfigPath(workDir) }

// StateDBPath returns the kine SQLite state.db path for a given work dir
// (<workDir>/db/state.db). Exported so preflight tooling (`k3sm doctor`) probes
// the SAME file the datastore writes — single-sourcing the layout so a duplicated
// path join in package main can never silently probe the wrong file.
func StateDBPath(workDir string) string { return filepath.Join(dbDir(workDir), "state.db") }

// KubectlPath returns the bundled kubectl binary path for a given work dir
// (downloaded alongside the control-plane binaries by ensureControlPlaneBinaries).
func KubectlPath(workDir string) string { return filepath.Join(binDir(workDir), "kubectl") }

// AuditLogPath returns the apiserver audit-log path for a given work dir
// (<workDir>/audit/audit.log — the 0700 dir writeConformanceConfig creates).
// Exported so argv, the tests, and the M10 audit e2e all probe the SAME file
// the apiserver writes — single-sourcing the layout (mirrors StateDBPath).
func AuditLogPath(workDir string) string { return filepath.Join(auditDir(workDir), "audit.log") }

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
	return ensureControlPlaneBinariesInto(ctx, binDir(workDir), kubeVersion)
}

// ensureControlPlaneBinariesInto is ensureControlPlaneBinaries against an
// explicit bin dir — shared by the boot path (the workdir bin) and StagePayload
// (an install payload dir).
func ensureControlPlaneBinariesInto(ctx context.Context, bd, kubeVersion string) error {
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
	return ensureKineInto(ctx, binDir(workDir), kineVersion)
}

// ensureKineInto is ensureKine against an explicit bin dir — shared by the boot
// path and StagePayload.
func ensureKineInto(ctx context.Context, bd, kineVersion string) error {
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

// PayloadBinaries is the full control-plane payload set a packaged install must
// stage beside the daemon (the boot path otherwise acquires them with gh/go —
// dev-shell tools a launchd daemon does not have): the kwok-ci/k8s prebuilt
// binaries plus kine. The single source for `k3sm payload`, `k3sm install`, and
// the boot-time seed, so the three can never disagree on the set.
func PayloadBinaries() []string { return append(append([]string{}, cpBinaries...), "kine") }

// StagePayload acquires the full control-plane payload into destDir using the
// executor's own pinned versions (DefaultKubeVersion via `gh release download`,
// DefaultKineVersion via `go install`). It is the packaging-side producer: run
// it where the dev tools exist (a human shell, goreleaser), then hand destDir to
// `k3sm install`, which stages it beside the daemon; the daemon boot seeds its
// workdir from the staged copy and never needs gh/go (a launchd _k3sm daemon
// has neither — the live M2-gate failure this closes).
func StagePayload(ctx context.Context, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("create payload dir %s: %w", destDir, err)
	}
	if err := ensureControlPlaneBinariesInto(ctx, destDir, DefaultKubeVersion); err != nil {
		return err
	}
	return ensureKineInto(ctx, destDir, DefaultKineVersion)
}

// seedBinDir copies every payload binary present in payloadDir and absent from
// the workdir bin into it (0755), so the subsequent ensure* steps find them
// present and only re-sign — never shelling out to gh/go. A missing payloadDir
// or missing individual binary is NOT an error here: the ensure* fallbacks
// still run and fail with their own actionable errors (dev shells keep working
// with no payload at all).
func seedBinDir(workDir, payloadDir string) error {
	if payloadDir == "" {
		return nil
	}
	bd := binDir(workDir)
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return fmt.Errorf("create bin dir %s: %w", bd, err)
	}
	for _, name := range PayloadBinaries() {
		dst := filepath.Join(bd, name)
		if _, err := os.Stat(dst); err == nil {
			continue // already present (a prior boot seeded/acquired it)
		}
		src := filepath.Join(payloadDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			if os.IsNotExist(err) {
				continue // not staged; the ensure* fallback owns the error
			}
			return fmt.Errorf("read payload %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			return fmt.Errorf("seed %s from payload: %w", dst, err)
		}
	}
	return nil
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

// writeComponentKubeconfig mints a client cert (CommonName cn, no Organization)
// from the SIGNING CA — which the apiserver's unconditional --client-ca-file trusts —
// and writes a 0600 client-cert kubeconfig at path pointing at the loopback apiserver.
// The component (kube-scheduler / kube-controller-manager) then authenticates as cn, so
// the apiserver's auto-created bootstrap RBAC (the system:kube-scheduler /
// system:kube-controller-manager ClusterRoleBindings) constrains it — the k3s
// per-component-identity model, replacing the shared system:masters admin token.
//
// verifyClusterCA selects the server-trust posture: when the apiserver presents a
// cluster-CA-signed serving cert (the mesh path) the kubeconfig pins
// certificate-authority-data to the cluster CA; single-node the apiserver self-signs, so
// the co-located loopback component skips verification (insecure-skip-tls-verify, the
// same posture the single-node admin kubeconfig uses) while still presenting its
// client-cert identity.
func writeComponentKubeconfig(path string, port int, cn string, h *certs.Hierarchy, verifyClusterCA bool) error {
	certPEM, keyPEM, err := h.Signing.IssueClient(cn, nil, componentCertValidity)
	if err != nil {
		return fmt.Errorf("issue %s client cert: %w", cn, err)
	}
	b64 := base64.StdEncoding.EncodeToString
	clusterTLS := "    insecure-skip-tls-verify: true"
	if verifyClusterCA {
		clusterTLS = "    certificate-authority-data: " + b64(h.Cluster.CertPEM)
	}
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %q
%s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: %s
current-context: k3sm
users:
- name: %s
  user:
    client-certificate-data: %s
    client-key-data: %s
`, apiServerURL(port), clusterTLS, cn, cn, b64(certPEM), b64(keyPEM))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s kubeconfig: %w", cn, err)
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
