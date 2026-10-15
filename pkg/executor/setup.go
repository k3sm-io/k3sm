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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/internal/binsign"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/helmchart"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// ComponentCertValidity is the lifetime of a per-component client cert (the scheduler /
// controller-manager identities, and the server's in-process node identity minted in
// cmd/k3sm). One year matches the admin client cert; the certs are re-minted on every
// server boot (provisionComponentCerts), so the control plane never runs near expiry.
const ComponentCertValidity = 365 * 24 * time.Hour

// cpBinaries are the prebuilt control-plane binaries downloaded from kwok-ci/k8s.
var cpBinaries = []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "kubectl"}

// binDir is the per-workdir directory holding the control-plane binaries.
func binDir(workDir string) string { return filepath.Join(workDir, "bin") }

// dbDir is the kine SQLite directory (WAL state.db lives here).
func dbDir(workDir string) string { return filepath.Join(workDir, "db") }

// certDir is the legacy apiserver --cert-dir, where releases before the
// cluster-CA serving leaf let the apiserver self-sign. It is neither read nor
// written now; it is kept on disk one release as the rollback artifact.
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

// apiServerKubeletClientCertPath / apiServerKubeletClientKeyPath are the client
// keypair the apiserver PRESENTS to a node's kubelet endpoint
// (--kubelet-client-certificate / --kubelet-client-key). It is a signing-CA-issued
// CN=certs.APIServerKubeletClientCN client cert, re-issued on every boot beside the
// scheduler/KCM identities, and it is the ONLY identity a node's :10250 admits.
func apiServerKubeletClientCertPath(workDir string) string {
	return filepath.Join(workDir, "kube-apiserver-kubelet-client.crt")
}
func apiServerKubeletClientKeyPath(workDir string) string {
	return filepath.Join(workDir, "kube-apiserver-kubelet-client.key")
}

// APIServerKubeletClientCertPath / APIServerKubeletClientKeyPath name the keypair
// above from outside the package (the rotation report), so the layout is joined in
// exactly one place — mirroring SchedulerKubeconfigPath.
func APIServerKubeletClientCertPath(workDir string) string {
	return apiServerKubeletClientCertPath(workDir)
}
func APIServerKubeletClientKeyPath(workDir string) string {
	return apiServerKubeletClientKeyPath(workDir)
}

// The request headers the aggregator sets and every backend trusting the
// request-header CA reads the user from (k3s's and upstream's names).
const (
	requestHeaderUsernameHeader     = "X-Remote-User"
	requestHeaderGroupHeader        = "X-Remote-Group"
	requestHeaderExtraHeadersPrefix = "X-Remote-Extra-"
)

// ProxyClientCertPath / ProxyClientKeyPath are the aggregator's front-proxy client
// keypair (--proxy-client-cert-file / --proxy-client-key-file): CN
// certs.ProxyClientCN, issued by the request-header CA, re-minted every boot.
func ProxyClientCertPath(workDir string) string {
	return filepath.Join(workDir, "client-auth-proxy.crt")
}
func ProxyClientKeyPath(workDir string) string {
	return filepath.Join(workDir, "client-auth-proxy.key")
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

// BinDir returns the work dir's binary cache (<workDir>/bin) — where the
// control-plane payload, kubectl and the pinned host buildx live. Exported so a
// caller that stages another pinned binary there joins the layout HERE rather
// than repeating it, mirroring KubectlPath.
func BinDir(workDir string) string { return binDir(workDir) }

// AuditLogPath returns the apiserver audit-log path for a given work dir
// (<workDir>/audit/audit.log — the 0700 dir writeConformanceConfig creates).
// Exported so argv, the tests, and the audit e2e all probe the SAME file
// the apiserver writes — single-sourcing the layout (mirrors StateDBPath).
func AuditLogPath(workDir string) string { return filepath.Join(auditDir(workDir), "audit.log") }

// SchedulerKubeconfigPath / ControllerManagerKubeconfigPath return the per-component
// client-cert kubeconfigs provisionComponentCerts re-issues on EVERY boot. Exported so
// `k3sm certificate rotate` reports exactly the files the boot re-issues instead of
// re-joining the layout in package main (mirrors KubeconfigPath).
func SchedulerKubeconfigPath(workDir string) string { return schedulerKubeconfigPath(workDir) }
func ControllerManagerKubeconfigPath(workDir string) string {
	return controllerManagerKubeconfigPath(workDir)
}

// TokenFilePath returns the apiserver static token-auth CSV (<workDir>/tokens.csv).
// Exported so tooling that must NOT touch it (certificate rotation's scope fence) can
// name it from the one authority for the layout.
func TokenFilePath(workDir string) string { return tokenFilePath(workDir) }

// ServiceAccountKeyPath / ServiceAccountPubPath return the service-account signing
// keypair. Rotating them would invalidate every issued ServiceAccount token, so they
// are deliberately outside certificate rotation — exported so that fence names the
// same files the executor writes.
func ServiceAccountKeyPath(workDir string) string { return saKeyPath(workDir) }
func ServiceAccountPubPath(workDir string) string { return saPubPath(workDir) }

// APIServerCertDir returns the legacy apiserver --cert-dir (<workDir>/apiserver-certs),
// where releases before the cluster-CA serving leaf let a single-node apiserver
// self-sign. Nothing reads or writes it now: the apiserver serves
// certs.APIServerServingCertPath on every topology and --root-ca-file is the cluster
// CA. It is kept one release, untouched, as the rollback artifact (the previous
// release's install pins its apiserver.crt), so rotation lists it out of scope and
// the server start logs it as legacy. Exported so both can name it.
func APIServerCertDir(workDir string) string { return certDir(workDir) }

// loopbackAPIServerHost is the apiserver bind of last resort — the single-node
// default, reached only when a Config names neither a bind address nor a node IP.
//
// It is deliberately NOT loopbackBindAddress (supervised.go), which carries the
// opposite contract: that one is an INVARIANT the scheduler and controller-manager
// may never leave, while this one is a fallback the mesh path routinely overrides.
// Sharing a symbol would make a future change to either silently move the other.
const loopbackAPIServerHost = "127.0.0.1"

// apiServerHost is the address the apiserver ACTUALLY BINDS, and therefore the host
// every in-process client and the healthz probe must dial: the explicit BindAddress,
// else NodeIP, else loopback.
//
// This is the ONE derivation of that chain — apiServerArgs renders --bind-address
// from it too. That single-sourcing is the whole point of the helper. A second,
// independent derivation is exactly the defect this closes (lab D1): the probe and
// the kubeconfigs hardcoded loopback while a --mesh-ip server bound its wireguard IP
// only, so bring-up wedged at the healthz wait and every in-process client pointed at
// an address nothing was listening on. Single-node boots — where the chain lands on
// loopback anyway — masked it completely.
func apiServerHost(cfg Config) string {
	if cfg.BindAddress != "" {
		return cfg.BindAddress
	}
	if cfg.NodeIP != "" {
		return cfg.NodeIP
	}
	return loopbackAPIServerHost
}

// apiServerURL is the HTTPS URL clients use to reach the apiserver: the effective
// bind host and the secure port. JoinHostPort brackets an IPv6 host; the single-node
// loopback case renders exactly the string it always did.
func apiServerURL(cfg Config) string {
	return "https://" + net.JoinHostPort(apiServerHost(cfg), strconv.Itoa(cfg.APIServerPort))
}

// ensureWorkDirs creates the workdir subtree (bin, db).
func ensureWorkDirs(workDir string) error {
	for _, d := range []string{binDir(workDir), dbDir(workDir)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

// ensureControlPlaneBinaries downloads the prebuilt darwin/arm64 control-plane
// binaries from kwok-ci/k8s (upstream does not ship them — k/k#118359) and
// ad-hoc signs each so arm64 Mach-O can exec. On a present set it checks the
// KubeMarkerName marker instead of downloading (see ensureControlPlaneBinariesVerified).
// Mirrors clusterup.sh step 1.
func ensureControlPlaneBinaries(ctx context.Context, logger *slog.Logger, workDir, kubeVersion string) error {
	return ensureControlPlaneBinariesVerified(ctx, logger, binDir(workDir), kubeVersion, false)
}

// ensureControlPlaneBinariesVerified is the acquisition path. Every download is
// verified against the pinned digests whenever kubeVersion has a pin (see
// verifyControlPlaneDownload). requirePin is true for the packaging producer
// (StagePayload), whose output is about to be archived and published, so an
// unpinned version is refused there; it is false for the boot path, where a dev may
// legitimately run an unpinned kubeVersion and gets a Warn instead.
//
// The boot path downloads into a scratch dir beside the set (restageFromRelease), so
// a refused download never leaves bytes in the working set that a later boot would
// sign and run. The packaging path downloads straight into its clean destination, so
// VerifyPayloadSet still sees every asset the release carried.
//
// A PRESENT set is never re-acquired on the packaging path and never fails the boot
// path: the boot checks the set's version marker (one small file read, never a hash
// of the binaries — signing has already rewritten the bytes) and reports what it
// found. A stale set is still a self-consistent control plane, and serving on it
// beats refusing to serve; see reportStagedControlPlane for the three outcomes.
func ensureControlPlaneBinariesVerified(ctx context.Context, logger *slog.Logger, bd, kubeVersion string, requirePin bool) error {
	// The release path (a Developer ID-signed k3sm, see signingPolicy) runs the set
	// the signed payload staged and nothing else: it is verified in place and used
	// byte-identical, and a missing or failing binary refuses the boot. It never
	// downloads, so the digest-pinned fallback below is dev-only.
	if !requirePin {
		p, err := resolveSigningPolicy(ctx, logger)
		if err != nil {
			return err
		}
		if p.release {
			if err := verifyPayloadBinaries(ctx, p, bd, healStamp(kubeMarkerPath(bd)), cpBinaries); err != nil {
				return err
			}
			reportStagedControlPlane(ctx, logger, bd, kubeVersion)
			return nil
		}
	}
	if _, err := os.Stat(filepath.Join(bd, "kube-apiserver")); err == nil {
		if requirePin {
			// Already-present bytes are already signed, and signing rewrites the
			// Mach-O, so their digests can no longer be compared against upstream.
			// A publishable payload must be built from a clean directory.
			return fmt.Errorf("%w: %s already contains control-plane binaries; stage into a clean directory so downloads can be digest-verified before signing",
				ErrPayloadDigestUnpinned, bd)
		}
		if err := signBinaries(ctx, bd, healStamp(kubeMarkerPath(bd)), cpBinaries); err != nil { // already acquired; ensure signed
			return err
		}
		reportStagedControlPlane(ctx, logger, bd, kubeVersion)
		return nil
	}
	if !requirePin {
		return restageFromRelease(ctx, logger, bd, kubeVersion)
	}
	if err := downloadControlPlane(ctx, logger, bd, kubeVersion, true); err != nil {
		return err
	}
	// LAST: the marker vouches for a downloaded, digest-verified and signed set.
	return writeKubeMarker(bd, kubeVersion)
}

// downloadControlPlane fetches the kubeVersion release into dir, makes it
// executable, verifies it (verifyControlPlaneDownload), and signs the set. It does
// not write the marker: each caller writes it once the set is where it belongs.
func downloadControlPlane(ctx context.Context, logger *slog.Logger, dir, kubeVersion string, requirePin bool) error {
	tag := kubeVersion + "-kwok.0-darwin-arm64"
	if out, err := runControlPlaneDownload(ctx, tag, dir); err != nil {
		return fmt.Errorf("download control-plane binaries %s: %w: %s", tag, err, out)
	}
	if err := chmodExec(dir); err != nil {
		return err
	}
	// BEFORE signing: codesign rewrites the binary, so this is the only moment the
	// downloaded bytes can be compared against the digests upstream published.
	if err := verifyControlPlaneDownload(logger, dir, kubeVersion, requirePin); err != nil {
		return err
	}
	resignFresh(ctx, dir, cpBinaries)
	return nil
}

// verifyControlPlaneDownload checks a freshly downloaded set against the pinned
// digests whenever kubeVersion has a pin, on every path: the kwok-ci/k8s tag is
// mutable, and these bytes become the cluster's apiserver whether a packaging run or
// a dev boot fetched them. Without a pin, requirePin refuses (the packaging path);
// otherwise the set is accepted with one Warn naming the version, since there is no
// reviewed digest to compare against and inventing one would be worse.
//
// It verifies the bytes in dir at the moment of the call only. On the boot path dir
// is writable by the invoking user, so the check binds the bytes against a different
// uid, not against a same-uid process (see restageFromRelease).
func verifyControlPlaneDownload(logger *slog.Logger, dir, kubeVersion string, requirePin bool) error {
	if _, pinned := PinnedPayloadDigests(kubeVersion); pinned || requirePin {
		return VerifyDownloadedDigests(dir, kubeVersion)
	}
	logger.Warn("control-plane binaries for an unpinned kube version were downloaded without digest verification",
		"unpinned", kubeVersion, "dir", dir)
	return nil
}

// runControlPlaneDownload runs the release download. It is a var so a test can stand
// in for `gh` without a network, the way runKineBuild stands in for the kine build.
var runControlPlaneDownload = ghReleaseDownload

// ghReleaseDownload runs `gh release download <tag>` from kwok-ci/k8s into dir and
// returns the combined output so a failure carries gh's own diagnostic.
func ghReleaseDownload(ctx context.Context, tag, dir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gh", "release", "download", tag,
		"--repo", "kwok-ci/k8s", "--dir", dir, "--clobber")
	return cmd.CombinedOutput()
}

// lookPathGh resolves the dev-shell download tool. Like lookPathGo it reads PATH at
// call time, so a test drives it with t.Setenv rather than a seam.
func lookPathGh() (string, error) { return exec.LookPath("gh") }

// reportStagedControlPlane reads the marker beside a present set and says what it
// means. It never fails and never parks the daemon: there is a working binary to
// run in every branch, which is the deliberate difference from kine's toolchain-less
// park (a kine that cannot be staged leaves nothing to run).
//
//   - marker vouches for kubeVersion: one Info line.
//   - no marker: a set staged before markers existed. It boots exactly as it always
//     did, with an Info line saying the version is unvouched; the next payload seed
//     stamps it, so the state converges without an alarm on every existing install.
//   - marker names another version: ERROR, with the remedy, and the boot continues
//     on the present set. When the staged set is OLDER and `gh` is on PATH (a dev
//     shell), the release is fetched as a fallback first; a daemon has no `gh`, so
//     there the fallback is skipped silently, with no retries and no breaker entry.
//     A NEWER staged set is never replaced: that would be the downgrade seedBinDir
//     refuses.
func reportStagedControlPlane(ctx context.Context, logger *slog.Logger, bd, kubeVersion string) {
	staged := readKubeMarker(bd)
	switch {
	case staged == kubeVersion:
		logger.Info("control-plane binaries verified "+kubeVersion, "dir", bd)
		return
	case staged == "":
		logger.Info("control-plane binaries present but their version is unvouched (no "+KubeMarkerName+" marker; staged before markers existed)",
			"pinned", kubeVersion, "dir", bd)
		return
	case KubeVersionOlder(kubeVersion, staged):
		logger.Error("control-plane binaries are NEWER than this build pins; continuing on them, because a control-plane downgrade over a datastore a newer apiserver wrote is refused",
			"staged", staged, "pinned", kubeVersion, "dir", bd, "remedy", NewerControlPlaneRemedy)
		return
	}
	attrs := []any{"staged", staged, "pinned", kubeVersion, "dir", bd, "remedy", StaleControlPlaneRemedy}
	if _, err := lookPathGh(); err == nil {
		dlErr := restageFromRelease(ctx, logger, bd, kubeVersion)
		if dlErr == nil {
			logger.Info("control-plane binaries re-staged from the release (dev-shell fallback)",
				"from", staged, "to", kubeVersion, "dir", bd)
			return
		}
		if errors.Is(dlErr, errTornControlPlaneSet) {
			logger.Error("control-plane re-stage failed part-way: the set in the work dir may be PARTIALLY replaced (a mix of the staged and the downloaded release) and carries no version marker; the boot continues on it",
				"staged", staged, "pinned", kubeVersion, "dir", bd, "error", dlErr.Error(), "remedy", StaleControlPlaneRemedy)
			return
		}
		attrs = append(attrs, "download-error", dlErr.Error())
	}
	logger.Error("control-plane binaries are STALE: the staged set is not the version this build pins; continuing on the stale set",
		attrs...)
}

// restageFromRelease is the boot path's download, used for an absent set and as the
// dev-shell fallback for a stale one: download into a scratch dir beside the set, so
// a failed, partial or digest-refused download never touches the working binaries,
// then move the four into place and write the marker last.
//
// The four renames are NOT shadow-staged (no swap of a whole directory), so a
// failure between them leaves a torn set; it is reported as errTornControlPlaneSet.
// That is acceptable only because this branch is dev-shell-only: it downloads with
// `gh`, which a launchd daemon never has — a packaged install stages and re-stages
// through seedBinDir from its payload instead.
//
// The renames move kube-apiserver last and the marker is written after all four, so
// a set torn part-way never looks present (presence is keyed on kube-apiserver).
//
// Same-uid assumption: the digest check binds the bytes only against a DIFFERENT
// uid. The scratch dir and the bin dir are writable by the invoking user, so a
// process running as that user can swap a binary between verify and rename. That is
// accepted because this path runs only for the dev shell or a user-owned work dir;
// a packaged install re-stages from its payload through seedBinDir.
func restageFromRelease(ctx context.Context, logger *slog.Logger, bd, kubeVersion string) error {
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return fmt.Errorf("create control-plane dir %s: %w", bd, err)
	}
	tmp, err := os.MkdirTemp(bd, ".kube-restage-")
	if err != nil {
		return fmt.Errorf("control-plane re-stage scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := downloadControlPlane(ctx, logger, tmp, kubeVersion, false); err != nil {
		return err
	}
	for _, name := range cpBinaries {
		if _, err := os.Stat(filepath.Join(tmp, name)); err != nil {
			return fmt.Errorf("release %s carries no %s: %w", kubeVersion, name, err)
		}
	}
	if err := clearKubeMarker(bd); err != nil {
		return err
	}
	// kube-apiserver LAST: presence of a set is keyed on it, so a torn set (some of
	// the four moved, then a failure) must never look present to the next boot.
	order := make([]string, 0, len(cpBinaries))
	for _, name := range cpBinaries {
		if name != "kube-apiserver" {
			order = append(order, name)
		}
	}
	order = append(order, "kube-apiserver")
	for _, name := range order {
		if err := os.Rename(filepath.Join(tmp, name), filepath.Join(bd, name)); err != nil {
			return fmt.Errorf("%w: install re-staged %s: %w", errTornControlPlaneSet, name, err)
		}
	}
	return writeKubeMarker(bd, kubeVersion)
}

// errTornControlPlaneSet marks a dev-shell re-stage that failed after it began
// replacing the set, so the work dir may hold a mix of two releases.
var errTornControlPlaneSet = errors.New("control-plane set may be partially replaced")

// StaleControlPlaneRemedy is the operator's fix for a staged control-plane set older
// than the binary's pin: a packaged install carries the pinned set in its payload,
// and re-installing re-stages it so the next boot seeds the whole set from it.
const StaleControlPlaneRemedy = "re-run `sudo k3sm install` so the staged payload carries this build's control-plane pin; the next boot re-seeds the whole set"

// NewerControlPlaneRemedy is the operator's fix for a staged control-plane set newer
// than the binary's pin: the k3sm binary is the older side, so it is the one to move.
const NewerControlPlaneRemedy = "install a k3sm release whose control-plane pin is at or above the staged set; a control-plane downgrade is refused"

// Control-plane marker. ONE marker covers the whole cpBinaries set, because the set
// is acquired, verified, and shipped as one release: a presence-only check cannot tell
// the set this build pins from the set an EARLIER release staged, so without it a
// binary-only upgrade that moves DefaultKubeVersion would keep serving the old
// apiserver with nothing anywhere saying so. The discipline is kine's (see
// KineMarkerName): one line, written atomically, and written LAST — only after every
// file in the set is in place and signed — so "the marker matches" implies "the set
// beside it is finished". The boot-time check is a read of this file, never a hash.
const (
	// KubeMarkerName is the basename of the version marker written beside a staged
	// control-plane set (in the workdir bin, in an install payload, and in the release
	// archive). Its content is the kube version and a newline.
	KubeMarkerName = "kube.version"
)

// kubeMarkerPath names the control-plane marker in a bin dir.
func kubeMarkerPath(bd string) string { return filepath.Join(bd, KubeMarkerName) }

// KubeMarkerPath returns the control-plane marker path for a given work dir
// (<workDir>/bin/kube.version). Exported so `k3sm status` reads the same file the
// seed writes (mirrors CrashLoopPath).
func KubeMarkerPath(workDir string) string { return kubeMarkerPath(binDir(workDir)) }

// kubeMarkerContent renders a marker: "<version>\n".
func kubeMarkerContent(version string) string { return version + "\n" }

// ParseKubeMarker returns the kube version a marker's content records. Anything but
// exactly one field is malformed and yields "", which no target ever matches — the
// same tolerant reading readKineMarker gives the kine marker.
func ParseKubeMarker(b []byte) string {
	f := strings.Fields(string(b))
	if len(f) != 1 {
		return ""
	}
	return f[0]
}

// readKubeMarker returns the version recorded beside a staged set; a missing,
// unreadable, or malformed marker yields "".
func readKubeMarker(bd string) string {
	v, _ := readKubeMarkerState(bd)
	return v
}

// kubeMarkerState tells the three things a marker read can find apart. The seed
// needs the distinction: a MISSING marker is a node staged before markers existed
// and is grandfathered (a vouching payload re-seeds it), while a PRESENT marker it
// cannot read as a version is not "older than everything" — it is an unknown the
// seed refuses to overwrite, because it cannot rule out a downgrade.
type kubeMarkerState int

const (
	kubeMarkerMissing   kubeMarkerState = iota // no marker file
	kubeMarkerMalformed                        // present, but unreadable or not a vMAJOR.MINOR.PATCH line
	kubeMarkerValid                            // present and names a version
)

// readKubeMarkerState reads the marker and classifies it. The version is returned
// only for kubeMarkerValid.
func readKubeMarkerState(bd string) (string, kubeMarkerState) {
	b, err := os.ReadFile(kubeMarkerPath(bd))
	if errors.Is(err, os.ErrNotExist) {
		return "", kubeMarkerMissing
	}
	if err != nil {
		return "", kubeMarkerMalformed
	}
	v := ParseKubeMarker(b)
	if _, ok := parseKinePin(v); !ok {
		return "", kubeMarkerMalformed
	}
	return v, kubeMarkerValid
}

// kubeSetStaged reports whether bd holds every control-plane binary AND a marker
// vouching for exactly version.
func kubeSetStaged(bd, version string) bool {
	if version == "" {
		return false
	}
	for _, name := range cpBinaries {
		if _, err := os.Stat(filepath.Join(bd, name)); err != nil {
			return false
		}
	}
	return readKubeMarker(bd) == version
}

// writeKubeMarker writes the marker atomically (temp + rename) so an interrupted
// stage can never leave a half-written marker vouching for the wrong bytes.
func writeKubeMarker(bd, version string) error {
	tmp := kubeMarkerPath(bd) + ".tmp"
	if err := os.WriteFile(tmp, []byte(kubeMarkerContent(version)), 0o644); err != nil {
		return fmt.Errorf("write control-plane version marker: %w", err)
	}
	if err := os.Rename(tmp, kubeMarkerPath(bd)); err != nil {
		return fmt.Errorf("install control-plane version marker: %w", err)
	}
	return nil
}

// clearKubeMarker drops the marker BEFORE a re-stage touches the set: until the new
// marker is written, the true answer to "what is staged?" is "nothing vouched for".
func clearKubeMarker(bd string) error {
	if err := os.Remove(kubeMarkerPath(bd)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear control-plane version marker: %w", err)
	}
	return nil
}

// KubeVersionOlder reports whether kube version a is strictly older than b. The
// vMAJOR.MINOR.PATCH comparison is kine's pin comparison (the shapes are the same);
// either side unparseable is false, so nothing is called a downgrade unless both
// versions prove it. Exported so `k3sm status` draws the staged-vs-pinned direction
// with the same comparison the seed's downgrade refusal uses.
func KubeVersionOlder(a, b string) bool { return kinePinOlder(a, b) }

// kine staging constants. The binary is accompanied by a VERSION MARKER, because a
// presence-only check ("is there a file called kine?") cannot tell a correctly staged
// binary from one an EARLIER release built: every node that has booted once already has
// a kine binary, so a pin change would reach fresh installs only and silently never
// reach the installed base — the exact failure mode the v1.14.2 -> v0.17.0 collapse
// would otherwise have had.
const (
	// kineBinaryName is the staged kine binary's basename (in the workdir bin, in an
	// install payload, and in the release archive).
	kineBinaryName = "kine"
	// KineMarkerName is the basename of the version marker written beside a staged
	// kine binary. Exported so the packaging/install paths name the one file the
	// staging contract depends on rather than re-typing the string.
	KineMarkerName = "kine.version"
	// kineBuildVariant records HOW the pinned kine child was built. "nocgo" is
	// CGO_ENABLED=0 against kine's pure-Go modernc.org/sqlite backend
	// (pkg/drivers/sqlite/sqlite_nocgo.go, //go:build !cgo); "+p1" is the first
	// carried patch set (kinePatches, kinepatch.go). It is part of the marker
	// because version alone does not identify the binary: the same kine tag builds two
	// different SQLite implementations depending on CGO_ENABLED, and only this one
	// keeps the unmaintained mattn/go-sqlite3 out of every k3sm artifact; and the same
	// tag built with and without the patches behaves differently on disk. Changing the
	// patch set changes the "+p" suffix, which is what makes every already-staged kine
	// (and every node seeding from an older payload) re-stage the patched build.
	kineBuildVariant = "nocgo+p1"
)

// kinePath / kineMarkerPath name the staged kine binary and its version marker in a
// bin dir (a workdir bin or a payload dir).
func kinePath(bd string) string       { return filepath.Join(bd, kineBinaryName) }
func kineMarkerPath(bd string) string { return filepath.Join(bd, KineMarkerName) }

// kineMarkerContent renders a marker: "<version> <variant>\n".
func kineMarkerContent(version string) string { return kineChild(version).markerContent() }

// readKineMarker returns the (version, variant) recorded beside a staged kine binary.
// A missing or unreadable marker yields ("", ""), which no target ever matches — so an
// unmarked binary (anything staged before markers existed) always re-stages.
func readKineMarker(bd string) (version, variant string) {
	return readChildMarker(kineMarkerPath(bd))
}

// kineStaged reports whether bd holds a kine binary whose marker vouches for exactly
// (version, kineBuildVariant). The marker is written LAST and only after the binary is
// staged and signed, so "marker matches" implies "the binary beside it is finished".
func kineStaged(bd, version string) bool { return kineChild(version).staged(bd) }

// writeKineMarker writes the marker atomically (temp + rename) so a crashed or
// killed boot can never leave a half-written marker vouching for the wrong bytes.
func writeKineMarker(bd, version string) error { return kineChild(version).writeMarker(bd) }

// ensureKine stages the kine the boot runs into the workdir bin.
//
// On the RELEASE path (a Developer ID-signed k3sm, see signingPolicy) it is the
// payload's kine and nothing else: verified, its stamp read from the verified bytes
// and matched against (kineVersion, kineBuildVariant), then used byte-identical
// (stagedChild.ensureShipped). A missing, unverified or mismatched shipped kine
// refuses the boot; it never falls through to a build.
//
// On the DEV path seedBinDir has already preferred the payload's kine when its marker
// vouches for the pins; what is left here builds kine from source CGO_ENABLED=0
// (kine's pure-Go modernc.org/sqlite backend) into the workdir bin, ad-hoc signs it,
// and records the version marker. It is a no-op only when the marker already vouches
// for the wanted version+variant — never on mere presence.
//
// payloadDir is the staged install payload seedBinDir seeds from ("" for none). When
// neither the work dir nor that payload vouches for the target build and there is no
// Go toolchain to make one, the k3sm binary was replaced without the payload that
// ships beside it (a swapped binary, then a kickstart): that is ErrKinePayloadStale,
// named as such rather than as a missing toolchain, because the fix is the install.
func ensureKine(ctx context.Context, logger *slog.Logger, workDir, payloadDir, kineVersion string) error {
	bd := binDir(workDir)
	p, err := resolveSigningPolicy(ctx, logger)
	if err != nil {
		return err
	}
	if p.release {
		return kineChild(kineVersion).ensureShipped(ctx, p, bd, payloadDir)
	}
	if err := kinePayloadStale(bd, payloadDir, kineVersion); err != nil {
		return err
	}
	return ensureKineInto(ctx, bd, kineVersion)
}

// ErrKinePayloadStale marks a server whose staged payload carries a different kine
// build than this binary runs, with no Go toolchain to build the right one. It is
// returned wrapped together with ErrNoGoToolchain, so the crash-loop breaker parks on
// the first failure (it cannot heal on retry); the recording site matches this
// sentinel first and records KinePayloadStaleRemedy.
var ErrKinePayloadStale = errors.New("the staged control-plane payload carries a different kine build than this k3sm runs")

// KinePayloadStaleRemedy is the operator's fix for ErrKinePayloadStale.
const KinePayloadStaleRemedy = "the k3sm binary was replaced without its control-plane payload; re-run `sudo k3sm install` from this release so the staged payload carries the kine it runs"

// kinePayloadStale reports ErrKinePayloadStale when nothing can supply the target
// kine: the work dir's marker does not vouch for it, the payload's does not either,
// and there is no Go toolchain. Any one of those holding returns nil and the normal
// seed or build path proceeds.
func kinePayloadStale(bd, payloadDir, kineVersion string) error {
	if payloadDir == "" || kineStaged(bd, kineVersion) || kineStaged(payloadDir, kineVersion) {
		return nil
	}
	if _, err := lookPathGo(); err == nil {
		return nil
	}
	want := kineChild(kineVersion)
	pv, pvar := readKineMarker(payloadDir)
	wv, wvar := readKineMarker(bd)
	return fmt.Errorf("stage kine: %w (%w): this k3sm runs kine %q, the payload in %s carries %q and the work dir %q; %s",
		ErrKinePayloadStale, ErrNoGoToolchain, strings.TrimSpace(want.markerContent()), payloadDir,
		strings.TrimSpace(pv+" "+pvar), strings.TrimSpace(wv+" "+wvar), KinePayloadStaleRemedy)
}

// ensureKineInto is ensureKine against an explicit bin dir — shared by the boot
// path and StagePayload. The staging choreography (marker check, toolchain
// preflight, drop-stale-marker, temp + rename, sign, marker last) is the
// stagedChild protocol; kineChild declares only how kine is built.
func ensureKineInto(ctx context.Context, bd, kineVersion string) error {
	return kineChild(kineVersion).ensureInto(ctx, bd)
}

// kineChild is kine's stagedChild declaration at the given pin.
func kineChild(kineVersion string) stagedChild {
	return stagedChild{
		name:    kineBinaryName,
		marker:  KineMarkerName,
		version: kineVersion,
		variant: kineBuildVariant,
		build: func(ctx context.Context, gopath string) (string, error) {
			return buildKine(ctx, kineVersion, gopath)
		},
		readStamp: kineStampFromBinary,
	}
}

// buildKine builds the pinned kine from its patched module source (CGO_ENABLED=0,
// see kineBuildEnv and buildPatchedKine) into the scratch GOPATH and returns the
// built binary's path, gopath/bin/kine. An explicit GOOS/GOARCH in the environment
// (the release stages darwin/arm64 explicitly) cross-compiles to the same path.
func buildKine(ctx context.Context, kineVersion, gopath string) (string, error) {
	// The scratch GOPATH is thrown away with the build; the MODULE CACHE must not be.
	modCache, err := kineModuleCacheDir(ctx)
	if err != nil {
		return "", err
	}
	if out, err := runKineBuild(ctx, kineVersion, gopath, modCache); err != nil {
		return "", fmt.Errorf("build kine %s (CGO_ENABLED=0): %w (a packaged install has no Go toolchain — re-run `sudo k3sm install` so the staged payload carries this pin): %s",
			kineVersion, err, out)
	}
	return filepath.Join(gopath, "bin", kineBinaryName), nil
}

// kineBuildEnv is the environment the pinned kine build runs under.
//
// CGO_ENABLED=0 selects kine's pure-Go SQLite backend (modernc.org/sqlite, behind
// //go:build !cgo). It is a real, supported kine variant on the pinned version — not
// the SQLite-disabled stub the spike measured on the old pin — and it is what keeps
// the unmaintained mattn/go-sqlite3 (and a C toolchain) out of every k3sm artifact.
// GOBIN is cleared (not just unset in our env) so an ambient GOBIN cannot redirect
// any install step out of the scratch GOPATH.
//
// GOMODCACHE is pinned AWAY from the scratch GOPATH, and that pin is the load-bearing
// part: a module cache left to derive from GOPATH lands inside the per-build temp dir,
// so kine's whole dependency tree is downloaded and then deleted with it on EVERY
// boot — a per-boot network round trip long enough to outlast a bring-up deadline,
// masquerading as a one-time cold-cache cost. Pinned, the pin's modules are fetched
// once per machine and every later boot builds offline from the warmed cache.
//
// Module verification is pinned, not inherited: the ambient GOSUMDB, GONOSUMDB,
// GONOSUMCHECK, GOPRIVATE, GOINSECURE, GOFLAGS and GOPROXY are dropped, and the checksum
// database, the public proxy and GOTOOLCHAIN=local are set last. A shell that ran the
// daemon with GOSUMDB=off would otherwise build kine from unverified modules. GOFLAGS is
// left unset for each command to set for itself.
func kineBuildEnv(gopath, modCache string) []string {
	env := make([]string, 0, len(os.Environ())+9)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(goVerificationEnv, name) {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"CGO_ENABLED=0", "GOWORK=off", "GOBIN=", "GOPATH="+gopath, "GOMODCACHE="+modCache,
		"GOSUMDB=sum.golang.org", "GOPROXY=https://proxy.golang.org,direct", "GOTOOLCHAIN=local")
}

// goVerificationEnv lists the ambient variables that weaken or redirect Go module
// verification or toolchain selection; kineBuildEnv never passes them through.
var goVerificationEnv = []string{
	"GOSUMDB", "GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE", "GOINSECURE", "GOFLAGS",
	"GOPROXY", "GONOPROXY", "GOTOOLCHAIN",
}

// ErrNoGoToolchain marks a re-stage of a source-built control-plane child (kine, and
// any other stagedChild) that cannot run because no `go` is on PATH.
// It is a PERMANENT bring-up fault: retrying under the same environment fails the same
// way, which is what lets the crash-loop breaker park on the first occurrence
// (CrashRecord.RecordPermanent). Match it with errors.Is, never by message.
var ErrNoGoToolchain = errors.New("no Go toolchain on PATH to build the pinned control-plane child")

// NoGoToolchainRemedy is the operator's fix for ErrNoGoToolchain: a packaged install
// carries the pinned children in its staged payload, so re-installing re-stages it and the
// boot seeds from the payload instead of building.
const NoGoToolchainRemedy = "a packaged install has no Go toolchain; re-run `sudo k3sm install` so the staged payload carries this pin"

// lookPathGo resolves the toolchain the child builds need. It reads PATH at call time,
// so a test drives it with t.Setenv; it is a var only so a release-path test can
// prove it is never consulted.
var lookPathGo = func() (string, error) { return exec.LookPath("go") }

// kineModuleCacheDir resolves the stable module cache the kine build downloads into,
// and runKineBuild runs the build itself. Both are vars so a test can assert the build
// environment and the cache's reuse across builds without fetching anything.
var (
	kineModuleCacheDir = hostGoModCache
	runKineBuild       = buildPatchedKine
)

// hostGoModCache returns the HOST TOOLCHAIN's own module cache (`go env GOMODCACHE`,
// which already honours an ambient GOMODCACHE or GOPATH).
//
// The host cache is chosen over a k3sm-private one deliberately: this code path only
// runs where a Go toolchain exists (a packaged install seeds kine from its staged
// payload and never builds), the host cache is shared by every work dir and every dev
// instance — so a pin is fetched once per machine rather than once per instance — and a
// `go mod download` warm-up then actually counts for the boot that follows. The
// fallback covers a toolchain reporting no cache at all; it gives up the sharing but
// keeps the property that matters, which is that the path is the same on the next boot.
func hostGoModCache(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMODCACHE").Output()
	if err != nil {
		return "", fmt.Errorf("resolve the Go module cache (go env GOMODCACHE): %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		base, cerr := os.UserCacheDir()
		if cerr != nil {
			return "", fmt.Errorf("resolve a stable Go module cache: %w", cerr)
		}
		dir = filepath.Join(base, "k3sm", "gomodcache")
	}
	// Created here rather than left to the toolchain so an unwritable cache fails with
	// the path named instead of inside a toolchain diagnostic.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create Go module cache %s: %w", dir, err)
	}
	return dir, nil
}

// copyFile copies src to dst with the given mode, replacing dst if present.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// PayloadBinaries is the full control-plane payload set a packaged install must
// stage beside the daemon (the boot path otherwise acquires them with gh/go —
// dev-shell tools a launchd daemon does not have): the kwok-ci/k8s prebuilt
// binaries plus kine, etcd and etcdutl (the offline tool `k3sm snapshot restore` runs
// on an etcd server), and the pinned helm the helm controller's Jobs run (see
// helm.go). The single source for `k3sm payload`, `k3sm install`, and
// the boot-time seed, so the three can never disagree on the set.
func PayloadBinaries() []string {
	return append(append([]string{}, cpBinaries...), kineBinaryName, etcdBinaryName, etcdutlBinaryName, helmchart.HelmBinaryName, registrysvc.ZotBinaryName)
}

// StagePayload acquires the full control-plane payload into destDir using the
// executor's own pinned versions (DefaultKubeVersion via `gh release download`,
// DefaultKineVersion via a patched CGO_ENABLED=0 source build, DefaultEtcdVersion via a
// CGO_ENABLED=0 build of the embedded wrapper module). Each part drops its version
// marker beside the binaries it describes — KubeMarkerName after the four
// kwok-ci/k8s binaries are digest-verified and signed, KineMarkerName after kine and
// EtcdMarkerName after etcd are built and signed — so a seeded workdir knows what it
// got. etcd ships in every payload whether or not the node runs it, as k3s ships it
// in every binary: a packaged install has no Go toolchain to build it later. It is the packaging-side
// producer: run it where the dev tools exist (a human shell, goreleaser), then hand
// destDir to `k3sm install`, which stages it beside the daemon; the daemon boot seeds
// its workdir from the staged copy and never needs gh/go (a launchd _k3sm daemon
// has neither — an observed live-hardware failure this closes).
func StagePayload(ctx context.Context, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("create payload dir %s: %w", destDir, err)
	}
	// Fail closed on the packaging path: these bytes are about to be archived and
	// published, so a third-party tag that moved (or an extra asset riding along)
	// must stop the release rather than ship. The digest check happens INSIDE the
	// download, before ad-hoc signing rewrites the Mach-O. The boot path verifies
	// too whenever a pin exists; only this path also refuses an unpinned version.
	// The logger is unused on this path: a present set is refused before anything
	// would be reported, and an unpinned version is refused rather than warned.
	if err := ensureControlPlaneBinariesVerified(ctx, slog.New(slog.DiscardHandler), destDir, DefaultKubeVersion, true); err != nil {
		return err
	}
	if err := ensureKineInto(ctx, destDir, DefaultKineVersion); err != nil {
		return err
	}
	if err := ensureEtcdInto(ctx, destDir, DefaultEtcdVersion); err != nil {
		return err
	}
	if err := ensureEtcdutlInto(ctx, destDir, DefaultEtcdVersion); err != nil {
		return err
	}
	// helm is re-downloaded and re-verified even if present (force): these bytes
	// are about to be published, and a copy already in the directory may have been
	// signed, which rewrites it past any digest comparison.
	// The packaging producer runs no signing decision: what it stages is ad-hoc
	// signed, and the attended pipeline re-signs the release copy.
	if err := stageHelm(ctx, signingPolicy{s: bootCodeSigner}, destDir, true); err != nil {
		return err
	}
	// The ingest registry's zot, built from its pinned module with its marker, so a
	// packaged install never builds it (pkg/registrysvc stages it from the payload).
	if err := stageZot(ctx, destDir); err != nil {
		return err
	}
	return VerifyPayloadSet(destDir)
}

// stageZot builds the pinned zot and its version marker into a payload dir. A var
// so a test of StagePayload stands in for the build.
var stageZot = func(ctx context.Context, destDir string) error {
	return registrysvc.EnsureZot(ctx, destDir, "", registrysvc.DefaultZotVersion)
}

// StageKine stages the pinned, patched kine (and its version marker) into destDir
// through the same stagedChild protocol the daemon boot and StagePayload use. It is
// the one kine build: `k3sm payload --kine-only` exposes it to the hack scripts, so
// no harness runs a kine built any other way.
func StageKine(ctx context.Context, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("create kine dir %s: %w", destDir, err)
	}
	return ensureKineInto(ctx, destDir, DefaultKineVersion)
}

// seedBinDir copies every payload binary present in payloadDir and absent from
// the workdir bin into it (0755, each on a new inode through atomicfile.InstallFile,
// signed before it takes its name), so the subsequent ensure* steps find them
// present and signed — never shelling out to gh/go. A missing payloadDir
// or missing individual binary is NOT an error here: the ensure* fallbacks
// still run and fail with their own actionable errors (dev shells keep working
// with no payload at all).
//
// The VERSIONED binaries are the exceptions to "never overwrite an existing workdir
// binary": kine, etcd (at DefaultEtcdVersion, under kine's rule), and the
// control-plane set (kube-apiserver, kube-controller-manager,
// kube-scheduler, kubectl). Each carries a version marker, and presence alone cannot
// tell this release's bytes from an earlier release's, so a binary-only upgrade that
// moved a pin would otherwise keep running the old bytes forever — kine loudly (its
// only other re-stage is a Go toolchain a launchd _k3sm daemon does not have), the
// control plane silently (its old set boots fine). So when the workdir's marker does
// not vouch for the target and the payload's OWN marker does, the payload wins: kine
// is replaced alone, the control-plane set is replaced WHOLE (every file, then the
// marker last). The payload ships in the same archive as this binary and therefore
// carries this binary's pins. An unmarked payload never wins — trusting it would mean
// stamping the new pin onto bytes nothing verified — and a payload OLDER than the
// control-plane set already staged is refused, as is any re-seed over a
// present-but-malformed marker (see below). Every other file is
// unversioned and is only ever filled in when absent. kineVersion and kubeVersion are
// the targets the caller resolved (Config.KineVersion, Config.KubeVersion).
//
// withEtcd is the posture: etcd is seeded (and re-seeded under its marker) only in
// the etcd posture. A kine-posture work dir never receives an etcd binary, even though
// every payload carries one.
func seedBinDir(ctx context.Context, logger *slog.Logger, workDir, payloadDir, kineVersion, kubeVersion string, withEtcd bool) error {
	if payloadDir == "" {
		return nil
	}
	bd := binDir(workDir)
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return fmt.Errorf("create bin dir %s: %w", bd, err)
	}
	policy, err := resolveSigningPolicy(ctx, logger)
	if err != nil {
		return err
	}
	// A staged kine whose marker does not vouch for the target is re-seeded from the
	// payload — but ONLY when the payload's OWN marker vouches for the target. Trusting
	// an unmarked payload instead would mean stamping "this is the new pin" onto bytes
	// nobody verified: a node upgraded by replacing only the binary still has the
	// previous release's payload staged, and the lie would leave it running the old
	// datastore engine while claiming the new one. An unmarked payload therefore falls
	// through to ensureKineInto, which rebuilds or reports.
	//
	// A payload kine whose marker does vouch for the target is PREFERRED: it replaces
	// a work-dir kine whose bytes differ even when that one's marker vouches too (an
	// earlier on-demand build), so the shipped binary is never shadowed.
	//
	// On the release path neither kine nor etcd is seeded here: ensureKine and
	// ensureEtcd install the payload's copy only after verifying it and reading its
	// stamp from the verified bytes (stagedChild.ensureShipped).
	restageKine, err := preferShipped(kineChild(kineVersion), bd, payloadDir)
	if err != nil {
		return err
	}
	// etcd follows kine's rule exactly, at the one version the wrapper pins.
	restageEtcd := false
	if withEtcd {
		if restageEtcd, err = preferShipped(etcdChild(DefaultEtcdVersion), bd, payloadDir); err != nil {
			return err
		}
	}
	if policy.release {
		restageKine, restageEtcd = false, false
	}
	// The control-plane set follows the same rule, with one refusal kine does not need
	// here (kine's own migration path owns its downgrade story): when the workdir's
	// marker names a NEWER version than the payload vouches for, the re-seed would
	// run an older apiserver over a datastore a newer one has written, which is one-way
	// and which the kine migration does not cover. The present set is left in place
	// and the boot continues on it; ensureControlPlaneBinaries reports it too.
	restageKube := false
	previousKube, markerState := readKubeMarkerState(bd)
	if !kubeSetStaged(bd, kubeVersion) && kubeSetStaged(payloadDir, kubeVersion) {
		switch {
		case markerState == kubeMarkerMalformed:
			logger.Error("refusing to re-seed the control-plane binaries: the work dir's version marker is present but malformed, so a downgrade cannot be ruled out; continuing on the present set",
				"marker", kubeMarkerPath(bd), "payload-version", kubeVersion, "remedy", "inspect the marker; delete it only if the set beside it is known to be older than "+kubeVersion+", and the next boot re-seeds")
		case KubeVersionOlder(kubeVersion, previousKube):
			logger.Error("refusing to re-seed the control-plane binaries: the staged payload is OLDER than the set in the work dir, and an apiserver downgrade over a datastore a newer apiserver wrote is one-way; continuing on the present set",
				"workdir-version", previousKube, "payload-version", kubeVersion, "dir", bd, "remedy", NewerControlPlaneRemedy)
		default:
			restageKube = true
		}
	}
	if restageKube {
		if err := clearKubeMarker(bd); err != nil {
			return err
		}
	}
	for _, name := range PayloadBinaries() {
		if name == etcdBinaryName && !withEtcd {
			continue
		}
		// etcdutl is never seeded: the daemon does not run it. `k3sm snapshot restore`
		// runs it offline, from the payload directory itself.
		if name == etcdutlBinaryName {
			continue
		}
		// On the release path kine and etcd are installed by their ensure step,
		// verified and stamp-checked, never filled in here.
		if policy.release && (name == kineBinaryName || name == etcdBinaryName) {
			continue
		}
		// zot is staged by the registry (pkg/registrysvc) from the payload directory
		// itself, under its own version marker, on both paths.
		if name == registrysvc.ZotBinaryName {
			continue
		}
		dst := filepath.Join(bd, name)
		versioned := (name == kineBinaryName && restageKine) || (name == etcdBinaryName && restageEtcd) ||
			(restageKube && isCPBinary(name))
		// On the release path the work dir runs the payload's helm and no other: a
		// copy that differs from it (an earlier dev install's ad-hoc build of the same
		// pin) is replaced, verified, rather than refused at signHelm.
		if policy.release && name == helmchart.HelmBinaryName {
			same, err := sameContent(filepath.Join(payloadDir, name), dst)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("compare the shipped %s with %s: %w", name, dst, err)
			}
			versioned = err == nil && !same
		}
		if _, err := os.Stat(dst); err == nil && !versioned {
			continue // already present (a prior boot seeded/acquired it)
		}
		src := filepath.Join(payloadDir, name)
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue // not staged; the ensure* fallback owns the error
			}
			return fmt.Errorf("read payload %s: %w", src, err)
		}
		// On a NEW inode, never over the old one: a versioned re-seed replaces a
		// binary a running child may still have mapped. On the dev path the copy is
		// signed (only if its signature does not already verify) before it takes
		// the name; on the release path a control-plane copy is verified against
		// the release requirement instead, and never signed.
		prepare := binsign.SignIfInvalid(ctx, bootCodeSigner, name)
		if policy.release && (isCPBinary(name) || name == helmchart.HelmBinaryName) {
			prepare = verifyTempHook(ctx, policy, name)
		}
		if err := atomicfile.InstallFile(src, dst, 0o755, prepare); err != nil {
			return fmt.Errorf("seed %s from payload: %w", dst, err)
		}
	}
	if restageKine {
		if err := writeKineMarker(bd, kineVersion); err != nil {
			return err
		}
	}
	if restageEtcd {
		if err := etcdChild(DefaultEtcdVersion).writeMarker(bd); err != nil {
			return err
		}
	}
	if restageKube {
		// LAST, after the whole set. The payload's bytes were signed when it was
		// staged and the ad-hoc signature is embedded in each Mach-O, so the copies
		// are signed already; the seed signed any that were not.
		if err := writeKubeMarker(bd, kubeVersion); err != nil {
			return err
		}
		if previousKube == "" {
			previousKube = "unvouched"
		}
		logger.Info("seeded the control-plane binaries from the staged payload",
			"from", previousKube, "to", kubeVersion, "dir", bd)
	}
	return nil
}

// preferShipped reports whether the dev seed must (re)place c's work-dir binary
// from the payload: the payload's marker vouches for c's pins, and the work dir does
// not already hold those very bytes under a vouching marker.
func preferShipped(c stagedChild, bd, payloadDir string) (bool, error) {
	if !c.staged(payloadDir) {
		return false, nil
	}
	if !c.staged(bd) {
		return true, nil
	}
	same, err := sameContent(c.binPath(payloadDir), c.binPath(bd))
	if err != nil {
		return false, fmt.Errorf("compare the payload %s with the work dir's: %w", c.name, err)
	}
	return !same, nil
}

// isCPBinary reports whether name is one of the control-plane set the kube marker
// covers.
func isCPBinary(name string) bool {
	for _, b := range cpBinaries {
		if b == name {
			return true
		}
	}
	return false
}

// fileExists reports whether path names an existing file (any stat error — including
// a permission error — reads as absent, which is the conservative answer for every
// caller here: it falls back to the acquisition path, which reports its own error).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// signBinaries is the dev signing: it makes sure each named binary in dir carries a
// valid signature so an arm64 Mach-O can exec on macOS. It runs on live work-dir
// binaries at every boot, so it never writes one in place (see package binsign):
//
//   - binsign.HealOnce first replaces each binary once per stamp (the content of
//     the set's version marker, or the versioned name), clearing a vnode an older
//     k3sm may have left poisoned by its in-place `codesign -f`;
//   - then binsign.EnsureSigned leaves a validly signed binary alone and ad-hoc
//     signs any other as a temp copy renamed over it.
//
// Both verify first: a binary whose signature verifies and is not ad hoc (a
// Developer ID) is never healed or re-signed, on either signing path. The
// control-plane set, the source-built children kine and etcd, and helm take this
// path only on the dev path (see signingPolicy).
//
// Signing failures are tolerated (best-effort: a non-macOS CI host should not block
// bring-up, and a failure leaves the file as it was); the binary fails loudly at
// exec if it truly cannot run.
func signBinaries(ctx context.Context, dir, stamp string, names []string) error {
	_ = binsign.HealOnce(ctx, bootCodeSigner, dir, stamp, names...)
	for _, n := range names {
		p := filepath.Join(dir, n)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		_, _ = binsign.EnsureSigned(ctx, bootCodeSigner, p)
	}
	return nil
}

// reapStagingTemps removes the ".<name>.tmp-<digits>" files a killed atomicfile
// install left in bd, for every binary the executor stages there and for the
// binsign heal marker. It must run before any staging step of this boot, so no
// live install's temp is removed.
func reapStagingTemps(bd string) error {
	for _, name := range append(PayloadBinaries(), binsign.HealMarkerName) {
		// zot's temps belong to the registry, which reaps them itself before it
		// stages (registrysvc.EnsureZotWith); it may be staging one now.
		if name == registrysvc.ZotBinaryName {
			continue
		}
		if err := atomicfile.ReapOrphans(bd, name); err != nil {
			return err
		}
	}
	return nil
}

// healStamp is the HealOnce stamp for a set guarded by the version marker at
// path: its content on one line, or "unmarked".
func healStamp(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unmarked"
	}
	s := strings.Join(strings.Fields(string(b)), " ")
	if s == "" {
		return "unmarked"
	}
	return s
}

// resignFresh ad-hoc signs each named, freshly downloaded binary in dir whatever
// signature it carries (a downloaded set is always re-signed ad hoc), each through
// a temp copy renamed over it. Best-effort, like signBinaries.
func resignFresh(ctx context.Context, dir string, names []string) {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		_ = binsign.ResignByReplace(ctx, bootCodeSigner, p)
	}
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
// apiserver loads via --token-auth-file, granting system:masters to the
// in-process node, the provisioning client and the healthz probe.
func writeTokenFile(workDir, token string) error {
	line := fmt.Sprintf("%s,admin,admin-uid,\"system:masters\"\n", token)
	if err := os.WriteFile(tokenFilePath(workDir), []byte(line), 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}

// writeKubeconfig writes an admin kubeconfig pointing at the apiserver with the
// static token, verifying the server against the cluster CA (read from the PKI dir),
// which issued the apiserver's serving leaf on every topology. It runs after
// provisionComponentCerts has ensured that CA.
//
// It takes the whole Config, not a work dir and a port, because the server URL needs
// the effective BIND HOST as well (apiServerHost): a mesh server binds its wireguard
// IP only, so a loopback URL here would hand every in-process client a dead address.
func writeKubeconfig(cfg Config, token string) error {
	caPEM, err := os.ReadFile(certs.ClusterCACertPath(cfg.WorkDir))
	if err != nil {
		return fmt.Errorf("read the cluster CA for the kubeconfig: %w", err)
	}
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %q
    certificate-authority-data: %s
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
`, apiServerURL(cfg), base64.StdEncoding.EncodeToString(caPEM), token)
	if err := os.WriteFile(kubeconfigPath(cfg.WorkDir), []byte(content), 0o600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	return nil
}

// writeComponentKubeconfig mints a client cert (CommonName cn, no Organization)
// from the SIGNING CA — which the apiserver's unconditional --client-ca-file trusts —
// and writes a 0600 client-cert kubeconfig at path pointing at the apiserver's
// EFFECTIVE BIND (apiServerHost — loopback single-node, the mesh IP on a mesh server).
// The component (kube-scheduler / kube-controller-manager) then authenticates as cn, so
// the apiserver's auto-created bootstrap RBAC (the system:kube-scheduler /
// system:kube-controller-manager ClusterRoleBindings) constrains it — the k3s
// per-component-identity model, replacing the shared system:masters admin token.
//
// The kubeconfig pins certificate-authority-data to the cluster CA, which issued the
// apiserver's serving leaf on every topology; it never skips server verification.
func writeComponentKubeconfig(cfg Config, path, cn string, h *certs.Hierarchy) error {
	certPEM, keyPEM, err := h.Signing.IssueClient(cn, nil, ComponentCertValidity)
	if err != nil {
		return fmt.Errorf("issue %s client cert: %w", cn, err)
	}
	b64 := base64.StdEncoding.EncodeToString
	clusterTLS := "    certificate-authority-data: " + b64(h.Cluster.CertPEM)
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
`, apiServerURL(cfg), clusterTLS, cn, cn, b64(certPEM), b64(keyPEM))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s kubeconfig: %w", cn, err)
	}
	return nil
}

// writeAPIServerKubeletClientCert mints the client keypair the apiserver presents
// to a node's kubelet endpoint (:10250 — logs, exec, attach, port-forward, stats)
// and writes it beside the per-component kubeconfigs (cert 0644, key 0600).
//
// It is issued by the SIGNING CA, which is both the apiserver's --client-ca-file
// and the anchor every node's kubelet endpoint verifies client certs against — so
// one CA distribution (the server reads it off disk, a joining worker receives it
// in its join response) covers the whole cluster. Its CN is the single identity
// that endpoint authorizes; see certs.APIServerKubeletClientCN for why it carries
// no Organization.
//
// Re-issued on every boot like the component kubeconfigs. That is transparent to
// the nodes: they pin the CA, never this leaf.
func writeAPIServerKubeletClientCert(workDir string, h *certs.Hierarchy) error {
	certPEM, keyPEM, err := h.Signing.IssueClient(certs.APIServerKubeletClientCN, nil, ComponentCertValidity)
	if err != nil {
		return fmt.Errorf("issue %s client cert: %w", certs.APIServerKubeletClientCN, err)
	}
	if err := os.WriteFile(apiServerKubeletClientCertPath(workDir), certPEM, 0o644); err != nil {
		return fmt.Errorf("write apiserver kubelet-client cert: %w", err)
	}
	if err := os.WriteFile(apiServerKubeletClientKeyPath(workDir), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write apiserver kubelet-client key: %w", err)
	}
	return nil
}

// writeProxyClientCert writes the aggregator's front-proxy client keypair the
// apiserver presents to an extension apiserver (--proxy-client-cert-file /
// --proxy-client-key-file): certs.ProxyClientCN, no Organization, clientAuth only,
// issued by the request-header CA through Hierarchy.IssueProxyClient (the only
// issuance that CA makes). Re-minted every boot like every other component leaf. The
// key is 0600: it is an impersonation credential at any backend that trusts the
// request-header CA, protected exactly as the CA keys beside it are.
func writeProxyClientCert(workDir string, h *certs.Hierarchy) error {
	certPEM, keyPEM, err := h.IssueProxyClient(ComponentCertValidity)
	if err != nil {
		return fmt.Errorf("issue %s proxy client cert: %w", certs.ProxyClientCN, err)
	}
	// The key lets its holder assert any user to the apiserver through the request
	// headers, so it is installed by rename: an existing symlink is replaced, not
	// followed, and an older file's wider mode cannot survive.
	if err := atomicfile.Replace(ProxyClientKeyPath(workDir), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write proxy client key: %w", err)
	}
	if err := atomicfile.Replace(ProxyClientCertPath(workDir), certPEM, 0o644); err != nil {
		return fmt.Errorf("write proxy client cert: %w", err)
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
