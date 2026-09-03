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

package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The HOST-side buildx pin.
//
// Two assets, two arches, ONE release tag: buildx.go pins the linux-arm64 asset
// the engine stages inside its Linux guest; this pins the darwin-arm64 asset the
// Mac runs to DRIVE that engine. They share BuildxVersion, so a version bump
// moves both and neither can drift from the other.
//
// PROVENANCE. Upstream's checksums.txt covers only the linux and windows assets.
// The darwin binaries are Developer-ID signed after the checksummed build, so the
// released bytes match neither that file (which omits them) nor the SLSA
// provenance subject digest (874075…, which is the pre-signing artifact). The pin
// below is therefore the sha256 of the RELEASED darwin-arm64 asset itself,
// recorded 2026-09-02 from
//
//	https://github.com/docker/buildx/releases/download/v0.17.1/buildx-v0.17.1.darwin-arm64
//
// (Mach-O 64-bit arm64, 56973344 bytes, "Developer ID Application: Tonis Tiigi
// (F32M533787)"). Re-record a bump the same way: download the asset, sha256 it,
// and confirm `codesign -dv` still reports that Developer ID before pinning.
const (
	// HostBuildxAsset is the pinned host buildx asset name (the host is darwin/arm64).
	HostBuildxAsset = "buildx-" + BuildxVersion + "." + hostBuildxPlatform
	// HostBuildxSHA256 is the released darwin/arm64 asset's sha256.
	HostBuildxSHA256 = "6f01a55c66edb9bc6f03c035c17f640b0edd672f2fcf0e7389440cc51c403517"

	// BuilderInstanceName is the buildx builder instance k3sm owns and injects
	// with --builder. It lives in a k3sm-owned BUILDX_CONFIG store, so the name
	// never collides with a builder the user created for something else.
	BuilderInstanceName = "k3sm"

	// hostBuildxPlatform is the host asset's platform suffix. k3sm is
	// arm64-only, so there is deliberately no darwin-amd64 pin: a Mac that
	// cannot run this binary cannot run k3sm either.
	hostBuildxPlatform = "darwin-arm64"
)

// HostBuildxURL is the download URL for the pinned host buildx asset.
func HostBuildxURL() string {
	return fmt.Sprintf("https://github.com/docker/buildx/releases/download/%s/%s", BuildxVersion, HostBuildxAsset)
}

// ValidateHostBuildxPin fails if the compiled-in host buildx pin is malformed.
// It is the host-side twin of ValidateBuildxPin: a build-time contract check that
// catches a bad bump with `go test` rather than with a fetch nobody can verify.
func ValidateHostBuildxPin() error {
	return validatePin(BuildxVersion, HostBuildxAsset, HostBuildxSHA256, hostBuildxPlatform)
}

// HostBuildxPath is where the verified host buildx binary is cached inside
// binDir (the work dir's bin cache, alongside the control-plane binaries). The
// version is in the file name so a bump downloads beside the old copy instead of
// silently reusing it.
func HostBuildxPath(binDir string) string {
	return filepath.Join(binDir, "buildx-"+BuildxVersion)
}

// HostConfigDir is the k3sm-owned BUILDX_CONFIG directory for workDir. It holds
// the k3sm builder instance record and nothing else, so repairing that instance
// can never disturb a builder the user configured for their own work.
func HostConfigDir(workDir string) string {
	return filepath.Join(workDir, "buildx")
}

// EnsureHostBuildx returns the path to a verified host buildx binary in binDir,
// downloading the pinned darwin/arm64 asset when the cached copy is absent or
// does not match the pin.
//
// The cached copy is re-verified on EVERY call, not only after a download: it
// lives in a work dir that outlives any single command, so "we fetched it
// correctly once" is not the property that matters — the same reasoning the
// in-pod stage applies to its copy on the cache PVC.
func EnsureHostBuildx(ctx context.Context, binDir string) (string, error) {
	if err := ValidateHostBuildxPin(); err != nil {
		return "", err
	}
	path := HostBuildxPath(binDir)
	if err := ensureVerifiedBinary(ctx, path, HostBuildxURL(), HostBuildxSHA256); err != nil {
		return "", err
	}
	return path, nil
}

// ensureVerifiedBinary is the pure-seam core of EnsureHostBuildx: it makes path
// hold exactly the bytes whose sha256 is want, fetching them from url when it
// does not already. Split out so a test can drive it against an httptest server
// without touching the pinned upstream URL.
func ensureVerifiedBinary(ctx context.Context, path, url, want string) error {
	if sum, err := sha256File(path); err == nil {
		if sum == want {
			// Cached and verified. The chmod is idempotent and repairs a copy
			// whose exec bit was lost (an archive round-trip, a restore).
			return os.Chmod(path, 0o755)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove unverified buildx at %s: %w", path, err)
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create buildx cache dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".buildx-*")
	if err != nil {
		return fmt.Errorf("stage buildx download in %s: %w", dir, err)
	}
	staged := tmp.Name()
	// Any exit before the rename must not leave a partial binary behind; the
	// remove is a no-op once the rename has consumed the staged file.
	defer func() { _ = os.Remove(staged) }()

	sum, err := downloadTo(ctx, tmp, url)
	if cerr := tmp.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("close %s: %w", staged, cerr)
	}
	if err != nil {
		return err
	}
	if sum != want {
		return fmt.Errorf("buildx %s from %s has sha256 %s, want %s — refusing to run unverified bytes", HostBuildxAsset, url, sum, want)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return fmt.Errorf("chmod staged buildx: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		return fmt.Errorf("install buildx at %s: %w", path, err)
	}
	return nil
}

// downloadTo streams url into w and returns the lowercase hex sha256 of what it
// wrote. The hash is taken from the bytes ON THE WAY TO DISK, so no reread can
// observe different content than was verified.
func downloadTo(ctx context.Context, w io.Writer, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("request %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256File returns the lowercase hex sha256 of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HostHomeDir is the k3sm-owned HOME directory buildx runs with, inside the
// k3sm BUILDX_CONFIG store for cfgDir. See BuildxEnv for why HOME is redirected
// at all; it lives under the store so a reset of the store takes it with it.
func HostHomeDir(cfgDir string) string {
	return filepath.Join(cfgDir, "home")
}

// BuildxEnv returns the environment for a buildx exec: base, with BUILDX_CONFIG
// forced to the k3sm-owned cfgDir, HOME forced to a k3sm-owned directory inside
// it, and DOCKER_CONFIG pinned to the config directory the caller's own
// environment resolves to.
//
// BUILDX_CONFIG is load-bearing at BOTH ends. buildx writes the instance record
// under BUILDX_CONFIG at create time and reads it back from there at build time;
// with the variable unset (or different) for the build, buildx does not find the
// k3sm instance and quietly falls back to the docker context, which on a Mac
// without Docker Desktop fails with an error that names the docker socket rather
// than the real cause. Deriving both ends from this one function is what makes
// the two agree.
//
// HOME is redirected to suppress the Docker Desktop deep link. On a Mac that has
// ever used Desktop's build backend, buildx ends every non-quiet build with
// "View build details: docker-desktop://…" — a link that opens an app k3sm does
// not use and cannot be reached by any hint variable: buildx v0.17.1 calls
// desktop.PrintBuildDetails unconditionally (commands/build.go, the default arm
// of the progressMode switch), gated only on desktop.BuildBackendEnabled(),
// which is
//
//	home, err := os.UserHomeDir()        // util/desktop/desktop.go:21-26
//	_, err = os.Stat(filepath.Join(home, ".docker", "desktop-build", ".lastaccess"))
//
// That path is rooted in os.UserHomeDir() LITERALLY, not in docker/cli's
// config.Dir(), so DOCKER_CONFIG cannot move it and pointing DOCKER_CONFIG
// somewhere clean suppresses nothing. DOCKER_CLI_HINTS reaches only docker/cli's
// HooksEnabled(), which buildx v0.17.1 never calls. os.UserHomeDir() on darwin
// is exactly os.Getenv("HOME"), so the one lever that works is HOME — and the
// user's credentials are handed back by DOCKER_CONFIG, whose derivation
// (docker/cli cli/config/config.go Dir(): $DOCKER_CONFIG, else $HOME/.docker) is
// reproduced here from the CALLER's environment before HOME is replaced. An
// inherited DOCKER_CONFIG is kept verbatim; auths, credsStore, credHelpers,
// contexts and the config file's other keys are read from the same directory
// they were before. A config directory that does not exist, or one with no
// config.json, is valid: docker/cli loads an empty config for it.
//
// WHAT ELSE THE REDIRECT MOVES, audited against the buildx v0.17.1 tree for the
// path k3sm drives (a local build context, the remote driver over tcp):
//
//   - docker/cli config.Dir() (cli/config/config.go) — the credentials, contexts
//     and .token_seed. Pinned by DOCKER_CONFIG above; unmoved.
//   - buildx's own store (util/confutil ConfigDir) — $BUILDX_CONFIG wins over
//     the config dir, and it is set here; unmoved.
//   - git, shelled out by util/gitutil with cmd.Env = os.Environ() to stamp
//     vcs provenance on a local context. It loses ~/.gitconfig. Verified not to
//     matter for what buildx asks it: every call is a read (rev-parse, remote
//     get-url, show --format, symbolic-ref, for-each-ref) and git's
//     dubious-ownership check exempts a sudo invocation by SUDO_UID rather than
//     by anything in HOME — confirmed on this repo, where rev-parse under sudo
//     answers the same with HOME redirected. Losing the global config cannot
//     change a commit sha.
//   - driver/kubernetes/context/load.go reads ~/.kube/config, but only for the
//     kubernetes driver. k3sm registers the remote driver and injects its own
//     --builder, and the k3sm BUILDX_CONFIG store holds no other instance, so
//     the kubernetes loader is unreachable from here.
//   - buildkit's appdefaults HOME paths are the rootless local-daemon address,
//     used only when the client address is empty. The remote driver always
//     supplies tcp://<endpoint>.
//   - RESIDUAL, accepted: `--cache-to/from type=s3` resolves AWS credentials
//     through the aws-sdk shared-config files under ~/.aws (util/buildflags
//     addAwsCredentials), and `bake` of a compose file expands a leading ~/ in
//     compose paths (compose-go paths.ExpandUser). Both follow the new HOME. A
//     user who needs either sets the SDK's own AWS_SHARED_CREDENTIALS_FILE /
//     AWS_CONFIG_FILE, or writes an absolute path. Neither is a registry
//     credential, so --push is unaffected.
//
// The rejected alternatives were filtering buildx's stderr (which carries the
// build's own progress UI) and patching the pinned binary (a fork to maintain
// for one line of output).
func BuildxEnv(base []string, cfgDir string) []string {
	dockerCfg := dockerConfigDir(base)
	out := make([]string, 0, len(base)+3)
	for _, kv := range base {
		// Every copy is dropped, not just the last: execve keeps duplicates and
		// getenv answers with the FIRST match, so a surviving inherited entry
		// would beat the one appended below.
		if hasEnvKey(kv, "BUILDX_CONFIG") || hasEnvKey(kv, "HOME") || hasEnvKey(kv, "DOCKER_CONFIG") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "BUILDX_CONFIG="+cfgDir, "HOME="+HostHomeDir(cfgDir))
	if dockerCfg != "" {
		out = append(out, "DOCKER_CONFIG="+dockerCfg)
	}
	return out
}

// dockerConfigDir reproduces docker/cli's config.Dir() over base: $DOCKER_CONFIG
// when set, else $HOME/.docker. It returns "" when base names neither, in which
// case BuildxEnv sets nothing and buildx falls back to the k3sm-owned HOME —
// there were no credentials to preserve.
func dockerConfigDir(base []string) string {
	if v := envValue(base, "DOCKER_CONFIG"); v != "" {
		return v
	}
	if home := envValue(base, "HOME"); home != "" {
		return filepath.Join(home, ".docker")
	}
	return ""
}

// envValue returns the value key takes in an environment slice, using getenv's
// first-match rule so a duplicated key resolves the way the child would see it.
func envValue(env []string, key string) string {
	for _, kv := range env {
		if hasEnvKey(kv, key) {
			return kv[len(key)+1:]
		}
	}
	return ""
}

// hasEnvKey reports whether the "K=V" entry kv names key.
func hasEnvKey(kv, key string) bool {
	return len(kv) > len(key) && kv[len(key)] == '=' && kv[:len(key)] == key
}

// BuildxArgs assembles the argv for a passthrough run: `--builder <instance>`
// followed by the user's arguments VERBATIM.
//
// k3sm parses nothing after `k3sm builder buildx` — the argv belongs to buildx,
// and a wrapper that re-interpreted flags would break every option it had not
// heard of. The injected flag is buildx's global one, so it binds whatever
// subcommand follows (build, bake, imagetools, …); a user who passes their own
// --builder later wins, because a repeated flag takes its last value.
func BuildxArgs(userArgs []string) []string {
	args := make([]string, 0, len(userArgs)+2)
	args = append(args, "--builder", BuilderInstanceName)
	return append(args, userArgs...)
}

// RunBuildx execs bin with args and env, inheriting stdio so buildx's own
// progress UI renders and an interactive build behaves as it would standalone.
// A non-zero exit is returned as an *exec.ExitError (wrapped), so the caller can
// forward buildx's exit code instead of flattening it to 1.
func RunBuildx(ctx context.Context, bin string, args, env []string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec buildx: %w", err)
	}
	return nil
}

// buildxRunner runs one buildx subcommand and returns its combined output. It is
// the seam the instance management is tested through — the instance logic is a
// decision over buildx's own answers, and those answers are cheap to fake and
// expensive to obtain for real.
type buildxRunner func(ctx context.Context, args ...string) (string, error)

// EnsureBuilderInstance makes the k3sm buildx instance in cfgDir name endpoint,
// creating it when absent and REPAIRING it when the endpoint has moved (the
// engine's ClusterIP changes across a `k3sm builder delete` + `up`). buildx
// refuses to redefine an existing instance, so a repair is a remove followed by
// a create.
func EnsureBuilderInstance(ctx context.Context, bin, cfgDir, endpoint string) error {
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return fmt.Errorf("create buildx config dir %s: %w", cfgDir, err)
	}
	// The redirected HOME is created, not merely named: buildx and the tools it
	// shells out to may write into it, and a HOME that does not exist turns a
	// write into a failure the operator cannot place.
	home := HostHomeDir(cfgDir)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("create buildx home dir %s: %w", home, err)
	}
	return ensureBuilderInstance(ctx, hostRunner(bin, BuildxEnv(os.Environ(), cfgDir)), endpoint)
}

// hostRunner is the real buildxRunner: it execs bin with env and captures both
// streams, because buildx reports "no builder … found" on stderr and the state
// decision needs to read it.
func hostRunner(bin string, env []string) buildxRunner {
	return func(ctx context.Context, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
}

// ensureBuilderInstance is the pure decision over a buildxRunner.
func ensureBuilderInstance(ctx context.Context, run buildxRunner, endpoint string) error {
	out, err := run(ctx, "inspect", BuilderInstanceName)
	if err == nil {
		if instanceMatches(out, endpoint) {
			return nil
		}
		// The endpoint moved. buildx errors on a create for an existing name, so
		// the stale record goes first.
		if rmOut, rmErr := run(ctx, "rm", BuilderInstanceName); rmErr != nil {
			return fmt.Errorf("remove stale buildx builder %q: %w: %s", BuilderInstanceName, rmErr, strings.TrimSpace(rmOut))
		}
		return createInstance(ctx, run, endpoint)
	}

	// inspect failed. The ordinary cause is an absent instance, so create.
	createErr := createInstance(ctx, run, endpoint)
	if createErr == nil {
		return nil
	}
	// A create that is refused while inspect could not read the record means a
	// remnant exists that is not usable. Drop it and try once more; if that
	// still fails, the first error is the honest one to report.
	if _, rmErr := run(ctx, "rm", BuilderInstanceName); rmErr != nil {
		return createErr
	}
	if retryErr := createInstance(ctx, run, endpoint); retryErr != nil {
		return createErr
	}
	return nil
}

// createInstance registers the k3sm builder against endpoint with the remote
// driver — the driver that dials a buildkitd tcp listener directly, which is
// what the engine's ClusterIP Service fronts.
func createInstance(ctx context.Context, run buildxRunner, endpoint string) error {
	out, err := run(ctx, "create", "--name", BuilderInstanceName, "--driver", "remote", endpoint)
	if err != nil {
		return fmt.Errorf("create buildx builder %q at %s: %w: %s", BuilderInstanceName, endpoint, err, strings.TrimSpace(out))
	}
	return nil
}

// instanceMatches reports whether `buildx inspect` output describes exactly the
// wanted endpoint. Exactly: an instance carrying any other node is stale or
// hand-edited, and rebuilding it is cheap, so anything but the single expected
// node is treated as a repair rather than trusted.
func instanceMatches(inspectOut, endpoint string) bool {
	eps := instanceEndpoints(inspectOut)
	return len(eps) == 1 && eps[0] == endpoint
}

// instanceEndpoints extracts the node endpoints from `buildx inspect` output,
// whose node block prints one "Endpoint: <addr>" line per node.
func instanceEndpoints(inspectOut string) []string {
	var eps []string
	for _, line := range strings.Split(inspectOut, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Endpoint:")
		if !ok {
			continue
		}
		if ep := strings.TrimSpace(rest); ep != "" {
			eps = append(eps, ep)
		}
	}
	return eps
}
