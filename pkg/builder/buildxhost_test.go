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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostBuildxPinIsWellFormed pins the compiled-in HOST buildx pin: it must
// validate, name the shared release tag, and be the darwin/arm64 asset — a host
// pin that named the guest asset would download a Linux ELF onto a Mac.
func TestHostBuildxPinIsWellFormed(t *testing.T) {
	t.Run("compiled_pin_validates", func(t *testing.T) {
		if err := ValidateHostBuildxPin(); err != nil {
			t.Fatalf("compiled host buildx pin is invalid: %v", err)
		}
	})
	t.Run("asset_is_host_arch_darwin_arm64", func(t *testing.T) {
		if !strings.HasSuffix(HostBuildxAsset, ".darwin-arm64") {
			t.Errorf("HostBuildxAsset=%q must be darwin-arm64 (the host drives the engine)", HostBuildxAsset)
		}
	})
	t.Run("shares_the_release_tag_with_the_guest_pin", func(t *testing.T) {
		if !strings.Contains(HostBuildxAsset, BuildxVersion) || !strings.Contains(BuildxAsset, BuildxVersion) {
			t.Errorf("host %q and guest %q must both name version %q", HostBuildxAsset, BuildxAsset, BuildxVersion)
		}
	})
	t.Run("host_and_guest_digests_differ", func(t *testing.T) {
		// Same tag, different arch, so the same digest would mean one of the two
		// pins was copied from the other rather than recorded.
		if HostBuildxSHA256 == BuildxSHA256 {
			t.Errorf("host and guest pins share a digest %q — one was copied, not recorded", HostBuildxSHA256)
		}
	})
	t.Run("url_names_version_and_asset", func(t *testing.T) {
		u := HostBuildxURL()
		if !strings.Contains(u, BuildxVersion) || !strings.HasSuffix(u, HostBuildxAsset) {
			t.Errorf("HostBuildxURL()=%q does not name version %q and asset %q", u, BuildxVersion, HostBuildxAsset)
		}
	})
}

// serveBytes starts a test server handing out body at /asset and returns its URL
// and the body's sha256.
func serveBytes(t *testing.T, body []byte) (string, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	return srv.URL + "/asset", hex.EncodeToString(sum[:])
}

// TestEnsureVerifiedBinary covers the fetch-and-verify contract: a matching
// digest installs an executable binary, a mismatch refuses and leaves NOTHING
// behind, a good cache is reused without a fetch, and a corrupted cache is
// replaced.
func TestEnsureVerifiedBinary(t *testing.T) {
	ctx := context.Background()

	t.Run("verified download installs an executable", func(t *testing.T) {
		url, sum := serveBytes(t, []byte("the pinned buildx bytes"))
		path := filepath.Join(t.TempDir(), "bin", "buildx-v0.17.1")
		if err := ensureVerifiedBinary(ctx, path, url, sum); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat installed binary: %v", err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("installed binary is not executable: mode %v", fi.Mode())
		}
	})

	t.Run("digest mismatch refuses and installs nothing", func(t *testing.T) {
		url, _ := serveBytes(t, []byte("bytes that are not the pinned release"))
		dir := t.TempDir()
		path := filepath.Join(dir, "buildx-v0.17.1")
		want := strings.Repeat("a", 64)
		err := ensureVerifiedBinary(ctx, path, url, want)
		if err == nil {
			t.Fatal("expected a refusal for a digest mismatch")
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name the wanted digest: %v", err)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("unverified bytes were installed at %s", path)
		}
		// Nor may a staged temp file survive the refusal.
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		if len(ents) != 0 {
			t.Errorf("refusal left %d file(s) behind: %v", len(ents), ents)
		}
	})

	t.Run("a verified cache is reused without a fetch", func(t *testing.T) {
		body := []byte("the pinned buildx bytes")
		sum := sha256.Sum256(body)
		path := filepath.Join(t.TempDir(), "buildx-v0.17.1")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("seed cache: %v", err)
		}
		// An unreachable URL proves no fetch happened.
		if err := ensureVerifiedBinary(ctx, path, "http://127.0.0.1:1/asset", hex.EncodeToString(sum[:])); err != nil {
			t.Fatalf("ensure over a good cache: %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("cached binary was not made executable: mode %v", fi.Mode())
		}
	})

	t.Run("a corrupted cache is replaced by the verified bytes", func(t *testing.T) {
		body := []byte("the pinned buildx bytes")
		url, sum := serveBytes(t, body)
		path := filepath.Join(t.TempDir(), "buildx-v0.17.1")
		if err := os.WriteFile(path, []byte("truncated"), 0o755); err != nil {
			t.Fatalf("seed cache: %v", err)
		}
		if err := ensureVerifiedBinary(ctx, path, url, sum); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != string(body) {
			t.Errorf("cache was not replaced: %q", got)
		}
	})

	t.Run("a non-200 response refuses", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "gone", http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)
		path := filepath.Join(t.TempDir(), "buildx-v0.17.1")
		if err := ensureVerifiedBinary(ctx, path, srv.URL, strings.Repeat("b", 64)); err == nil {
			t.Fatal("expected an error for a 404")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("a 404 installed something at %s", path)
		}
	})
}

// fakeBuildx records buildx invocations and answers them from a scripted table.
type fakeBuildx struct {
	calls   [][]string
	inspect string
	// inspectErr is what `inspect` returns; a non-nil value models an absent
	// instance (buildx exits 1 with `no builder "k3sm" found`).
	inspectErr error
	createErr  error
	rmErr      error
	// createErrOnce, when set, fails only the FIRST create.
	createErrOnce error
	creates       int
}

func (f *fakeBuildx) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	switch args[0] {
	case "inspect":
		return f.inspect, f.inspectErr
	case "rm":
		return "", f.rmErr
	case "create":
		f.creates++
		if f.creates == 1 && f.createErrOnce != nil {
			return "", f.createErrOnce
		}
		return "", f.createErr
	}
	return "", nil
}

// verbs returns the buildx subcommand of each recorded call, in order.
func (f *fakeBuildx) verbs() string {
	var vs []string
	for _, c := range f.calls {
		vs = append(vs, c[0])
	}
	return strings.Join(vs, ",")
}

// TestEnsureBuilderInstance pins the create/repair decision over a faked buildx.
func TestEnsureBuilderInstance(t *testing.T) {
	const ep = "tcp://10.43.0.5:1234"
	inspectAt := func(addr string) string {
		return "Name:   k3sm\nDriver: remote\n\nNodes:\nName:     k3sm0\nEndpoint: " + addr + "\nStatus:   inactive\n"
	}

	t.Run("absent instance is created", func(t *testing.T) {
		f := &fakeBuildx{inspectErr: errors.New(`no builder "k3sm" found`)}
		if err := ensureBuilderInstance(context.Background(), f.run, ep); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if f.verbs() != "inspect,create" {
			t.Fatalf("calls = %s, want inspect,create", f.verbs())
		}
		got := strings.Join(f.calls[1], " ")
		want := "create --name k3sm --driver remote " + ep
		if got != want {
			t.Errorf("create argv = %q, want %q", got, want)
		}
	})

	t.Run("a matching instance is left alone", func(t *testing.T) {
		f := &fakeBuildx{inspect: inspectAt(ep)}
		if err := ensureBuilderInstance(context.Background(), f.run, ep); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if f.verbs() != "inspect" {
			t.Errorf("a healthy instance was disturbed: calls = %s", f.verbs())
		}
	})

	t.Run("endpoint drift is repaired by rm then create", func(t *testing.T) {
		f := &fakeBuildx{inspect: inspectAt("tcp://10.43.0.9:1234")}
		if err := ensureBuilderInstance(context.Background(), f.run, ep); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if f.verbs() != "inspect,rm,create" {
			t.Fatalf("calls = %s, want inspect,rm,create", f.verbs())
		}
		if last := f.calls[2]; last[len(last)-1] != ep {
			t.Errorf("recreate did not use the new endpoint: %v", last)
		}
	})

	t.Run("a failed rm during a repair is reported", func(t *testing.T) {
		f := &fakeBuildx{inspect: inspectAt("tcp://10.43.0.9:1234"), rmErr: errors.New("permission denied")}
		err := ensureBuilderInstance(context.Background(), f.run, ep)
		if err == nil {
			t.Fatal("expected the rm failure to surface")
		}
		if !strings.Contains(err.Error(), "k3sm") {
			t.Errorf("error does not name the builder: %v", err)
		}
	})

	t.Run("an unreadable remnant is dropped and recreated", func(t *testing.T) {
		f := &fakeBuildx{
			inspectErr:    errors.New("failed to find driver"),
			createErrOnce: errors.New(`existing instance for "k3sm" but no append mode`),
		}
		if err := ensureBuilderInstance(context.Background(), f.run, ep); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if f.verbs() != "inspect,create,rm,create" {
			t.Errorf("calls = %s, want inspect,create,rm,create", f.verbs())
		}
	})

	t.Run("a create that cannot succeed reports the first failure", func(t *testing.T) {
		f := &fakeBuildx{inspectErr: errors.New("absent"), createErr: errors.New("driver remote unavailable")}
		err := ensureBuilderInstance(context.Background(), f.run, ep)
		if err == nil {
			t.Fatal("expected the create failure to surface")
		}
		if !strings.Contains(err.Error(), "driver remote unavailable") {
			t.Errorf("error lost the buildx cause: %v", err)
		}
	})
}

// TestInstanceEndpoints pins the inspect-output parse the repair decision reads.
func TestInstanceEndpoints(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []string
	}{
		{"one node", "Nodes:\nName:     k3sm0\nEndpoint: tcp://10.43.0.5:1234\n", []string{"tcp://10.43.0.5:1234"}},
		{"indented", "Nodes:\n  Endpoint:   tcp://10.43.0.5:1234  \n", []string{"tcp://10.43.0.5:1234"}},
		{"two nodes", "Endpoint: tcp://a:1\nEndpoint: tcp://b:2\n", []string{"tcp://a:1", "tcp://b:2"}},
		{"none", "ERROR: no builder \"k3sm\" found\n", nil},
		{"empty value", "Endpoint:\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := instanceEndpoints(tc.out)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("instanceEndpoints = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("a two-node instance never matches", func(t *testing.T) {
		if instanceMatches("Endpoint: tcp://a:1\nEndpoint: tcp://b:2\n", "tcp://a:1") {
			t.Error("an instance carrying a second node was accepted as healthy")
		}
	})
}

// TestBuildxArgsPassThrough pins the passthrough contract: --builder is injected
// ahead of the user's argv, and nothing about that argv is rewritten.
func TestBuildxArgsPassThrough(t *testing.T) {
	user := []string{"build", "-t", "myapp:dev", "--build-arg", "X=--builder", "--output", "type=oci,dest=out.oci", "."}
	got := BuildxArgs(user)

	if got[0] != "--builder" || got[1] != BuilderInstanceName {
		t.Fatalf("argv does not start with the injected builder: %v", got[:2])
	}
	if len(got) != len(user)+2 {
		t.Fatalf("argv length = %d, want %d — the wrapper added or dropped arguments", len(got), len(user)+2)
	}
	for i, a := range user {
		if got[i+2] != a {
			t.Errorf("user arg %d rewritten: got %q, want %q", i, got[i+2], a)
		}
	}

	t.Run("the caller's slice is not aliased", func(t *testing.T) {
		src := []string{"build", "."}
		out := BuildxArgs(src)
		out[2] = "bake"
		if src[0] != "build" {
			t.Errorf("BuildxArgs wrote through to the caller's slice: %v", src)
		}
	})

	t.Run("no args still yields a well-formed prefix", func(t *testing.T) {
		out := BuildxArgs(nil)
		if len(out) != 2 || out[0] != "--builder" {
			t.Errorf("BuildxArgs(nil) = %v", out)
		}
	})
}

// TestBuildxEnvForcesConfigDir pins that BUILDX_CONFIG is the k3sm-owned store,
// that an inherited value cannot win, and that the rest of the caller's
// environment rides through untouched.
func TestBuildxEnvForcesConfigDir(t *testing.T) {
	const cfgDir = "/var/lib/k3sm/server/buildx"

	t.Run("the k3sm store wins over an inherited one", func(t *testing.T) {
		env := BuildxEnv([]string{"PATH=/usr/bin", "BUILDX_CONFIG=/Users/dev/.docker/buildx"}, cfgDir)
		assertEnv(t, env, map[string]string{"BUILDX_CONFIG": cfgDir, "PATH": "/usr/bin"})
		if n := countEnv(env, "BUILDX_CONFIG"); n != 1 {
			t.Errorf("BUILDX_CONFIG appears %d times, want exactly 1: %v", n, env)
		}
	})

	t.Run("a key that merely starts with the name is left alone", func(t *testing.T) {
		env := BuildxEnv([]string{"BUILDX_CONFIG_X=y", "HOMEBREW_PREFIX=/opt/homebrew"}, cfgDir)
		assertEnv(t, env, map[string]string{"BUILDX_CONFIG_X": "y", "HOMEBREW_PREFIX": "/opt/homebrew"})
	})
}

// TestBuildxEnvSuppressesTheDesktopLink pins the other half of the buildx
// environment: HOME moved to a k3sm-owned directory (which is what keeps buildx
// from finding Docker Desktop's build-backend marker and ending every build with
// a docker-desktop:// link) and DOCKER_CONFIG pinned to the config directory the
// CALLER's environment resolved to, which is what hands the user's registry
// credentials back after HOME has moved. Neither half is optional: without the
// redirect the link prints, without the pin a --push is 401.
func TestBuildxEnvSuppressesTheDesktopLink(t *testing.T) {
	const cfgDir = "/var/lib/k3sm/server/buildx"
	home := HostHomeDir(cfgDir)

	t.Run("the k3sm home is inside the k3sm store and is not the user's", func(t *testing.T) {
		if got, want := home, filepath.Join(cfgDir, "home"); got != want {
			t.Errorf("HostHomeDir = %q, want %q", got, want)
		}
	})

	t.Run("HOME is redirected and DOCKER_CONFIG derived from the caller's", func(t *testing.T) {
		env := BuildxEnv([]string{"PATH=/usr/bin", "HOME=/Users/dev"}, cfgDir)
		assertEnv(t, env, map[string]string{
			"HOME":          home,
			"DOCKER_CONFIG": "/Users/dev/.docker",
			"PATH":          "/usr/bin",
		})
	})

	t.Run("an inherited DOCKER_CONFIG wins over the derivation", func(t *testing.T) {
		// docker/cli's config.Dir() prefers $DOCKER_CONFIG over $HOME/.docker, so
		// reproducing that order is what makes a user's explicit choice survive.
		env := BuildxEnv([]string{"HOME=/Users/dev", "DOCKER_CONFIG=/etc/docker-cfg"}, cfgDir)
		assertEnv(t, env, map[string]string{"DOCKER_CONFIG": "/etc/docker-cfg", "HOME": home})
	})

	t.Run("a config dir with no config.json is still pinned", func(t *testing.T) {
		// docker/cli loads an empty config for a directory that holds no
		// config.json, so an absent user config is not a reason to leave
		// DOCKER_CONFIG unset and let it re-derive from the k3sm HOME.
		dir := t.TempDir()
		env := BuildxEnv([]string{"HOME=" + dir}, cfgDir)
		assertEnv(t, env, map[string]string{"DOCKER_CONFIG": filepath.Join(dir, ".docker")})
	})

	t.Run("a symlinked config dir is pinned by the path, not resolved", func(t *testing.T) {
		// The value is handed to buildx verbatim; resolving it here would defeat
		// a user who symlinks ~/.docker at a credential store on another volume.
		real := filepath.Join(t.TempDir(), "real-docker")
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "link-docker")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		env := BuildxEnv([]string{"DOCKER_CONFIG=" + link}, cfgDir)
		assertEnv(t, env, map[string]string{"DOCKER_CONFIG": link})
	})

	t.Run("no HOME and no DOCKER_CONFIG leaves DOCKER_CONFIG unset", func(t *testing.T) {
		// There were no credentials to preserve, and inventing a path would point
		// buildx at a directory nobody has written.
		env := BuildxEnv([]string{"PATH=/usr/bin"}, cfgDir)
		if n := countEnv(env, "DOCKER_CONFIG"); n != 0 {
			t.Errorf("DOCKER_CONFIG was set with nothing to derive it from: %v", env)
		}
		assertEnv(t, env, map[string]string{"HOME": home})
	})

	t.Run("every inherited copy is dropped, not just the last", func(t *testing.T) {
		// execve keeps duplicate keys and getenv answers with the FIRST match, so
		// a surviving inherited entry would beat the one appended.
		base := []string{
			"HOME=/Users/dev",
			"DOCKER_CONFIG=/Users/dev/.docker",
			"HOME=/Users/dev",
			"DOCKER_CONFIG=/tmp/other",
		}
		env := BuildxEnv(base, cfgDir)
		for _, key := range []string{"HOME", "DOCKER_CONFIG"} {
			if n := countEnv(env, key); n != 1 {
				t.Errorf("%s appears %d times, want exactly 1: %v", key, n, env)
			}
		}
		assertEnv(t, env, map[string]string{"HOME": home, "DOCKER_CONFIG": "/Users/dev/.docker"})
	})
}

// assertEnv checks that env resolves each wanted key to its wanted value, using
// getenv's first-match rule.
func assertEnv(t *testing.T, env []string, want map[string]string) {
	t.Helper()
	for key, val := range want {
		got := ""
		for _, kv := range env {
			if strings.HasPrefix(kv, key+"=") {
				got = strings.TrimPrefix(kv, key+"=")
				break
			}
		}
		if got != val {
			t.Errorf("%s = %q, want %q", key, got, val)
		}
	}
}

// countEnv counts the entries in env naming key.
func countEnv(env []string, key string) int {
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			n++
		}
	}
	return n
}

// TestHostPathsAreVersioned pins the cache layout: the binary name carries the
// pinned version (a bump downloads beside the old copy rather than reusing it),
// and the config dir is k3sm-owned rather than the user's buildx store.
func TestHostPathsAreVersioned(t *testing.T) {
	if !strings.HasSuffix(HostBuildxPath("/w/bin"), "buildx-"+BuildxVersion) {
		t.Errorf("HostBuildxPath = %q, want a version-suffixed name", HostBuildxPath("/w/bin"))
	}
	if got := HostConfigDir("/w"); got != filepath.Join("/w", "buildx") {
		t.Errorf("HostConfigDir = %q", got)
	}
}
