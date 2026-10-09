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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor/etcdchild"
)

// envLast returns the LAST assignment of key in env — the value a child process sees.
func envLast(env []string, key string) (string, bool) {
	v, ok := "", false
	for _, kv := range env {
		if name, val, found := strings.Cut(kv, "="); found && name == key {
			v, ok = val, true
		}
	}
	return v, ok
}

// TestEtcdBuildEnvNoCgoOutOfModule pins how the etcd child is built: pure Go, outside
// k3sm's module and workspace, against the committed lockfile only, with the local
// compiler — and that each of those holds even when the ambient environment says the
// opposite, because the daemon and the release stage inherit whatever shell ran them.
func TestEtcdBuildEnvNoCgoOutOfModule(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("GOWORK", "/somewhere/go.work")
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOMODCACHE", "/ambient/modcache")

	cache := t.TempDir()
	origCache, origBuild := kineModuleCacheDir, runEtcdBuild
	t.Cleanup(func() { kineModuleCacheDir, runEtcdBuild = origCache, origBuild })
	kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }

	var got *exec.Cmd
	runEtcdBuild = func(cmd *exec.Cmd) ([]byte, error) {
		got = cmd
		// The wrapper must be fully materialized where the build runs.
		for _, f := range []string{"go.mod", "go.sum", "main.go"} {
			if _, err := os.Stat(filepath.Join(cmd.Dir, f)); err != nil {
				t.Errorf("wrapper %s not materialized in the build dir: %v", f, err)
			}
		}
		out := cmd.Args[slices.Index(cmd.Args, "-o")+1]
		return nil, os.WriteFile(out, []byte("pretend-etcd"), 0o755)
	}

	bd := t.TempDir()
	if err := ensureEtcdInto(t.Context(), bd, DefaultEtcdVersion); err != nil {
		t.Fatalf("ensureEtcdInto = %v", err)
	}
	if got == nil {
		t.Fatal("the etcd build never ran")
	}

	for _, want := range []struct{ key, val string }{
		{"CGO_ENABLED", "0"},
		{"GOWORK", "off"},
		{"GOFLAGS", "-mod=readonly"},
		{"GOTOOLCHAIN", "local"},
		{"GOMODCACHE", cache},
		{"GOBIN", ""},
	} {
		if v, ok := envLast(got.Env, want.key); !ok || v != want.val {
			t.Errorf("build env %s = %q (set=%v), want %q over the ambient value", want.key, v, ok, want.val)
		}
	}
	if gp, _ := envLast(got.Env, "GOPATH"); gp == "" || strings.HasPrefix(cache, gp) {
		t.Errorf("GOPATH = %q, want a per-build scratch dir distinct from the cache %q", gp, cache)
	}
	if !slices.Equal(got.Args[1:3], []string{"build", "-trimpath"}) ||
		!slices.Contains(got.Args, "-buildvcs=false") || !slices.Contains(got.Args, "-mod=readonly") {
		t.Errorf("build argv = %q, want `go build -trimpath -buildvcs=false -mod=readonly ...`", got.Args)
	}
	if b, err := os.ReadFile(filepath.Join(bd, EtcdMarkerName)); err != nil || string(b) != "v3.6.15 nocgo\n" {
		t.Errorf("etcd marker = %q (%v), want %q", b, err, "v3.6.15 nocgo\n")
	}
	if b, _ := os.ReadFile(filepath.Join(bd, "etcd")); string(b) != "pretend-etcd" {
		t.Errorf("staged etcd = %q, want the built bytes", b)
	}

	t.Run("an unpinned version is refused before anything is touched", func(t *testing.T) {
		runEtcdBuild = func(*exec.Cmd) ([]byte, error) {
			t.Error("built an etcd version the wrapper does not pin")
			return nil, errors.New("unreachable")
		}
		bd := t.TempDir()
		if err := os.WriteFile(filepath.Join(bd, EtcdMarkerName), []byte("v3.6.14 nocgo\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureEtcdInto(t.Context(), bd, "v3.7.0"); !errors.Is(err, ErrEtcdVersionUnpinned) {
			t.Fatalf("ensureEtcdInto(v3.7.0) = %v, want ErrEtcdVersionUnpinned", err)
		}
		if _, err := os.Stat(filepath.Join(bd, EtcdMarkerName)); err != nil {
			t.Error("the refusal dropped the existing marker")
		}
	})
}

// TestEtcdutlBuiltFromTheWrapper: etcdutl is staged under the stagedChild protocol
// from the SAME materialized wrapper, building upstream's etcdutl main package (the
// module's tool) with the etcd build's argv, and gets its own marker.
func TestEtcdutlBuiltFromTheWrapper(t *testing.T) {
	cache := t.TempDir()
	origCache, origBuild := kineModuleCacheDir, runEtcdBuild
	t.Cleanup(func() { kineModuleCacheDir, runEtcdBuild = origCache, origBuild })
	kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }
	var got *exec.Cmd
	runEtcdBuild = func(cmd *exec.Cmd) ([]byte, error) {
		got = cmd
		if b, err := os.ReadFile(filepath.Join(cmd.Dir, "go.mod")); err != nil || string(b) != string(etcdchild.GoMod) {
			t.Errorf("the build dir does not hold the embedded wrapper go.mod (%v)", err)
		}
		out := cmd.Args[slices.Index(cmd.Args, "-o")+1]
		return nil, os.WriteFile(out, []byte("pretend-etcdutl"), 0o755)
	}
	bd := t.TempDir()
	if err := ensureEtcdutlInto(t.Context(), bd, DefaultEtcdVersion); err != nil {
		t.Fatalf("ensureEtcdutlInto = %v", err)
	}
	if got == nil || got.Args[len(got.Args)-1] != etcdutlPackage || !slices.Contains(got.Args, "-mod=readonly") {
		t.Fatalf("build argv = %v, want `go build ... -mod=readonly -o <bin> %s`", got, etcdutlPackage)
	}
	if v, _ := envLast(got.Env, "GOWORK"); v != "off" {
		t.Errorf("GOWORK = %q, want off", v)
	}
	if b, err := os.ReadFile(filepath.Join(bd, EtcdutlMarkerName)); err != nil || string(b) != DefaultEtcdVersion+" nocgo\n" {
		t.Errorf("etcdutl marker = %q (%v)", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(bd, etcdutlBinaryName)); string(b) != "pretend-etcdutl" {
		t.Errorf("staged etcdutl = %q, want the built bytes", b)
	}
	if err := ensureEtcdutlInto(t.Context(), t.TempDir(), "v3.7.0"); !errors.Is(err, ErrEtcdVersionUnpinned) {
		t.Errorf("ensureEtcdutlInto(v3.7.0) = %v, want ErrEtcdVersionUnpinned", err)
	}
}

// TestDefaultEtcdVersionMatchesWrapper keeps the Go pin and the embedded wrapper in
// lockstep: a DefaultEtcdVersion bump without a regenerated wrapper (or the reverse)
// would build one version and stamp the marker with another. Both programs the
// wrapper builds, the etcd server and the etcdutl that restores its snapshots, must
// sit at that one pin, and etcdutl must be the module's declared tool (the only way
// it is built from the server's own module graph).
func TestDefaultEtcdVersionMatchesWrapper(t *testing.T) {
	mod := string(etcdchild.GoMod)
	for _, m := range []string{"go.etcd.io/etcd/server/v3", etcdutlPackage} {
		req := regexp.MustCompile(`(?m)^\s*(?:require\s+)?`+regexp.QuoteMeta(m)+` (\S+)(?:\s*// indirect)?\s*$`).FindAllStringSubmatch(mod, -1)
		if len(req) != 1 || req[0][1] != DefaultEtcdVersion {
			t.Errorf("go.mod.txt requires %s at %v, want exactly %s once", m, req, DefaultEtcdVersion)
		}
	}
	if !regexp.MustCompile(`(?m)^tool ` + regexp.QuoteMeta(etcdutlPackage) + `$`).MatchString(mod) {
		t.Errorf("go.mod.txt does not declare `tool %s`", etcdutlPackage)
	}
	if etcdChild(DefaultEtcdVersion).markerContent() != etcdutlChild(DefaultEtcdVersion).markerContent() {
		t.Error("the etcd and etcdutl markers vouch for different (version, variant) pairs")
	}
	if !regexp.MustCompile(`(?m)^module k3sm\.io/etcd-child$`).MatchString(mod) {
		t.Error("go.mod.txt does not declare module k3sm.io/etcd-child")
	}
	if !regexp.MustCompile(`(?m)^go 1\.\d+(\.\d+)?$`).MatchString(mod) {
		t.Error("go.mod.txt carries no go line")
	}
	// The minimum toolchain is either an explicit toolchain line or a go line that
	// names a patch release: Go drops a toolchain line equal to the go line, which
	// is what a dependency asking for go1.N.P produces.
	if !regexp.MustCompile(`(?m)^toolchain go1\.\d+\.\d+$`).MatchString(mod) &&
		!regexp.MustCompile(`(?m)^go 1\.\d+\.\d+$`).MatchString(mod) {
		t.Error("go.mod.txt names no minimum toolchain (a toolchain line, or a go line with a patch release)")
	}
	if strings.Contains(mod, "\nreplace") {
		t.Error("go.mod.txt carries a replace directive; the wrapper must build the upstream module as published")
	}
	sum := string(etcdchild.GoSum)
	for _, want := range []string{
		"go.etcd.io/etcd/server/v3 " + DefaultEtcdVersion + " h1:",
		"go.etcd.io/etcd/server/v3 " + DefaultEtcdVersion + "/go.mod h1:",
		etcdutlPackage + " " + DefaultEtcdVersion + " h1:",
		etcdutlPackage + " " + DefaultEtcdVersion + "/go.mod h1:",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("go.sum.txt has no %q line", want)
		}
	}
	if !strings.Contains(string(etcdchild.MainGo), "etcdmain.Main(os.Args)") {
		t.Error("main.go.txt does not call etcdmain.Main(os.Args)")
	}
}

// TestPayloadSetIncludesEtcd: etcd ships in every payload, so a packaged install (no Go
// toolchain) can run it, and the set check admits its marker while still refusing
// anything else riding along.
func TestPayloadSetIncludesEtcd(t *testing.T) {
	for _, want := range []string{"etcd", "etcdutl"} {
		if !slices.Contains(PayloadBinaries(), want) {
			t.Fatalf("PayloadBinaries() = %v, want it to include %s", PayloadBinaries(), want)
		}
	}
	dir := t.TempDir()
	for _, name := range append(PayloadBinaries(), KineMarkerName, EtcdMarkerName, EtcdutlMarkerName, KubeMarkerName) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyPayloadSet(dir); err != nil {
		t.Fatalf("VerifyPayloadSet with etcd + %s = %v, want nil", EtcdMarkerName, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etcdctl"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPayloadSet(dir); !errors.Is(err, ErrPayloadDigestMismatch) {
		t.Errorf("VerifyPayloadSet with an extra file = %v, want ErrPayloadDigestMismatch", err)
	}
	// etcdutl is run from the payload by `k3sm snapshot restore`, never by the
	// daemon, so no posture's work-dir seed copies it.
	work := t.TempDir()
	if err := os.Remove(filepath.Join(dir, "etcdctl")); err != nil {
		t.Fatal(err)
	}
	if err := seedBinDir(discardLogger(), work, dir, DefaultKineVersion, DefaultKubeVersion, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(binDir(work), etcdutlBinaryName)); !os.IsNotExist(err) {
		t.Errorf("the work-dir seed copied etcdutl (stat err %v); only the restore command runs it", err)
	}
}

// TestSeedBinDirReseedsEtcdUnderMarker: in the etcd posture, etcd is a versioned
// payload binary on kine's terms — a workdir etcd whose marker does not vouch for the
// pin is replaced from a payload whose own marker does, and never from an unmarked one.
func TestSeedBinDirReseedsEtcdUnderMarker(t *testing.T) {
	marked := etcdChild(DefaultEtcdVersion)
	for _, tc := range []struct {
		name          string
		payloadMarked bool
		want          string
	}{
		{"marked payload replaces a stale etcd", true, "new-pin"},
		{"unmarked payload never replaces it", false, "old-pin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, work := t.TempDir(), t.TempDir()
			bd := binDir(work)
			if err := os.MkdirAll(bd, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marked.binPath(bd), []byte("old-pin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marked.binPath(payload), []byte("new-pin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.payloadMarked {
				if err := marked.writeMarker(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := seedBinDir(discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, true); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(marked.binPath(bd)); string(got) != tc.want {
				t.Errorf("workdir etcd = %q, want %q", got, tc.want)
			}
			if got := etcdStaged(bd, DefaultEtcdVersion); got != tc.payloadMarked {
				t.Errorf("etcdStaged after seed = %v, want %v", got, tc.payloadMarked)
			}
		})
	}
}
