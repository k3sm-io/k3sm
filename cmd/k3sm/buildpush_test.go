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

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// noPush is the imagePusher for tests that are not about the upload: it uploads
// nothing and cannot fail, so a build test never needs a registry. It is also
// the assertion that --push was NOT asked for — deliver only calls the seam when
// the flag is set.
func noPush(context.Context, name.Reference, ggcrv1.Image, string) error { return nil }

// recordingPush is an imagePusher that remembers what it was handed and appends
// to a shared event log, which is how the store-then-push ORDER is proven
// without a daemon or a registry.
type recordingPush struct {
	log      *[]string
	targets  []string
	workDirs []string
	err      error
}

func (p *recordingPush) push(_ context.Context, ref name.Reference, img ggcrv1.Image, workDir string) error {
	if img == nil {
		return errors.New("the pusher was handed a nil image")
	}
	*p.log = append(*p.log, "push")
	p.targets = append(p.targets, ref.String())
	p.workDirs = append(p.workDirs, workDir)
	return p.err
}

// loggingStore is a storeRecorder that appends to the same event log.
type loggingStore struct {
	log   *[]string
	calls []string
	err   error
}

func (s *loggingStore) record(_ context.Context, ref name.Tag, _ ggcrv1.Image) error {
	*s.log = append(*s.log, "store")
	s.calls = append(s.calls, ref.String())
	return s.err
}

// stageNodeRegistry stages a credential for a node ingest registry at addr and
// points the work-dir resolution at it, exactly as a running server would.
func stageNodeRegistry(t *testing.T, addr string) string {
	t.Helper()
	workDir, _ := stageLocalCredential(t, addr)
	t.Setenv("K3SM_WORK_DIR", workDir)
	return workDir
}

// pushCtx writes a one-file build context and returns its directory.
func pushCtx(t *testing.T) string {
	t.Helper()
	return writeCtx(t, "FROM scratch\nCOPY app /app\nENTRYPOINT [\"/app\"]")
}

// TestResolvePushTarget pins WHERE `k3sm build --push` sends an image, from the
// --tag alone.
//
// The rule has two halves and both are load-bearing. A tag that names a registry
// goes there, spelled as written — k3sm never re-aims an explicit reference. A
// BARE tag goes to THIS node's ingest registry, which is the push-side mirror of
// the pull side: a Pod naming "myapp:v1" is served from that registry first, so
// a build that pushed it anywhere else would publish an image no Pod resolves —
// and, on Docker Hub, would publish it to the internet.
func TestResolvePushTarget(t *testing.T) {
	const addr = "127.0.0.1:6450"

	t.Run("resolution", func(t *testing.T) {
		workDir, _ := stageLocalCredential(t, addr)
		cases := []struct {
			name string
			tag  string
			want string
		}{
			{"a bare name goes to this node's registry", "myapp:v1", "localhost:6450/myapp:v1"},
			{"a bare name with a path element goes there too", "team/myapp:v1", "localhost:6450/team/myapp:v1"},
			{"a bare name with no tag keeps its own spelling", "myapp", "localhost:6450/myapp"},
			{"this node's registry, written out", "localhost:6450/myapp:v1", "localhost:6450/myapp:v1"},
			{"this node's registry by address", "127.0.0.1:6450/myapp:v1", "127.0.0.1:6450/myapp:v1"},
			{"a public registry is untouched", "ghcr.io/org/myapp:v1", "ghcr.io/org/myapp:v1"},
			{"a private registry is untouched", "registry.example.com/me/myapp:v1", "registry.example.com/me/myapp:v1"},
			{"an explicit Docker Hub reference is untouched", "docker.io/library/myapp:v1", "docker.io/library/myapp:v1"},
			{"a registry on another loopback port is untouched", "localhost:6451/myapp:v1", "localhost:6451/myapp:v1"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := resolvePushTarget(tc.tag, workDir)
				if err != nil {
					t.Fatalf("resolvePushTarget(%q) = %v", tc.tag, err)
				}
				if got.String() != tc.want {
					t.Errorf("resolvePushTarget(%q) = %q, want %q", tc.tag, got, tc.want)
				}
			})
		}
	})

	// A bare tag with no node registry is REFUSED, and the refusal names both
	// ways out. The alternatives are worse than an error: normalising to Docker
	// Hub would push a private image to the internet, and skipping the upload
	// would exit 0 on a command whose entire purpose was the upload.
	t.Run("a bare tag with no node registry is refused", func(t *testing.T) {
		_, err := resolvePushTarget("myapp:v1", t.TempDir())
		if !errors.Is(err, errNoNodeRegistry) {
			t.Fatalf("resolvePushTarget with no registry = %v, want errNoNodeRegistry", err)
		}
		for _, want := range []string{"--registry-port", "full registry reference"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
	})

	t.Run("a named registry needs no node registry", func(t *testing.T) {
		got, err := resolvePushTarget("ghcr.io/org/myapp:v1", t.TempDir())
		if err != nil {
			t.Fatalf("a fully qualified tag was refused on a node with no registry: %v", err)
		}
		if got.String() != "ghcr.io/org/myapp:v1" {
			t.Errorf("resolved %q", got)
		}
	})

	t.Run("a malformed tag is reported as a tag error", func(t *testing.T) {
		if _, err := resolvePushTarget("NOT A REFERENCE", t.TempDir()); err == nil {
			t.Fatal("a malformed tag resolved to a push target")
		} else if errors.Is(err, errNoNodeRegistry) {
			t.Errorf("a malformed tag was reported as a missing registry: %v", err)
		}
	})
}

// TestBuildPushOrdering pins the sequence and the failure wording.
//
// The store recording comes FIRST and happens whether or not --push was given —
// deliberately unlike `docker build --push`, because a k3sm build's product is
// an image this node can run. So a failed upload leaves the operator with a
// usable image, and the error has to say so or it reads as a lost build.
func TestBuildPushOrdering(t *testing.T) {
	ctxDir := pushCtx(t)
	stageNodeRegistry(t, "127.0.0.1:6450")

	t.Run("the store is written before the push", func(t *testing.T) {
		var log []string
		store := &loggingStore{log: &log}
		pusher := &recordingPush{log: &log}
		var out bytes.Buffer

		if err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "myapp:v1",
			push:       true,
			format:     "docker",
			contextDir: ctxDir,
		}, &out, engineBuild, store.record, pusher.push); err != nil {
			t.Fatalf("build: %v", err)
		}

		if want := []string{"store", "push"}; strings.Join(log, ",") != strings.Join(want, ",") {
			t.Fatalf("delivery order = %v, want %v", log, want)
		}
		if len(store.calls) != 1 || store.calls[0] != "myapp:v1" {
			t.Errorf("store recordings = %v, want the ORIGINAL bare reference", store.calls)
		}
		if len(pusher.targets) != 1 || pusher.targets[0] != "localhost:6450/myapp:v1" {
			t.Errorf("push targets = %v, want this node's registry", pusher.targets)
		}
		if !strings.Contains(out.String(), "push:   localhost:6450/myapp:v1") {
			t.Errorf("the summary does not report the resolved push target:\n%s", out.String())
		}
	})

	t.Run("no --push pushes nothing and reports nothing", func(t *testing.T) {
		var log []string
		store := &loggingStore{log: &log}
		pusher := &recordingPush{log: &log}
		var out bytes.Buffer

		if err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "myapp:v1",
			format:     "docker",
			contextDir: ctxDir,
		}, &out, engineBuild, store.record, pusher.push); err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(pusher.targets) != 0 {
			t.Errorf("a build with no --push uploaded to %v", pusher.targets)
		}
		if strings.Contains(out.String(), "push:") {
			t.Errorf("a build with no --push reported one:\n%s", out.String())
		}
	})

	t.Run("a store failure means no push at all", func(t *testing.T) {
		// The registry must never hold content this node's own store rejected:
		// the store recording is what makes the image runnable here, and an
		// upload past a failed recording publishes an image the build cannot
		// vouch for.
		var log []string
		store := &loggingStore{log: &log, err: errors.New("cannot reach runtimed")}
		pusher := &recordingPush{log: &log}

		err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "myapp:v1",
			push:       true,
			format:     "docker",
			contextDir: ctxDir,
		}, io.Discard, engineBuild, store.record, pusher.push)
		if err == nil {
			t.Fatal("expected the store failure to fail the build")
		}
		if len(pusher.targets) != 0 {
			t.Errorf("the image was pushed after a failed store recording: %v", pusher.targets)
		}
	})

	t.Run("a push failure fails the build and says the image is in the store", func(t *testing.T) {
		var log []string
		store := &loggingStore{log: &log}
		pusher := &recordingPush{log: &log, err: errors.New("registry rejected the credential")}
		var out bytes.Buffer

		err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "myapp:v1",
			push:       true,
			format:     "docker",
			contextDir: ctxDir,
		}, &out, engineBuild, store.record, pusher.push)
		if err == nil {
			t.Fatal("expected the push failure to fail the build")
		}
		if len(store.calls) != 1 {
			t.Fatalf("store recordings = %v, want the recording to have happened first", store.calls)
		}
		for _, want := range []string{"myapp:v1", "is in the node store", "push failed", "registry rejected the credential"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error does not contain %q: %v", want, err)
			}
		}
		if strings.Contains(out.String(), "push:") {
			t.Errorf("a failed push was reported as one that landed:\n%s", out.String())
		}
	})

	t.Run("a bare tag with no node registry fails the build after the store", func(t *testing.T) {
		var log []string
		store := &loggingStore{log: &log}
		pusher := &recordingPush{log: &log}
		// A work dir with no credential is a node whose registry is off.
		t.Setenv("K3SM_WORK_DIR", t.TempDir())

		err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "myapp:v1",
			push:       true,
			format:     "docker",
			contextDir: ctxDir,
		}, io.Discard, engineBuild, store.record, pusher.push)
		if !errors.Is(err, errNoNodeRegistry) {
			t.Fatalf("build --push with no node registry = %v, want errNoNodeRegistry", err)
		}
		if len(store.calls) != 1 {
			t.Errorf("store recordings = %v, want the image recorded before the push was attempted", store.calls)
		}
		if len(pusher.targets) != 0 {
			t.Errorf("an unresolvable target was still uploaded: %v", pusher.targets)
		}
		if !strings.Contains(err.Error(), "is in the node store") {
			t.Errorf("the error does not say the image is usable here: %v", err)
		}
	})
}

// TestBuildPushFlag pins the argv grammar: --push is off by default, it is
// advertised, and it composes with --output rather than replacing it.
func TestBuildPushFlag(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		o, err := parseBuildArgs([]string{"-t", "app:dev", "."}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if o.push {
			t.Error("push = true with no --push: a build must not upload anything unasked")
		}
	})
	t.Run("parses", func(t *testing.T) {
		o, err := parseBuildArgs([]string{"-t", "app:dev", "--push", "."}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !o.push {
			t.Error("--push did not reach the options")
		}
	})
	t.Run("composes with --output", func(t *testing.T) {
		o, err := parseBuildArgs([]string{"-t", "app:dev", "--push", "--output", "img.tar", "."}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !o.push || o.output != "img.tar" {
			t.Errorf("push=%v output=%q, want both honoured", o.push, o.output)
		}
	})
	t.Run("the usage advertises it", func(t *testing.T) {
		var help bytes.Buffer
		if _, err := parseBuildArgs([]string{"-h"}, &help); err == nil {
			t.Fatal("-h returned no error, want flag.ErrHelp")
		}
		if !strings.Contains(help.String(), "-push") {
			t.Errorf("the usage does not advertise --push:\n%s", help.String())
		}
	})
}

// TestBuildPushToRegistry is the end-to-end rung: a real build, the real upload
// path `k3sm image push` uses, and a real registry on loopback.
//
// It is what proves the two things a fake seam cannot: that the node's own
// per-boot credential is discovered and presented for a bare tag, and that the
// content genuinely arrives under the resolved reference.
func TestBuildPushToRegistry(t *testing.T) {
	// The docker config chain is part of the credential contract, so it is
	// pinned empty rather than read from the developer's machine.
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")

	t.Run("a bare tag lands in this node's registry, authenticated", func(t *testing.T) {
		host, probe := startRegistry(t, "")
		// The credential names the LIVE registry's address, which is what makes
		// the resolution and the credential lookup agree the way they do on a
		// node whose server minted both.
		workDir, cred := stageLocalCredential(t, host)
		t.Setenv("K3SM_WORK_DIR", workDir)

		ctxDir := pushCtx(t)
		layout := filepath.Join(t.TempDir(), "layout")
		store := &recordingStore{}
		var out bytes.Buffer

		if err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "myapp:v1",
			push:       true,
			output:     layout,
			format:     "oci",
			contextDir: ctxDir,
		}, &out, engineBuild, store.record, pushImage); err != nil {
			t.Fatalf("build --push: %v", err)
		}

		// The store keeps the operator's ORIGINAL bare reference, and --output
		// still wrote its artifact: --push is a third sink, not a replacement.
		if len(store.calls) != 1 || store.calls[0] != "myapp:v1" {
			t.Errorf("store recordings = %v, want [myapp:v1]", store.calls)
		}
		if _, err := os.Stat(filepath.Join(layout, "index.json")); err != nil {
			t.Errorf("--output wrote no layout alongside --push: %v", err)
		}

		_, port, _ := strings.Cut(host, ":")
		target := "localhost:" + port + "/myapp:v1"
		if !strings.Contains(out.String(), "push:   "+target) {
			t.Errorf("the summary does not name the resolved target %q:\n%s", target, out.String())
		}
		assertRegistryHolds(t, target, layoutDigest(t, layout))

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password))
		if !containsHeader(probe.headers(), want) {
			t.Errorf("the node's own push credential was never presented; headers = %q", probe.headers())
		}
		if strings.Contains(out.String(), cred.Password) {
			t.Error("the build echoed the registry credential to stdout")
		}
	})

	t.Run("a fully qualified tag goes to the registry it names", func(t *testing.T) {
		host, _ := startRegistry(t, "")
		// No node registry at all: an explicit reference must not need one.
		t.Setenv("K3SM_WORK_DIR", t.TempDir())

		ctxDir := pushCtx(t)
		layout := filepath.Join(t.TempDir(), "layout")
		target := host + "/team/myapp:v1"
		var out bytes.Buffer

		if err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        target,
			push:       true,
			output:     layout,
			format:     "oci",
			contextDir: ctxDir,
		}, &out, engineBuild, noStore, pushImage); err != nil {
			t.Fatalf("build --push: %v", err)
		}
		if !strings.Contains(out.String(), "push:   "+target) {
			t.Errorf("the summary does not name %q:\n%s", target, out.String())
		}
		assertRegistryHolds(t, target, layoutDigest(t, layout))
	})
}

// containsHeader reports whether any recorded Authorization header is want.
func containsHeader(seen []string, want string) bool {
	for _, h := range seen {
		if h == want {
			return true
		}
	}
	return false
}
