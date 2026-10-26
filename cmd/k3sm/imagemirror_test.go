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
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// fakeMirrorer records every copy it is asked for and answers with err.
type fakeMirrorer struct {
	calls []string
	err   error
}

func (f *fakeMirrorer) mirror(_ context.Context, src, mirror name.Reference, _ string) error {
	f.calls = append(f.calls, src.String()+" -> "+mirror.String())
	return f.err
}

// TestMirrorPulled pins which pulled references get a copy in the cluster
// registry, under which name, and what a failed copy prints.
func TestMirrorPulled(t *testing.T) {
	mustMirror := func(ref string) string {
		t.Helper()
		m, err := image.PublicMirrorReference(flatRegistryHost, ref)
		if err != nil {
			t.Fatalf("PublicMirrorReference(%q): %v", ref, err)
		}
		return m
	}
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name       string
		ref        string
		copyErr    error
		wantMirror string // "" = no copy is attempted
		wantWarn   []string
	}{
		{name: "a bare Docker Hub name is copied under docker.io", ref: "nginx:1", wantMirror: "registry-k3sm:6450/docker.io/library/nginx:1"},
		{name: "a docker.io reference is copied under docker.io", ref: "docker.io/library/nginx:1.27", wantMirror: mustMirror("docker.io/library/nginx:1.27")},
		{name: "another public registry keeps its host in the name", ref: "ghcr.io/org/app:v1", wantMirror: "registry-k3sm:6450/ghcr.io/org/app:v1"},
		{name: "a digest reference keeps its digest", ref: "ghcr.io/org/app@" + digest, wantMirror: "registry-k3sm:6450/ghcr.io/org/app@" + digest},
		{name: "a cluster-registry reference is not copied", ref: "registry-k3sm:6450/app:dev"},
		{name: "the loopback push gate is the cluster registry", ref: "localhost:6451/app:dev"},
		{name: "a registry with a port is not copied", ref: "example.test:5000/app:v1"},
		{
			name:       "a failed copy warns with the remedy",
			ref:        "ghcr.io/org/app:v1",
			copyErr:    fmt.Errorf("%w; %s", errNoUserKubeconfig, builderTokenRemedy),
			wantMirror: "registry-k3sm:6450/ghcr.io/org/app:v1",
			wantWarn:   []string{"warning", "ghcr.io/org/app:v1 is in this node's cache", "registry-k3sm:6450/ghcr.io/org/app:v1", "no kubeconfig", "k3sm kubeconfig", "--no-mirror"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeMirrorer{err: tc.copyErr}
			var out, warn bytes.Buffer
			o := imageOptions{subcommand: "pull", source: tc.ref, workDir: t.TempDir()}
			mirrorPulled(context.Background(), o, storeImage(tc.ref, digest, "", ""), &out, &warn, f.mirror)
			if tc.wantMirror == "" {
				if len(f.calls) != 0 {
					t.Fatalf("copied %v, want no copy", f.calls)
				}
				if out.Len() != 0 || warn.Len() != 0 {
					t.Fatalf("printed out=%q warn=%q, want nothing", out.String(), warn.String())
				}
				return
			}
			if len(f.calls) != 1 || !strings.HasSuffix(f.calls[0], " -> "+tc.wantMirror) {
				t.Fatalf("copies = %v, want one to %s", f.calls, tc.wantMirror)
			}
			if tc.copyErr == nil {
				if !strings.Contains(out.String(), "mirror:   "+tc.wantMirror) {
					t.Errorf("out = %q, want the mirror line", out.String())
				}
				if warn.Len() != 0 {
					t.Errorf("warn = %q, want nothing", warn.String())
				}
				return
			}
			if strings.Contains(out.String(), "mirror:") {
				t.Errorf("out = %q, want no mirror line for a failed copy", out.String())
			}
			for _, w := range tc.wantWarn {
				if !strings.Contains(warn.String(), w) {
					t.Errorf("warning has no %q\ngot: %s", w, warn.String())
				}
			}
		})
	}
}

// TestImagePullCopiesToClusterRegistry drives `k3sm image pull` end to end
// against a fake daemon: the node pull comes first, the copy follows it, a
// failed copy leaves the pull a success, and --no-mirror skips the copy.
func TestImagePullCopiesToClusterRegistry(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		copyErr  error
		wantCopy bool
		wantOut  []string
		wantWarn string
	}{
		{name: "a public pull is copied", args: []string{"pull", "docker.io/library/nginx:1"}, wantCopy: true,
			wantOut: []string{"pulled docker.io/library/nginx:1", "mirror:   registry-k3sm:6450/docker.io/library/nginx:1"}},
		{name: "--no-mirror skips the copy", args: []string{"pull", "docker.io/library/nginx:1", "--no-mirror"},
			wantOut: []string{"pulled docker.io/library/nginx:1"}},
		{name: "a failed copy warns and the pull succeeds", args: []string{"pull", "docker.io/library/nginx:1"}, wantCopy: true,
			copyErr: errors.New("connect to the push gate: refused"), wantOut: []string{"pulled docker.io/library/nginx:1"}, wantWarn: "connect to the push gate: refused"},
		{name: "a cluster pull is not copied", args: []string{"pull", "registry-k3sm:6450/app:dev"},
			wantOut: []string{"pulled registry-k3sm:6450/app:dev"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeMirrorer{err: tc.copyErr}
			prev := pullMirrorer
			pullMirrorer = f.mirror
			t.Cleanup(func() { pullMirrorer = prev })

			fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{
				Image: storeImage(tc.args[1], "sha256:3333333333333333333333333333333333333333333333333333333333333333", "darwin", "arm64"),
			}}
			sock := serveFakeImages(t, fake)
			var warn bytes.Buffer
			o, err := parseImageArgs(append([]string{"--socket", sock, "--work-dir", t.TempDir()}, tc.args...), &warn)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var out bytes.Buffer
			if err := imageCommand(ctx, o, &out, dialRuntimed); err != nil {
				t.Fatalf("image pull = %v, want success", err)
			}
			if fake.gotPull == nil {
				t.Fatal("the node pull never happened")
			}
			if got := len(f.calls) == 1; got != tc.wantCopy {
				t.Fatalf("copies = %v, want copy=%v", f.calls, tc.wantCopy)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(out.String(), w) {
					t.Errorf("out has no %q\ngot:\n%s", w, out.String())
				}
			}
			if !tc.wantCopy && strings.Contains(out.String(), "mirror:") {
				t.Errorf("out = %q, want no mirror line", out.String())
			}
			if tc.wantWarn == "" && warn.Len() != 0 {
				t.Errorf("warn = %q, want nothing", warn.String())
			}
			if tc.wantWarn != "" && !strings.Contains(warn.String(), tc.wantWarn) {
				t.Errorf("warn = %q, want %q", warn.String(), tc.wantWarn)
			}
		})
	}
}

// TestNoMirrorIsPullOnly refuses --no-mirror on a verb that writes no copy.
func TestNoMirrorIsPullOnly(t *testing.T) {
	if _, err := parseImageArgs([]string{"ls", "--no-mirror"}, io.Discard); err == nil || !strings.Contains(err.Error(), "--no-mirror") {
		t.Fatalf("ls --no-mirror = %v, want a refusal naming the flag", err)
	}
	o, err := parseImageArgs([]string{"pull", "nginx:1", "--no-mirror"}, io.Discard)
	if err != nil || !o.noMirror {
		t.Fatalf("pull --no-mirror = %+v, %v; want noMirror set", o.noMirror, err)
	}
}

// TestImagePullPinsTheCopySource proves the cluster copy reads the exact image
// the node pull cached: the source is the pulled repository at the digest the
// daemon reported (the index digest when the tag resolved through an index),
// never the tag re-resolved at the public registry, and the copy keeps the tag
// the user pulled. A response with no digest gets no copy and a warning.
func TestImagePullPinsTheCopySource(t *testing.T) {
	const (
		manifestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		indexDigest    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		ref            = "ghcr.io/org/app:v1"
		wantDest       = "registry-k3sm:6450/ghcr.io/org/app:v1"
	)
	cases := []struct {
		name       string
		manifest   string
		index      string
		wantSource string // "" = no copy is attempted
		wantWarn   []string
	}{
		{name: "a single manifest is copied from its digest", manifest: manifestDigest, wantSource: "ghcr.io/org/app@" + manifestDigest},
		{name: "an index is copied from the index digest", manifest: manifestDigest, index: indexDigest, wantSource: "ghcr.io/org/app@" + indexDigest},
		{name: "a response with no digest skips the copy and warns", wantWarn: []string{"warning", ref, "no digest", "--no-mirror"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeMirrorer{}
			prev := pullMirrorer
			pullMirrorer = f.mirror
			t.Cleanup(func() { pullMirrorer = prev })

			img := storeImage(ref, tc.manifest, "darwin", "arm64")
			img.Manifest.IndexDigest = tc.index
			fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: img}}
			sock := serveFakeImages(t, fake)
			var warn bytes.Buffer
			o, err := parseImageArgs([]string{"--socket", sock, "--work-dir", t.TempDir(), "pull", ref}, &warn)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var out bytes.Buffer
			if err := imageCommand(ctx, o, &out, dialRuntimed); err != nil {
				t.Fatalf("image pull = %v, want success", err)
			}
			if tc.wantSource == "" {
				if len(f.calls) != 0 {
					t.Fatalf("copies = %v, want none", f.calls)
				}
				if strings.Contains(out.String(), "mirror:") {
					t.Errorf("out = %q, want no mirror line", out.String())
				}
				for _, w := range tc.wantWarn {
					if !strings.Contains(warn.String(), w) {
						t.Errorf("warning has no %q\ngot: %s", w, warn.String())
					}
				}
				return
			}
			if want := tc.wantSource + " -> " + wantDest; len(f.calls) != 1 || f.calls[0] != want {
				t.Fatalf("copies = %v, want exactly [%s]", f.calls, want)
			}
			if warn.Len() != 0 {
				t.Errorf("warn = %q, want nothing", warn.String())
			}
		})
	}
}
