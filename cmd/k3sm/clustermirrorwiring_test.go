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
	"testing"

	"k3sm.io/runtimed/pkg/image"

	"k3sm.io/k3sm/pkg/clustermirror"
)

// TestClusterMirrorWiring pins the seam that carries peer registries from the
// node's cluster view into runtimed's puller.
//
// It is worth a test of its own because the failure is SILENT: a
// RuntimedConfig.ImageMirrors that is never assigned leaves a node that still
// starts, still runs every pod it has, and simply never falls back to a peer —
// visible only as an image that will not pull on the one Mac it was not pushed
// to. Nothing else in the suite would go red.
func TestClusterMirrorWiring(t *testing.T) {
	t.Parallel()

	t.Run("the node's mirror source reaches runtimed's config", func(t *testing.T) {
		src := &recordingMirrors{}
		cfg := runtimedConfig(nodeOptions{nodeName: "mac-a", imageMirrors: src}, nil)
		if cfg.ImageMirrors == nil {
			t.Fatal("ImageMirrors is nil: the node's peer registries never reach the puller")
		}
		// Identity, not merely non-nil: a config that substituted some other
		// source would pass a nil check and still consult the wrong cluster.
		if cfg.ImageMirrors != image.MirrorSource(src) {
			t.Errorf("ImageMirrors = %v, want the source the node built", cfg.ImageMirrors)
		}
	})

	t.Run("a bring-up with no cluster threads no mirrors", func(t *testing.T) {
		// nil is the single-node posture and the complete, correct behavior there:
		// runtimed produces no candidate, so no fallback can run.
		if got := runtimedConfig(nodeOptions{nodeName: "mac-a"}, nil).ImageMirrors; got != nil {
			t.Errorf("ImageMirrors = %v with no source, want nil", got)
		}
	})

	t.Run("the shipped source satisfies the seam", func(t *testing.T) {
		// The type the node actually builds, checked against the interface the
		// config field declares — so a signature change in either repo fails here
		// rather than at a pull on a two-Mac cluster.
		var src image.MirrorSource = clustermirror.New(clustermirror.Config{NodeName: "mac-a"})
		if got := src.Mirrors("localhost:6450/app:v1"); got != nil {
			t.Errorf("an unstarted source returned %+v, want no candidates", got)
		}
	})
}

// recordingMirrors is a MirrorSource with a fixed, empty answer. The wiring test
// asserts WHICH source arrives, never what it says.
type recordingMirrors struct{}

func (*recordingMirrors) Mirrors(string) []image.Mirror { return nil }
