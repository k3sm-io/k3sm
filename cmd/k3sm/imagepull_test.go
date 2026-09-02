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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// storeImage is a store entry shaped the way the daemon returns one: the digest
// and the resolved platform are read out of the embedded Descriptor and
// ImageManifest, never re-spelled as parallel scalars.
func storeImage(reference, digest, os, arch string) *runtimev1.Image {
	img := &runtimev1.Image{
		ManifestDescriptor: &runtimev1.Descriptor{
			Digest:    digest,
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Size:      512,
		},
		Manifest: &runtimev1.ImageManifest{
			Reference: reference,
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Config:    &runtimev1.Descriptor{Digest: "sha256:cfg", Size: 1024},
			Layers: []*runtimev1.Descriptor{
				{Digest: "sha256:layer1", Size: 1 << 20},
				{Digest: "sha256:layer2", Size: 2 << 20},
			},
		},
	}
	if os != "" {
		img.Manifest.Platform = &runtimev1.Platform{Os: os, Architecture: arch}
	}
	return img
}

// TestImagePullVerb is the k3sm-side gate for `k3sm image pull`: the CLI is a
// CLIENT of the daemon's puller — the selector an operator typed reaches the
// wire unaltered, an unset platform stays unset, and the daemon's own refusal is
// what the operator reads.
func TestImagePullVerb(t *testing.T) {
	const digest = "sha256:pulled"

	t.Run("sends the reference and prints the resolved digest", func(t *testing.T) {
		fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{
			Image: storeImage("example.test/app:v1", digest, "darwin", "arm64"),
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "pull", "example.test/app:v1"})
		if err != nil {
			t.Fatalf("image pull: %v", err)
		}
		if fake.gotPull == nil {
			t.Fatalf("the daemon was never called — the CLI did not act as a client")
		}
		if fake.gotPull.GetReference() != "example.test/app:v1" {
			t.Errorf("reference on the wire = %q", fake.gotPull.GetReference())
		}
		// UNSET, not an empty Platform: the daemon reads unset as its own host
		// platform, and &Platform{} would ask for an image whose OS is "".
		if fake.gotPull.GetPlatform() != nil {
			t.Errorf("platform on the wire = %v, want nil for an unset --platform", fake.gotPull.GetPlatform())
		}
		if fake.gotPull.GetPolicy() != runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED {
			t.Errorf("policy on the wire = %v, want UNSPECIFIED for an unset --policy", fake.gotPull.GetPolicy())
		}
		for _, want := range []string{"pulled example.test/app:v1", digest, "darwin/arm64"} {
			if !strings.Contains(out, want) {
				t.Errorf("pull printed no %q\ngot:\n%s", want, out)
			}
		}
	})

	t.Run("carries the platform and the policy verbatim", func(t *testing.T) {
		fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{
			Image: storeImage("example.test/app:v1", digest, "linux", "amd64"),
		}}
		sock := serveFakeImages(t, fake)

		if _, err := runImageCmd(t, []string{
			"--socket", sock, "pull", "example.test/app:v1",
			"--platform", "linux/amd64", "--policy", "always",
		}); err != nil {
			t.Fatalf("image pull: %v", err)
		}
		p := fake.gotPull.GetPlatform()
		if p.GetOs() != "linux" || p.GetArchitecture() != "amd64" {
			t.Errorf("platform on the wire = %v", p)
		}
		if fake.gotPull.GetPolicy() != runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS {
			t.Errorf("policy on the wire = %v", fake.gotPull.GetPolicy())
		}
	})

	t.Run("reports a cache hit as up to date", func(t *testing.T) {
		fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{
			Image:          storeImage("example.test/app:v1", digest, "darwin", "arm64"),
			AlreadyPresent: true,
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "pull", "example.test/app:v1"})
		if err != nil {
			t.Fatalf("image pull: %v", err)
		}
		if !strings.Contains(out, "up to date") {
			t.Errorf("a pull that fetched nothing printed %q", out)
		}
	})

	// The two failure channels the wire defines. Both mean nothing was recorded,
	// so both must exit non-zero — reporting only the transport status would
	// render a refused pull as a success.
	t.Run("surfaces the daemon's refusal", func(t *testing.T) {
		tests := []struct {
			name string
			fake *fakeImagesDaemon
			want string
		}{
			{
				name: "a transport status",
				fake: &fakeImagesDaemon{pullErr: status.Error(codes.NotFound,
					"PullImage: example.test/app:v1 is not in any registry this node can reach")},
				want: "is not in any registry this node can reach",
			},
			{
				name: "an in-band status on a successful RPC",
				fake: &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{
					Error: status.New(codes.FailedPrecondition, "the store is out of space").Proto(),
				}},
				want: "the store is out of space",
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				sock := serveFakeImages(t, tc.fake)
				out, err := runImageCmd(t, []string{"--socket", sock, "pull", "example.test/app:v1"})
				if err == nil {
					t.Fatalf("pull succeeded against a refusing daemon: %s", out)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error = %v, want one containing %q", err, tc.want)
				}
				if out != "" {
					t.Errorf("a failed pull printed %q; nothing was recorded", out)
				}
			})
		}
	})

	// A daemon predating the image service answers UNIMPLEMENTED for every
	// method, and the wire's skew contract says a client reads that as "this
	// daemon has no image service" rather than as an internal error.
	t.Run("names an unimplemented service as one", func(t *testing.T) {
		fake := &fakeImagesDaemon{pullErr: status.Error(codes.Unimplemented, "unknown method PullImage")}
		sock := serveFakeImages(t, fake)
		_, err := runImageCmd(t, []string{"--socket", sock, "pull", "example.test/app:v1"})
		if err == nil || !strings.Contains(err.Error(), "does not serve the image service") {
			t.Errorf("error = %v, want the image-service skew message", err)
		}
	})
}
