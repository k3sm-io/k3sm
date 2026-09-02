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

// TestImageTagVerb is the gate for `k3sm image tag`. Two claims: the target
// reaches TagImage as a DIGEST however the operator named it — a reference is
// resolved read-only first, because a tag that named another tag could be
// re-aimed by a concurrent pull — and the daemon's two refusals arrive verbatim.
func TestImageTagVerb(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1a", 32)

	t.Run("a digest source is tagged without a resolve", func(t *testing.T) {
		fake := &fakeImagesDaemon{tagResp: &runtimev1.TagImageResponse{
			Image: storeImage("example.test/app:v2", digest, "darwin", "arm64"),
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "tag", digest, "example.test/app:v2"})
		if err != nil {
			t.Fatalf("image tag: %v", err)
		}
		if len(fake.gotInspect) != 0 {
			t.Errorf("a digest source was still resolved through InspectImage (%d call(s))", len(fake.gotInspect))
		}
		if fake.gotTag.GetDigest() != digest || fake.gotTag.GetReference() != "example.test/app:v2" {
			t.Errorf("TagImage got digest=%q reference=%q", fake.gotTag.GetDigest(), fake.gotTag.GetReference())
		}
		if !strings.Contains(out, "tagged example.test/app:v2") {
			t.Errorf("tag printed %q", out)
		}
	})

	t.Run("a reference source is resolved to a digest first", func(t *testing.T) {
		fake := &fakeImagesDaemon{
			inspectResp: &runtimev1.InspectImageResponse{
				Image: storeImage("example.test/app:v1", digest, "darwin", "arm64"),
			},
			tagResp: &runtimev1.TagImageResponse{
				Image: storeImage("example.test/app:v2", digest, "darwin", "arm64"),
			},
		}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{
			"--socket", sock, "tag", "example.test/app:v1", "example.test/app:v2",
			"--platform", "darwin/arm64",
		})
		if err != nil {
			t.Fatalf("image tag: %v", err)
		}
		if len(fake.gotInspect) != 1 {
			t.Fatalf("InspectImage called %d time(s), want exactly one resolve", len(fake.gotInspect))
		}
		// The resolve names the source by reference and carries the platform,
		// because the entry it must resolve is a (reference x platform) key.
		if got := fake.gotInspect[0]; got.GetReference() != "example.test/app:v1" || got.GetDigest() != "" ||
			got.GetPlatform().GetArchitecture() != "arm64" {
			t.Errorf("resolve request = %v", got)
		}
		// TagImage never sees the mutable name: it is handed the digest the
		// resolve returned.
		if fake.gotTag.GetDigest() != digest {
			t.Errorf("TagImage got digest %q, want the resolved %q", fake.gotTag.GetDigest(), digest)
		}
		if !strings.Contains(out, "resolves to "+digest) {
			t.Errorf("tag did not show the resolution it performed\ngot:\n%s", out)
		}
	})

	t.Run("surfaces the daemon's refusals verbatim", func(t *testing.T) {
		tests := []struct {
			name string
			fake *fakeImagesDaemon
			args []string
			want string
		}{
			{
				name: "the digest is not in the store",
				fake: &fakeImagesDaemon{tagErr: status.Error(codes.NotFound,
					"TagImage: "+digest+" is not in the local store")},
				args: []string{"tag", digest, "example.test/app:v2"},
				want: "is not in the local store",
			},
			{
				// The refusal that is the whole point of the verb: this RPC never
				// re-points an entry, because that would drop the old edge — a
				// root removal wearing a tag's clothes.
				name: "the name already resolves elsewhere",
				fake: &fakeImagesDaemon{tagErr: status.Error(codes.FailedPrecondition,
					"TagImage: example.test/app:v2 for darwin/arm64 already resolves to sha256:other; untag it first — this verb never re-points an entry")},
				args: []string{"tag", digest, "example.test/app:v2"},
				want: "untag it first — this verb never re-points an entry",
			},
			{
				name: "the source reference cannot be resolved",
				fake: &fakeImagesDaemon{inspectErr: status.Error(codes.NotFound,
					"InspectImage: example.test/app:v1 is not in the local index")},
				args: []string{"tag", "example.test/app:v1", "example.test/app:v2"},
				want: "is not in the local index",
			},
			{
				name: "the source reference is ambiguous",
				fake: &fakeImagesDaemon{inspectErr: status.Error(codes.FailedPrecondition,
					"InspectImage: example.test/app:v1 has 2 platform entries; name one with --platform")},
				args: []string{"tag", "example.test/app:v1", "example.test/app:v2"},
				want: "name one with --platform",
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				sock := serveFakeImages(t, tc.fake)
				_, err := runImageCmd(t, append([]string{"--socket", sock}, tc.args...))
				if err == nil {
					t.Fatalf("tag succeeded against a refusing daemon")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error = %v, want one containing %q", err, tc.want)
				}
			})
		}
	})

	t.Run("an idempotent repeat says nothing was written", func(t *testing.T) {
		fake := &fakeImagesDaemon{tagResp: &runtimev1.TagImageResponse{
			Image:          storeImage("example.test/app:v2", digest, "darwin", "arm64"),
			AlreadyPresent: true,
		}}
		sock := serveFakeImages(t, fake)
		out, err := runImageCmd(t, []string{"--socket", sock, "tag", digest, "example.test/app:v2"})
		if err != nil {
			t.Fatalf("image tag: %v", err)
		}
		if !strings.Contains(out, "already tagged") {
			t.Errorf("the idempotent repeat printed %q", out)
		}
	})
}

// TestImageUntagVerb is the gate for `k3sm image untag`: the pin and the
// platform reach the wire, an absent name is an error rather than a silent
// success, and the output states the fact the whole provenance model rests on —
// untag removes a NAME, not bytes.
func TestImageUntagVerb(t *testing.T) {
	digest := "sha256:" + strings.Repeat("2b", 32)

	t.Run("removes one name and says the bytes remain", func(t *testing.T) {
		fake := &fakeImagesDaemon{untagResp: &runtimev1.UntagImageResponse{
			Removed: storeImage("example.test/app:v1", digest, "darwin", "arm64"),
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{
			"--socket", sock, "untag", "example.test/app:v1",
			"--platform", "darwin/arm64", "--digest", digest,
		})
		if err != nil {
			t.Fatalf("image untag: %v", err)
		}
		if fake.gotUntag.GetReference() != "example.test/app:v1" {
			t.Errorf("reference on the wire = %q", fake.gotUntag.GetReference())
		}
		if fake.gotUntag.GetDigest() != digest {
			t.Errorf("digest pin on the wire = %q, want %q", fake.gotUntag.GetDigest(), digest)
		}
		if fake.gotUntag.GetPlatform().GetOs() != "darwin" {
			t.Errorf("platform on the wire = %v", fake.gotUntag.GetPlatform())
		}
		if !strings.Contains(out, "untagged example.test/app:v1") {
			t.Errorf("untag printed %q", out)
		}
		// The operator must not read an untag as a reclaim: the bytes survive
		// until a prune re-derives reachability.
		if !strings.Contains(out, "prune") || !strings.Contains(out, "still on disk") {
			t.Errorf("untag did not say the content survives\ngot:\n%s", out)
		}
	})

	t.Run("an absent name is an error, not a silent success", func(t *testing.T) {
		fake := &fakeImagesDaemon{untagErr: status.Error(codes.NotFound,
			"UntagImage: example.test/app:v1 for darwin/arm64 is not in the local index")}
		sock := serveFakeImages(t, fake)
		out, err := runImageCmd(t, []string{"--socket", sock, "untag", "example.test/app:v1"})
		if err == nil {
			t.Fatalf("untag of an absent name succeeded: %s", out)
		}
		if !strings.Contains(err.Error(), "is not in the local index") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("an ambiguous untag is refused and removes nothing", func(t *testing.T) {
		fake := &fakeImagesDaemon{untagErr: status.Error(codes.FailedPrecondition,
			"UntagImage: example.test/app:v1 has 2 platform entries; nothing was removed")}
		sock := serveFakeImages(t, fake)
		_, err := runImageCmd(t, []string{"--socket", sock, "untag", "example.test/app:v1"})
		if err == nil || !strings.Contains(err.Error(), "nothing was removed") {
			t.Errorf("error = %v, want the ambiguity refusal", err)
		}
	})
}
