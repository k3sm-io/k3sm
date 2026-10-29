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
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// withMountScopes returns opts plus a Pusher whose writer for ref's repository
// already holds the pull scope of every repository of the same registry that
// t's layers are mounted from.
//
// go-containerregistry's writer starts with the push scope alone and adds a
// mount source's pull scope the first time a layer upload mounts from it,
// replacing the HTTP client every other concurrent layer upload reads without
// a lock (a data race in the module, present upstream too). Mounting those
// layers here, one at a time and before the concurrent push starts, makes
// every such refresh happen while nothing else runs. The push then finds the
// scopes already held and never replaces the client, and it skips the layers
// mounted here because its Pusher records them as written.
//
// Every mountable layer is mounted here, not only the first per source: a
// layer the destination already holds is skipped by the writer before it adds
// the scope, so only mounting them all guarantees no refresh is left for the
// concurrent phase. A mount is one small request with no layer bytes, so the
// lost parallelism costs little. The refresh asks for exactly the scope the
// push would have asked for, so a credential that lacks it fails here as it
// would have failed mid-push.
//
// t is a v1.Image, a v1.ImageIndex or a *remote.Descriptor; anything else, or
// an image with no such layer, returns opts unchanged.
func withMountScopes(ctx context.Context, ref name.Reference, t any, opts []remote.Option) ([]remote.Option, error) {
	repo := ref.Context()
	layers, err := sameRegistryMounts(repo, t)
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return opts, nil
	}
	p, err := remote.NewPusher(opts...)
	if err != nil {
		return nil, err
	}
	for _, ml := range layers {
		if err := p.Upload(ctx, repo, ml); err != nil {
			return nil, err
		}
	}
	return append(append([]remote.Option(nil), opts...), remote.Reuse(p)), nil
}

// sameRegistryMounts is every layer of t, once per digest, that the writer
// would mount from another repository of repo's registry: the layers whose
// upload makes it refresh its scopes.
func sameRegistryMounts(repo name.Repository, t any) ([]*remote.MountableLayer, error) {
	var out []*remote.MountableLayer
	seen := map[ggcrv1.Hash]bool{}
	var walk func(t any) error
	walkImage := func(img ggcrv1.Image) error {
		ls, err := img.Layers()
		if err != nil {
			return err
		}
		for _, l := range ls {
			ml, ok := l.(*remote.MountableLayer)
			if !ok {
				continue
			}
			src := ml.Reference.Context()
			if src.String() == repo.String() || src.Registry.String() != repo.Registry.String() {
				continue
			}
			d, err := ml.Digest()
			if err != nil {
				return err
			}
			if seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, ml)
		}
		return nil
	}
	walk = func(t any) error {
		switch v := t.(type) {
		case *remote.Descriptor:
			switch {
			case v.MediaType.IsIndex():
				idx, err := v.ImageIndex()
				if err != nil {
					return err
				}
				return walk(idx)
			case v.MediaType.IsImage():
				img, err := v.Image()
				if err != nil {
					return err
				}
				return walkImage(img)
			}
		case ggcrv1.Image:
			return walkImage(v)
		case ggcrv1.ImageIndex:
			m, err := v.IndexManifest()
			if err != nil {
				return err
			}
			for _, d := range m.Manifests {
				switch {
				case d.MediaType.IsIndex():
					child, err := v.ImageIndex(d.Digest)
					if err != nil {
						return err
					}
					if err := walk(child); err != nil {
						return err
					}
				case d.MediaType.IsImage():
					child, err := v.Image(d.Digest)
					if err != nil {
						return err
					}
					if err := walkImage(child); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := walk(t); err != nil {
		return nil, err
	}
	return out, nil
}
