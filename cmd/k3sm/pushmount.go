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
// It fails closed: when t, or anything inside it, is a shape the walk cannot
// enumerate, the push runs with one job, so no layer upload runs beside the
// one that may replace the client.
//
// t is a v1.Image, a v1.ImageIndex or a *remote.Descriptor.
func withMountScopes(ctx context.Context, ref name.Reference, t any, opts []remote.Option) ([]remote.Option, error) {
	repo := ref.Context()
	layers, complete, err := sameRegistryMounts(repo, t)
	if err != nil {
		return nil, err
	}
	out := append([]remote.Option(nil), opts...)
	if !complete {
		out = append(out, remote.WithJobs(1))
	}
	if len(layers) == 0 {
		return out, nil
	}
	p, err := remote.NewPusher(out...)
	if err != nil {
		return nil, err
	}
	for _, ml := range layers {
		if err := p.Upload(ctx, repo, ml); err != nil {
			return nil, err
		}
	}
	// Reuse makes the push run with p's options, not the options passed
	// beside it, so everything the push needs is already in out.
	return append(out, remote.Reuse(p)), nil
}

// sameRegistryMounts is every layer of t, once per digest, that the writer
// would mount from another repository of repo's registry: the layers whose
// upload makes it refresh its scopes. complete is false when the walk met a
// shape it cannot enumerate, so layers may be missing some.
func sameRegistryMounts(repo name.Repository, t any) (layers []*remote.MountableLayer, complete bool, err error) {
	seen := map[ggcrv1.Hash]bool{}
	complete = true
	add := func(l ggcrv1.Layer) error {
		ml, ok := l.(*remote.MountableLayer)
		if !ok {
			return nil
		}
		src := ml.Reference.Context()
		if src.String() == repo.String() || src.Registry.String() != repo.Registry.String() {
			return nil
		}
		d, err := ml.Digest()
		if err != nil {
			return err
		}
		if !seen[d] {
			seen[d] = true
			layers = append(layers, ml)
		}
		return nil
	}
	walkImage := func(img ggcrv1.Image) error {
		ls, err := img.Layers()
		if err != nil {
			return err
		}
		for _, l := range ls {
			if err := add(l); err != nil {
				return err
			}
		}
		return nil
	}
	var walk func(t any) error
	walkIndex := func(idx ggcrv1.ImageIndex) error {
		m, err := idx.IndexManifest()
		if err != nil {
			return err
		}
		for _, d := range m.Manifests {
			switch {
			case d.MediaType.IsIndex():
				child, err := idx.ImageIndex(d.Digest)
				if err != nil {
					return err
				}
				if err := walk(child); err != nil {
					return err
				}
			case d.MediaType.IsImage():
				child, err := idx.Image(d.Digest)
				if err != nil {
					return err
				}
				if err := walkImage(child); err != nil {
					return err
				}
			default:
				// The pusher uploads any other child as a blob, and a remote
				// index serves it as a mountable layer.
				withLayer, ok := idx.(interface {
					Layer(ggcrv1.Hash) (ggcrv1.Layer, error)
				})
				if !ok {
					complete = false
					continue
				}
				l, err := withLayer.Layer(d.Digest)
				if err != nil {
					return err
				}
				if err := add(l); err != nil {
					return err
				}
			}
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
				return walkIndex(idx)
			case v.MediaType.IsImage():
				img, err := v.Image()
				if err != nil {
					return err
				}
				return walkImage(img)
			case v.MediaType.IsSchema1():
				img, err := v.Schema1()
				if err != nil {
					return err
				}
				return walkImage(img)
			}
			complete = false
		case ggcrv1.Image:
			return walkImage(v)
		case ggcrv1.ImageIndex:
			return walkIndex(v)
		default:
			complete = false
		}
		return nil
	}
	if err := walk(t); err != nil {
		return nil, false, err
	}
	return layers, complete, nil
}
