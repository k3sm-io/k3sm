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

package oci

import (
	"errors"
	"fmt"
	"path"
	"strings"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ErrUnsupportedPlatform reports a --platform value this builder cannot honestly
// stamp.
var ErrUnsupportedPlatform = errors.New("oci: unsupported platform")

// The only platform v1 emits. The builder does no cross-compilation — it copies
// host files verbatim — so any other value would write a config whose declared
// platform contradicts its bytes. That config is exactly what k3sm's own
// fail-closed platform selector later treats as authoritative, so a free-form
// --platform would be a supported way to mint a self-consistent lie: the
// manifest verifies, the digest is stable, and the artifact is wrong.
const (
	PlatformOS      = "darwin"
	PlatformArch    = "arm64"
	PlatformVariant = "v8"
)

// DefaultPlatform is the only accepted --platform value, in os/arch form.
const DefaultPlatform = PlatformOS + "/" + PlatformArch

// shellPrefix wraps a shell-form ENTRYPOINT/CMD, matching Docker.
var shellPrefix = []string{"/bin/sh", "-c"}

// Request is one build.
type Request struct {
	Dockerfile *Dockerfile
	Context    *Context
	// Platform is the target, in "os/arch" form. Empty means DefaultPlatform.
	Platform string
	// TmpDir stages layer tars. Empty uses the OS temp dir.
	TmpDir string
}

// Build assembles the image described by req. It performs no I/O outside the
// build context and the staging directory, and never signs anything.
func Build(req Request) (ggcrv1.Image, error) {
	if req.Dockerfile == nil || req.Context == nil {
		return nil, errors.New("oci: build request needs a Dockerfile and a context")
	}
	if err := checkPlatform(req.Platform); err != nil {
		return nil, err
	}

	img, err := stampPlatform(empty.Image)
	if err != nil {
		return nil, err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read base config: %w", err)
	}
	cfg = cfg.DeepCopy()
	cfg.Config.Env = nil
	cfg.Config.Labels = map[string]string{}

	workdir := "/"
	for _, inst := range req.Dockerfile.Instructions {
		switch inst.Verb {
		case VerbFrom:
			// scratch: the empty base, already in hand.

		case VerbCopy, VerbAdd:
			entries, err := req.Context.selectEntries(inst.Args[:len(inst.Args)-1], inst.Args[len(inst.Args)-1], workdir)
			if err != nil {
				return nil, fmt.Errorf("line %d: %s: %w", inst.Line, inst.Verb, err)
			}
			layer, err := BuildLayer(entries, req.TmpDir)
			if err != nil {
				return nil, fmt.Errorf("line %d: %s: %w", inst.Line, inst.Verb, err)
			}
			img, err = mutate.Append(img, mutate.Addendum{
				Layer:     layer,
				MediaType: types.OCIUncompressedLayer,
				History:   history(inst),
			})
			if err != nil {
				return nil, fmt.Errorf("line %d: append layer: %w", inst.Line, err)
			}

		case VerbEnv:
			cfg.Config.Env = mergeEnv(cfg.Config.Env, inst.Args)

		case VerbEntrypoint:
			cfg.Config.Entrypoint = command(inst)

		case VerbCmd:
			cfg.Config.Cmd = command(inst)

		case VerbWorkdir:
			workdir = joinWorkdir(workdir, inst.Args[0])
			cfg.Config.WorkingDir = workdir

		case VerbLabel:
			for _, kv := range inst.Args {
				k, v, _ := strings.Cut(kv, "=")
				cfg.Config.Labels[k] = v
			}

		case VerbExpose:
			if cfg.Config.ExposedPorts == nil {
				cfg.Config.ExposedPorts = map[string]struct{}{}
			}
			for _, p := range inst.Args {
				cfg.Config.ExposedPorts[p] = struct{}{}
			}
		}
	}

	// mutate.Append wrote its own history entries for the layer instructions.
	// Take RootFS from the assembled image and derive history in ONE place, so
	// there is a single derivation rather than two that must be proven equal.
	merged, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read assembled config: %w", err)
	}
	cfg.RootFS = merged.RootFS
	cfg.History = orderedHistory(req.Dockerfile)
	cfg.Created = ggcrv1.Time{Time: epoch}
	cfg.Author = ""
	cfg.Container = ""
	cfg.DockerVersion = ""

	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	return mutate.MediaType(mutate.ConfigMediaType(img, types.OCIConfigJSON), types.OCIManifestSchema1), nil
}

// checkPlatform enforces the single supported target.
func checkPlatform(p string) error {
	// Accept the full triple too: it is the spelling this builder stamps into
	// the config, and the one runtimed's platform selection canonicalizes to.
	if p == "" || p == DefaultPlatform || p == DefaultPlatform+"/"+PlatformVariant {
		return nil
	}
	return fmt.Errorf(
		"%q: %w — this builder copies host files verbatim and does not cross-compile, so %s is the only platform it can truthfully declare",
		p, ErrUnsupportedPlatform, DefaultPlatform)
}

// stampPlatform sets os/architecture/variant on the base. ggcr's empty.Image
// carries neither field, and a config with an empty os or architecture is
// rejected outright by k3sm's own platform verification — so a naive
// mutate.AppendLayers(empty.Image, …) would produce an image k3sm cannot pull.
func stampPlatform(base ggcrv1.Image) (ggcrv1.Image, error) {
	cfg, err := base.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read base config: %w", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture, cfg.Variant = PlatformOS, PlatformArch, PlatformVariant
	out, err := mutate.ConfigFile(base, cfg)
	if err != nil {
		// Returning the unstamped base here would emit a config with an empty
		// os/architecture — exactly the "self-consistent lie" this function
		// exists to prevent, and one that exits 0.
		return nil, fmt.Errorf("stamp platform: %w", err)
	}
	return out, nil
}

// history renders one instruction's history entry. EmptyLayer marks the
// metadata-only verbs, so the entry count matches the instruction count while
// RootFS.DiffIDs matches only the filesystem-touching ones.
func history(inst Instruction) ggcrv1.History {
	return ggcrv1.History{
		Created:    ggcrv1.Time{Time: epoch},
		CreatedBy:  inst.Raw,
		EmptyLayer: inst.Verb != VerbCopy && inst.Verb != VerbAdd,
	}
}

// orderedHistory returns one history entry per instruction, in source order.
//
// It folds directly over the instructions rather than reconciling the two
// producers (mutate.Append's entries and the metadata verbs') by CreatedBy:
// that keying is lossless only while both produce identical values for
// identical raw lines — an invariant nothing states — and it would silently
// collapse duplicate lines the moment history() grew a per-instruction field.
func orderedHistory(df *Dockerfile) []ggcrv1.History {
	out := make([]ggcrv1.History, 0, len(df.Instructions))
	for _, inst := range df.Instructions {
		if inst.Verb == VerbFrom {
			continue
		}
		out = append(out, history(inst))
	}
	return out
}

// command renders an ENTRYPOINT/CMD operand list. A shell form is wrapped the
// way Docker wraps it; an exec form is taken verbatim.
func command(inst Instruction) []string {
	if inst.JSON {
		return append([]string{}, inst.Args...)
	}
	return append(append([]string{}, shellPrefix...), inst.Args[0])
}

// mergeEnv applies key=value pairs, replacing an existing key IN PLACE so
// ordering stays a function of first appearance (Docker's semantics).
func mergeEnv(env []string, pairs []string) []string {
	for _, kv := range pairs {
		k, _, _ := strings.Cut(kv, "=")
		replaced := false
		for i, existing := range env {
			if ek, _, _ := strings.Cut(existing, "="); ek == k {
				env[i] = kv
				replaced = true
				break
			}
		}
		if !replaced {
			env = append(env, kv)
		}
	}
	return env
}

// joinWorkdir accumulates a relative WORKDIR onto the previous one.
func joinWorkdir(cur, next string) string {
	if strings.HasPrefix(next, "/") {
		return path.Clean(next)
	}
	return path.Clean(path.Join(cur, next))
}
