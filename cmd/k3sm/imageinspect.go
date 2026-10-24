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
	"encoding/json"
	"fmt"
	"io"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// imageInspect reports what the cluster registry holds under one name: the
// manifest, and for an image its config.
//
// Strictly read-only. The target is a tag or a repository@digest. An index is
// reported as its platforms unless --platform selects one, which is then
// inspected as an image. -o json prints the registry's own manifest and config
// documents (re-indented, not re-encoded) beside the reference and digest.
//
// ABSENT FIELDS ARE ABSENT FACTS: a config that sets no user prints no USER
// row, not an empty one.
func imageInspect(ctx context.Context, o imageOptions, out io.Writer) error {
	c, err := resolveClusterImage(o.source, o.workDir)
	if err != nil {
		return err
	}
	opts, err := registryOptions(ctx, c, o.workDir)
	if err != nil {
		return err
	}
	desc, parent, err := getClusterImage(c, o.platform, o.workDir, opts)
	if err != nil {
		return err
	}
	view := inspectView{
		Reference: c.flat.String(),
		Digest:    desc.Digest.String(),
		MediaType: string(desc.MediaType),
		Manifest:  json.RawMessage(desc.Manifest),
	}
	if parent != nil {
		view.Index = parent.Digest.String()
	}
	if desc.MediaType.IsIndex() {
		return writeIndexInspect(out, o.output, view, desc)
	}
	img, err := desc.Image()
	if err != nil {
		return fmt.Errorf("read the image %s: %w", c.flat, err)
	}
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		return fmt.Errorf("read the config of %s: %w", c.flat, err)
	}
	view.Config = json.RawMessage(rawCfg)
	if o.output == "json" {
		return writeInspectJSON(out, view)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("parse the config of %s: %w", c.flat, err)
	}
	m, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("parse the manifest of %s: %w", c.flat, err)
	}
	writeInspectTable(out, view, cf, m)
	return nil
}

// inspectView is the -o json document: the name, the digest, and the
// registry's documents as it serves them.
type inspectView struct {
	Reference string          `json:"reference"`
	Digest    string          `json:"digest"`
	MediaType string          `json:"mediaType"`
	Index     string          `json:"index,omitempty"`
	Manifest  json.RawMessage `json:"manifest"`
	Config    json.RawMessage `json:"config,omitempty"`
}

// writeInspectJSON prints view as indented JSON.
func writeInspectJSON(out io.Writer, view inspectView) error {
	b, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return fmt.Errorf("render the inspection as JSON: %w", err)
	}
	_, err = fmt.Fprintf(out, "%s\n", b)
	return err
}

// writeIndexInspect renders an index: its digest and each platform's manifest.
func writeIndexInspect(out io.Writer, format string, view inspectView, desc *remote.Descriptor) error {
	if format == "json" {
		return writeInspectJSON(out, view)
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return fmt.Errorf("read the index %s: %w", view.Reference, err)
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return fmt.Errorf("parse the index %s: %w", view.Reference, err)
	}
	fmt.Fprintf(out, "%-11s %s\n", "REFERENCE", view.Reference)
	fmt.Fprintf(out, "%-11s %s\n", "DIGEST", view.Digest)
	fmt.Fprintf(out, "%-11s %s\n", "MEDIATYPE", view.MediaType)
	fmt.Fprintf(out, "%-11s %d\n", "PLATFORMS", len(m.Manifests))
	for _, child := range m.Manifests {
		p := "unlabelled"
		if child.Platform != nil {
			p = child.Platform.String()
		}
		fmt.Fprintf(out, "  %-16s %s\n", p, child.Digest)
	}
	fmt.Fprintln(out, "(pass --platform to inspect one of them)")
	return nil
}

// writeInspectTable renders the human form of an image: the facts an operator
// came for, each one omitted when the config does not set it.
func writeInspectTable(out io.Writer, view inspectView, cf *ggcrv1.ConfigFile, m *ggcrv1.Manifest) {
	row := func(label, value string) {
		if value == "" {
			return
		}
		fmt.Fprintf(out, "%-11s %s\n", label, value)
	}
	row("REFERENCE", view.Reference)
	row("DIGEST", view.Digest)
	row("MEDIATYPE", view.MediaType)
	if p := cf.Platform(); p != nil {
		row("PLATFORM", p.String())
	}
	row("INDEX", view.Index)
	if !cf.Created.IsZero() {
		row("CREATED", cf.Created.UTC().Format(time.RFC3339))
	}
	row("USER", cf.Config.User)
	row("WORKDIR", cf.Config.WorkingDir)
	if v := cf.Config.Entrypoint; len(v) > 0 {
		row("ENTRYPOINT", fmt.Sprintf("%q", v))
	}
	if v := cf.Config.Cmd; len(v) > 0 {
		row("CMD", fmt.Sprintf("%q", v))
	}
	row("CONFIG", fmt.Sprintf("%s  %s", m.Config.Digest, humanBytes(blobBytes(m.Config.Size))))
	fmt.Fprintf(out, "%-11s %d\n", "LAYERS", len(m.Layers))
	total := blobBytes(m.Config.Size)
	seen := map[ggcrv1.Hash]bool{m.Config.Digest: true}
	for _, l := range m.Layers {
		fmt.Fprintf(out, "  %s  %s\n", l.Digest, humanBytes(blobBytes(l.Size)))
		if !seen[l.Digest] {
			seen[l.Digest] = true
			total += blobBytes(l.Size)
		}
	}
	fmt.Fprintf(out, "%-11s %s\n", "TOTAL", humanBytes(total))
	fmt.Fprintln(out, "(sizes are the registry's stored blob sizes, each distinct blob counted once)")
}

// blobBytes reads a descriptor size as an unsigned count, clamping a negative
// size, which is a malformed manifest, to zero rather than wrapping it.
func blobBytes(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
