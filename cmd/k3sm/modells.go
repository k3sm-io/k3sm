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
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"

	"k3sm.io/k3sm/pkg/modelpack"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/runtimed/pkg/artifact"
)

// modelReportSchemaVersion versions `k3sm model ls -o json`. The document
// only ever grows: a new key is added, an existing one never changes meaning,
// and a consumer (the app) refuses a version it does not know.
const modelReportSchemaVersion = 1

// maxModelTags caps the tags one listing walks, models or not, so a
// registry holding an unbounded number of tags cannot make the listing
// unbounded. A variable so a test can lower it.
var maxModelTags = 10000

// modelRow is one model tag in the registry and what its manifest and
// ModelPack config record. A value the model does not record is "" or 0.
type modelRow struct {
	// Name is the model's name as push and rm take it: the repository
	// without models/.
	Name         string `json:"name"`
	Repository   string `json:"repository"`
	Tag          string `json:"tag"`
	Reference    string `json:"reference"`
	Digest       string `json:"digest"`
	Format       string `json:"format"`
	SizeBytes    int64  `json:"sizeBytes"`
	Files        int    `json:"files"`
	Shards       int    `json:"shards"`
	Quantization string `json:"quantization"`
	ParamSize    string `json:"paramSize"`
	// Variant is the io.k3sm.model.variant annotation of the index entry
	// this row describes, and Index the digest of that index, when the tag
	// names a variant index; both omitted for a tag naming one manifest.
	// Digest is then the variant's own manifest.
	Variant string `json:"variant,omitempty"`
	Index   string `json:"index,omitempty"`
	// Error is why the row carries no metadata: its manifest or config
	// could not be read. Omitted when there is none.
	Error string `json:"error,omitempty"`
}

// modelListReport is `k3sm model ls -o json`.
type modelListReport struct {
	SchemaVersion int            `json:"schemaVersion"`
	Registry      registryReport `json:"registry"`
	Models        []modelRow     `json:"models"`
	// Truncated is set when the listing stopped at maxModelTags tags, so
	// more models may exist than are listed. Omitted when false.
	Truncated bool `json:"truncated,omitempty"`
}

// modelLs lists the models in the cluster registry: every tag of a
// repository under models/ whose manifest carries the ModelPack artifactType,
// or whose index lists model variants (one row per variant), with the
// metadata its manifest and config record. It reads one manifest
// and one config blob per tag and never a file of the model. A registry that
// does not answer is reported, not an error, as `k3sm image ls` does.
func modelLs(ctx context.Context, o modelOptions, out io.Writer, env imageRegistryEnv) error {
	rep := modelListReport{SchemaVersion: modelReportSchemaVersion, Registry: registryReport{Name: canonicalRegistry}, Models: []modelRow{}}
	rows, truncated, err := listModels(ctx, env)
	if err != nil {
		rep.Registry.Error = err.Error()
	} else {
		rep.Registry.Reachable = true
		rep.Models, rep.Truncated = rows, truncated
	}
	if o.output == "json" {
		return writeImageReport(out, rep)
	}
	return renderModelList(out, rep)
}

// listModels reads the model rows, sorted by repository and tag. It walks
// at most maxModelTags tags; truncated reports that it stopped there.
func listModels(ctx context.Context, env imageRegistryEnv) (rows []modelRow, truncated bool, err error) {
	reg, err := openRegistry(ctx, env)
	if err != nil {
		return nil, false, err
	}
	repos := slices.Sorted(slices.Values(reg.repos))
	rows = []modelRow{}
	walked := 0
	for _, repo := range repos {
		if !strings.HasPrefix(repo, modelRepositoryPrefix) {
			continue
		}
		tags, err := reg.c.Tags(ctx, repo)
		if err != nil {
			return nil, false, err
		}
		slices.Sort(tags)
		for _, tag := range tags {
			if !registryclient.ValidTag(tag) {
				continue
			}
			if walked == maxModelTags {
				return rows, true, nil
			}
			walked++
			rows = append(rows, describeTag(ctx, reg.c, repo, tag)...)
		}
	}
	return rows, false, nil
}

// describeTag is the rows of repo:tag: one for a ModelPack manifest, one
// per variant entry for an OCI image index of model variants (entries
// carrying the io.k3sm.model.variant annotation, in index order), none for
// anything else (an image, an index of images). An index over the runtime's
// size or entry caps is one row with Error set, and its entries are not read.
func describeTag(ctx context.Context, c *registryclient.Client, repo, tag string) []modelRow {
	row := modelRow{
		Name:       strings.TrimPrefix(repo, modelRepositoryPrefix),
		Repository: repo,
		Tag:        tag,
		Reference:  canonicalRegistry + "/" + repo + ":" + tag,
	}
	m, err := c.Manifest(ctx, repo, tag)
	if err != nil {
		row.Error = err.Error()
		return []modelRow{row}
	}
	if !m.IsIndex() {
		if r, ok := describeModel(ctx, c, m, row); ok {
			return []modelRow{r}
		}
		return nil
	}
	if m.MediaType != registryclient.MediaTypeOCIIndex {
		return nil
	}
	if len(m.Raw) > artifact.MaxIndexBytes || len(m.Manifests) > artifact.MaxIndexEntries {
		row.Index = m.Digest
		row.Error = fmt.Sprintf("model %s:%s: index of %d bytes and %d entries, at most %d and %d", repo, tag, len(m.Raw), len(m.Manifests), artifact.MaxIndexBytes, artifact.MaxIndexEntries)
		return []modelRow{row}
	}
	var rows []modelRow
	for i, e := range m.Manifests {
		variant, ok := e.Annotations[artifact.AnnotationVariant]
		if !ok {
			continue
		}
		vr := row
		vr.Index = m.Digest
		// The variant and the entry digest are registry content: checked
		// before either can reach a row, and a bad one is named by index.
		if modelpack.ValidateVariant(variant) != nil || e.MediaType != registryclient.MediaTypeOCIManifest || !registryclient.ValidDigest(e.Digest) {
			vr.Error = fmt.Sprintf("model %s:%s: index entry %d is not a valid variant entry", repo, tag, i)
			rows = append(rows, vr)
			continue
		}
		vr.Variant = variant
		vm, err := c.Manifest(ctx, repo, e.Digest)
		if err != nil {
			vr.Error = err.Error()
			rows = append(rows, vr)
			continue
		}
		if vm.IsIndex() {
			vr.Error = fmt.Sprintf("model %s:%s: variant %s names an index, not a manifest", repo, tag, variant)
			rows = append(rows, vr)
			continue
		}
		if r, ok := describeModel(ctx, c, vm, vr); ok {
			rows = append(rows, r)
		}
	}
	return rows
}

// describeModel fills row from manifest m and, when it is a ModelPack
// manifest, its config. ok is false for anything that is not a model. A
// model whose config cannot be read is a row with Error set and no metadata,
// never a failed listing.
func describeModel(ctx context.Context, c *registryclient.Client, m registryclient.Manifest, row modelRow) (modelRow, bool) {
	repo, tag := row.Repository, row.Tag
	if m.Config == nil || artifactv1.ArtifactType(m.ArtifactType, m.Config.MediaType) != artifactv1.ArtifactTypeModel {
		return modelRow{}, false
	}
	row.Digest = m.Digest
	// A layer digest is registry content: checked before it can reach an
	// error string, and the error names its index, not its bytes.
	for i, l := range m.Layers {
		if !registryclient.ValidDigest(l.Digest) {
			row.Error = fmt.Sprintf("model %s:%s: layer %d has an invalid digest", repo, tag, i)
			return row, true
		}
	}
	config, err := c.Blob(ctx, repo, *m.Config, modelpack.MaxConfigBytes)
	if err != nil {
		row.Error = err.Error()
		return row, true
	}
	layers := make([]ispec.Descriptor, 0, len(m.Layers))
	for _, l := range m.Layers {
		layers = append(layers, ispec.Descriptor{MediaType: l.MediaType, Digest: digest.Digest(l.Digest), Size: l.Size})
	}
	md, err := modelpack.Describe(layers, config)
	if err != nil {
		row.Error = fmt.Sprintf("model %s:%s: %v", repo, tag, err)
		return row, true
	}
	row.Format, row.SizeBytes, row.Files, row.Shards = md.Format, md.SizeBytes, md.Files, md.Shards
	row.Quantization, row.ParamSize = md.Quantization, md.ParamSize
	return row, true
}

// printable is s with every C0 and C1 control character and DEL removed,
// and invalid UTF-8 replaced: the one sink filter for text the table prints,
// so registry content can never drive the terminal. JSON output needs none;
// encoding/json escapes control characters.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, string(utf8.RuneError)))
}

// renderModelList is ls's table. Every string it prints goes through
// printable.
func renderModelList(out io.Writer, rep modelListReport) error {
	p := printable
	if !rep.Registry.Reachable {
		fmt.Fprintf(out, "registry %s is unreachable: %s\n", p(rep.Registry.Name), p(rep.Registry.Error))
		return nil
	}
	if len(rep.Models) == 0 {
		fmt.Fprintf(out, "no models in registry %s.\n", p(rep.Registry.Name))
		renderModelTruncated(out, rep)
		return nil
	}
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return p(s)
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVARIANT\tFORMAT\tQUANT\tPARAMS\tSIZE\tFILES\tSHARDS\tDIGEST")
	var failed []modelRow
	for _, r := range rep.Models {
		if r.Error != "" {
			failed = append(failed, r)
			fmt.Fprintf(tw, "%s:%s\t%s\t-\t-\t-\t-\t-\t-\t%s\n", p(r.Name), p(r.Tag), dash(r.Variant), dash(shortDigest(r.Digest)))
			continue
		}
		fmt.Fprintf(tw, "%s:%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p(r.Name), p(r.Tag), dash(r.Variant), dash(r.Format), dash(r.Quantization),
			dash(r.ParamSize), humanBytes(uint64(max(r.SizeBytes, 0))), strconv.Itoa(r.Files), strconv.Itoa(r.Shards), dash(shortDigest(r.Digest)))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, r := range failed {
		fmt.Fprintf(out, "(%s:%s: no metadata: %s)\n", p(r.Name), p(r.Tag), p(r.Error))
	}
	renderModelTruncated(out, rep)
	return nil
}

// renderModelTruncated is the table's last line when the listing stopped
// at its cap.
func renderModelTruncated(out io.Writer, rep modelListReport) {
	if rep.Truncated {
		fmt.Fprintf(out, "(listing stopped after %d tags; more models may exist)\n", maxModelTags)
	}
}
