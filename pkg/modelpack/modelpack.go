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

package modelpack

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// The weight formats the config's format field records.
const (
	FormatSafetensors = "safetensors"
	FormatGGUF        = "gguf"
)

// modelFSLayers is the ModelPack modelfs type: the model's file system is the
// manifest's layers, in order.
const modelFSLayers = "layers"

// Sentinel errors a caller can branch on with errors.Is. A path the
// artifact/v1 rules refuse is reported with that package's sentinel.
var (
	// ErrNotRegular is a directory entry that is neither a regular file nor a
	// directory: a symbolic link is refused, never followed out of the model.
	ErrNotRegular = errors.New("not a regular file")
	// ErrNoWeights is a directory with no .safetensors or .gguf file.
	ErrNoWeights = errors.New("no weight file (.safetensors or .gguf)")
	// ErrMixedFormats is a directory holding both safetensors and GGUF weights.
	ErrMixedFormats = errors.New("both safetensors and gguf weights")
	// ErrIncompleteSplit is a split weight set missing a split, or a split
	// safetensors set missing its index.
	ErrIncompleteSplit = errors.New("incomplete split weight set")
	// ErrContentChanged is a file whose bytes no longer match the digest the
	// manifest records for it.
	ErrContentChanged = errors.New("file changed since the manifest was built")
)

// Config is the ModelPack config blob, in the fields k3sm's profile writes.
type Config struct {
	Config  ConfigFields `json:"config"`
	ModelFS ModelFS      `json:"modelfs"`
}

// ConfigFields is the config's config object: the weight format, required,
// and the quantization and parameter size when the model's config.json names
// them.
type ConfigFields struct {
	Format       string `json:"format"`
	ParamSize    string `json:"paramSize,omitempty"`
	Quantization string `json:"quantization,omitempty"`
}

// ModelFS is the config's modelfs object: the digest of every layer, in layer
// order. A raw layer's diff ID is its digest.
type ModelFS struct {
	Type    string          `json:"type"`
	DiffIDs []digest.Digest `json:"diffIds"`
}

// Layer is one file of the artifact: its validated path and its descriptor.
type Layer struct {
	Path       string
	Descriptor ispec.Descriptor
}

// Artifact is a built ModelPack artifact: the manifest and config bytes as
// they are pushed, and a layer per file. Open reads a layer's bytes from the
// directory it was built from.
type Artifact struct {
	// Manifest is the manifest's bytes; Digest is their digest.
	Manifest []byte
	Digest   digest.Digest
	// Config is the config blob's bytes; ConfigDescriptor names them.
	Config           []byte
	ConfigDescriptor ispec.Descriptor
	// Layers are the files, sorted by path, in manifest order.
	Layers []Layer

	fsys fs.FS
}

// Build builds the artifact for the model directory dir.
func Build(ctx context.Context, dir string) (*Artifact, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("model directory: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("model directory %s is not a directory", dir)
	}
	a, err := BuildFS(ctx, os.DirFS(dir))
	if err != nil {
		return nil, fmt.Errorf("model directory %s: %w", dir, err)
	}
	return a, nil
}

// BuildFS builds the artifact for the model whose files are fsys. It lists
// the files, validates every path and the profile's rules on the names alone,
// and only then reads: config.json for the config, and each file once to hash
// it.
func BuildFS(ctx context.Context, fsys fs.FS) (*Artifact, error) {
	paths, err := listFiles(fsys)
	if err != nil {
		return nil, err
	}
	if err := artifactv1.ValidatePathSet(paths); err != nil {
		return nil, err
	}
	slices.Sort(paths)
	format, err := checkProfile(paths)
	if err != nil {
		return nil, err
	}
	fields := ConfigFields{}
	if slices.Contains(paths, "config.json") {
		f, err := openRegular(fsys, "config.json")
		if err != nil {
			return nil, err
		}
		fields, err = readModelConfig(f)
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	fields.Format = format

	a := &Artifact{fsys: fsys}
	cfg := Config{Config: fields, ModelFS: ModelFS{Type: modelFSLayers, DiffIDs: []digest.Digest{}}}
	for _, p := range paths {
		d, size, err := hashFile(ctx, fsys, p)
		if err != nil {
			return nil, err
		}
		a.Layers = append(a.Layers, Layer{Path: p, Descriptor: ispec.Descriptor{
			MediaType: mediaTypeFor(p),
			Digest:    d,
			Size:      size,
			Annotations: map[string]string{
				artifactv1.AnnotationFilepath: p,
				ispec.AnnotationTitle:         p,
			},
		}})
		cfg.ModelFS.DiffIDs = append(cfg.ModelFS.DiffIDs, d)
	}

	if a.Config, err = json.Marshal(cfg); err != nil {
		return nil, fmt.Errorf("encode the model config: %w", err)
	}
	a.ConfigDescriptor = ispec.Descriptor{
		MediaType: artifactv1.MediaTypeModelConfig,
		Digest:    digest.FromBytes(a.Config),
		Size:      int64(len(a.Config)),
	}
	m := ispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ispec.MediaTypeImageManifest,
		ArtifactType: artifactv1.ArtifactTypeModel,
		Config:       a.ConfigDescriptor,
		Layers:       make([]ispec.Descriptor, 0, len(a.Layers)),
	}
	for _, l := range a.Layers {
		m.Layers = append(m.Layers, l.Descriptor)
	}
	if a.Manifest, err = json.Marshal(m); err != nil {
		return nil, fmt.Errorf("encode the model manifest: %w", err)
	}
	a.Digest = digest.FromBytes(a.Manifest)
	return a, nil
}

// listFiles walks fsys and returns every regular file's path. It reads
// directory entries only, never a file's bytes, and stops as soon as the
// count or depth passes what ValidatePathSet would accept.
func listFiles(fsys fs.FS) ([]string, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		switch {
		case d.IsDir():
			if strings.Count(p, "/")+1 >= artifactv1.MaxPathDepth {
				return fmt.Errorf("%q: %w", p+"/", artifactv1.ErrPathDepth)
			}
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%q (%s): %w", p, d.Type(), ErrNotRegular)
		}
		if len(paths) == artifactv1.MaxPaths {
			return fmt.Errorf("more than %d files: %w", artifactv1.MaxPaths, artifactv1.ErrTooManyPaths)
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

// splitPattern matches a split weight file: <prefix>-<i>-of-<n>.<ext>, five
// digits each, as Hugging Face and llama.cpp's gguf-split name them.
var splitPattern = regexp.MustCompile(`^(.+)-([0-9]{5})-of-([0-9]{5})\.(safetensors|gguf)$`)

// checkProfile applies the profile's rules to the names: exactly one weight
// format, and every split set complete (a split safetensors set with its
// index). It returns the format.
func checkProfile(paths []string) (string, error) {
	present := make(map[string]bool, len(paths))
	for _, p := range paths {
		present[p] = true
	}
	var safetensors, gguf bool
	type set struct{ prefix, ext, total string }
	splits := map[set]bool{}
	for _, p := range paths {
		switch strings.ToLower(path.Ext(p)) {
		case ".safetensors":
			safetensors = true
		case ".gguf":
			gguf = true
		}
		if m := splitPattern.FindStringSubmatch(p); m != nil {
			splits[set{prefix: m[1], ext: m[4], total: m[3]}] = true
		}
	}
	for s := range splits {
		n, _ := strconv.Atoi(s.total)
		if n == 0 {
			return "", fmt.Errorf("%s-*-of-%s.%s: a set of zero splits: %w", s.prefix, s.total, s.ext, ErrIncompleteSplit)
		}
		for i := 1; i <= n; i++ {
			want := fmt.Sprintf("%s-%05d-of-%s.%s", s.prefix, i, s.total, s.ext)
			if !present[want] {
				return "", fmt.Errorf("%s is missing: %w", want, ErrIncompleteSplit)
			}
		}
		if s.ext == FormatSafetensors {
			if index := s.prefix + ".safetensors.index.json"; !present[index] {
				return "", fmt.Errorf("%s-*-of-%s.safetensors has no %s: %w", s.prefix, s.total, index, ErrIncompleteSplit)
			}
		}
	}
	switch {
	case safetensors && gguf:
		return "", ErrMixedFormats
	case safetensors:
		return FormatSafetensors, nil
	case gguf:
		return FormatGGUF, nil
	}
	return "", ErrNoWeights
}

// mediaTypeFor is the layer media type of the file at p: weights by
// extension, documentation by name, and every other file (tokenizer,
// config.json, the safetensors index, templates) weight config. Code never
// reaches here: ValidatePath refuses it by name.
func mediaTypeFor(p string) string {
	base := strings.ToLower(path.Base(p))
	switch {
	case strings.HasSuffix(base, ".safetensors"), strings.HasSuffix(base, ".gguf"):
		return artifactv1.MediaTypeModelWeight
	case strings.HasSuffix(base, ".md"):
		return artifactv1.MediaTypeModelDoc
	}
	for _, doc := range []string{"readme", "license", "licence", "notice", "copying"} {
		if strings.HasPrefix(base, doc) {
			return artifactv1.MediaTypeModelDoc
		}
	}
	return artifactv1.MediaTypeModelWeightConfig
}

// hashFile returns the digest and size of the regular file at p.
func hashFile(ctx context.Context, fsys fs.FS, p string) (digest.Digest, int64, error) {
	f, err := openRegular(fsys, p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, ctxReader{ctx: ctx, r: f})
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", p, err)
	}
	return digest.NewDigest(digest.SHA256, h), n, nil
}

// openRegular opens p and refuses it unless it is a regular file.
func openRegular(fsys fs.FS, p string) (fs.File, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err // an fs.PathError names the op and the path
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%q (%s): %w", p, st.Mode().Type(), ErrNotRegular)
	}
	return f, nil
}

// Open reads layer l's bytes from the directory the artifact was built from.
// The read is verified: it ends in ErrContentChanged, not io.EOF, when the
// bytes are not the ones the manifest names, so a file rewritten since Build
// is never uploaded under the old digest.
func (a *Artifact) Open(l Layer) (io.ReadCloser, error) {
	f, err := openRegular(a.fsys, l.Path)
	if err != nil {
		return nil, err
	}
	return &verifiedReader{f: f, path: l.Path, want: l.Descriptor, h: sha256.New()}, nil
}

// verifiedReader hashes what it reads and checks size and digest at the end.
type verifiedReader struct {
	f    fs.File
	path string
	want ispec.Descriptor
	h    hash.Hash
	n    int64
}

func (v *verifiedReader) Read(p []byte) (int, error) {
	n, err := v.f.Read(p)
	v.h.Write(p[:n])
	v.n += int64(n)
	if v.n > v.want.Size {
		return n, fmt.Errorf("%s: more than %d bytes: %w", v.path, v.want.Size, ErrContentChanged)
	}
	if errors.Is(err, io.EOF) {
		if got := digest.NewDigest(digest.SHA256, v.h); v.n != v.want.Size || got != v.want.Digest {
			return n, fmt.Errorf("%s: now %s (%d bytes), the manifest names %s (%d bytes): %w", v.path, got, v.n, v.want.Digest, v.want.Size, ErrContentChanged)
		}
	}
	return n, err
}

func (v *verifiedReader) Close() error { return v.f.Close() }

// ctxReader stops a read when ctx is done, so hashing a large file honours
// cancellation.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
