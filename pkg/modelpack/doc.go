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

// Package modelpack builds a ModelPack (CNCF model-spec) artifact from a model
// directory, in k3sm's profile of it: one raw, uncompressed layer per file,
// typed with the artifact/v1 media types and carrying its path in the
// org.cncf.model.filepath and org.opencontainers.image.title annotations; a
// config recording the weight format, and the quantization and parameter size
// when the model's config.json records them; and the ModelPack artifactType
// on the manifest. The profile is a subset, so any ModelPack reader reads it.
//
// The model's config.json and a pushed config are untrusted: both are read
// bounded and fail-closed (unknown fields ignored, a value outside a short
// closed character set dropped, a malformed config.json giving no metadata
// rather than a refused push). Describe turns a manifest's layers and config
// into the metadata a listing shows.
//
// Every path goes through artifactv1.ValidatePathSet before any file is
// opened, so a code or pickle file is refused by its name and never read, and
// a directory that would not mount the same way on a case-insensitive volume
// is refused. The output is deterministic: layers sorted by path, no
// timestamps, so the same files always make the same manifest digest.
//
// A split weight set (model-0000N-of-0000M.safetensors with its
// model.safetensors.index.json, or -0000N-of-0000M.gguf) is one artifact with
// one layer per split, names preserved, and is refused when incomplete.
package modelpack
