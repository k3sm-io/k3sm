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

package shadow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// DirName is the shadow set's directory under the install root.
const DirName = "shadow"

// ManifestName is the manifest's file name inside the shadow directory.
const ManifestName = "sources.json"

// Dir is the shadow directory for an install root.
func Dir(installDir string) string { return filepath.Join(installDir, DirName) }

// ManifestPath is the manifest's path for an install root.
func ManifestPath(installDir string) string { return filepath.Join(Dir(installDir), ManifestName) }

// Shell is one member of the set: the file name of the copy under the shadow
// directory and the host binary it is made from. The names are the contract
// with runtimed's shadowCopies map (bash also serves /bin/sh there: Apple's
// /bin/sh is a dispatcher that re-execs the platform shell, so it is never
// copied itself).
type Shell struct {
	Name   string
	Source string
}

// Shells is the set, in the order the installer makes it.
var Shells = []Shell{
	{Name: "bash", Source: "/bin/bash"},
	{Name: "zsh", Source: "/bin/zsh"},
	{Name: "dash", Source: "/bin/dash"},
	{Name: "env", Source: "/usr/bin/env"},
}

// ManifestVersion is the manifest schema version this package writes and reads.
const ManifestVersion = 1

// Manifest records the host binaries the set was made from.
type Manifest struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
}

// Source is one copy's provenance: the copy's name, the host binary, and that
// binary's cdhash when the copy was made.
type Source struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	CDHash string `json:"cdhash"`
}

// Encode renders m as the manifest file's bytes.
func Encode(m Manifest) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode shadow manifest: %w", err)
	}
	return append(b, '\n'), nil
}

// Decode parses a manifest, refusing an unknown version.
func Decode(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode shadow manifest: %w", err)
	}
	if m.Version != ManifestVersion {
		return Manifest{}, fmt.Errorf("decode shadow manifest: version %d, want %d", m.Version, ManifestVersion)
	}
	return m, nil
}

// Drifted is a source whose live cdhash no longer matches the manifest, or
// that could not be read.
type Drifted struct {
	Source Source
	Live   string // "" when the live binary could not be read
	Err    error
}

// Drift compares every manifest source with its live cdhash (cdhash is
// CDHash in production) and returns the ones that differ or cannot be read.
func Drift(m Manifest, cdhash func(path string) (string, error)) []Drifted {
	var out []Drifted
	for _, s := range m.Sources {
		live, err := cdhash(s.Path)
		if err != nil || live != s.CDHash {
			out = append(out, Drifted{Source: s, Live: live, Err: err})
		}
	}
	return out
}

// ErrNoCDHash is returned when codesign output carries no CDHash line (an
// unsigned binary).
var ErrNoCDHash = errors.New("no CDHash in codesign output")

// ParseCDHash extracts the CDHash value from `codesign -dvvv` output.
func ParseCDHash(out []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "CDHash="); ok && v != "" {
			return strings.ToLower(v), nil
		}
	}
	return "", ErrNoCDHash
}

// CDHash reads path's code directory hash through codesign (for a universal
// binary, the slice the host would run).
func CDHash(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, "codesign", "-dvvv", path).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codesign -dvvv %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	h, err := ParseCDHash(out)
	if err != nil {
		return "", fmt.Errorf("codesign -dvvv %s: %w", path, err)
	}
	return h, nil
}
