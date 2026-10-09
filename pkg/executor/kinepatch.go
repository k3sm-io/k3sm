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

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// kineModulePath is the upstream kine module the child is built from.
const kineModulePath = "github.com/k3s-io/kine"

// kineSourcePatch is one exact-text edit k3sm carries against the pinned kine
// module source. old must occur exactly once in file; anything else fails the build,
// so a pin bump either still carries the fix or stops and makes someone look.
type kineSourcePatch struct {
	// name identifies the patch in errors.
	name string
	// file is the slash-separated path inside the kine module.
	file string
	// old is the upstream text replaced, and new its replacement.
	old, new string
}

// kinePatches is the patch set the kine child is built with. kineBuildVariant names
// it: any change to this list changes that variant, so every staged kine re-stages.
//
// migrate-scan-in-order: generic.(*Generic).Migrate issues BOTH of its COUNT(*)
// queries before scanning either, then returns after the first Scan (the legacy
// key_value table does not exist on any kine datastore k3sm creates). The second
// *sql.Row is never scanned, so its rows are never closed and its pooled connection
// is never returned. The pure-Go driver (modernc.org/sqlite) steps a statement when
// it is queried, so that connection holds an open read transaction for the life of
// the process. A read transaction pins the oldest WAL snapshot: no checkpoint can
// copy a frame past it, the WAL is never reset, and state.db-wal grows without bound
// (observed: 7 GB in 37 h on a single-node server). mattn/go-sqlite3 defers the step
// to the first Next, which is why the cgo build k3s ships does not show it. The fix
// scans each query before issuing the next, so both rows are closed by their Scan.
// Upstream: unfixed at v0.17.2 and on main (2026-10-09).
var kinePatches = []kineSourcePatch{{
	name: "migrate-scan-in-order",
	file: "pkg/drivers/generic/generic.go",
	old: `	var (
		count     = 0
		countKV   = d.queryRow(ctx, query.New("SELECT COUNT(*) FROM key_value", "?", false, ""))
		countKine = d.queryRow(ctx, query.New("SELECT COUNT(*) FROM kine", "?", false, ""))
	)

	if err := countKV.Scan(&count); err != nil || count == 0 {
		return
	}

	if err := countKine.Scan(&count); err != nil || count != 0 {
		return
	}
`,
	new: `	// Scan each COUNT before issuing the next: an unscanned *sql.Row keeps its
	// connection, and its statement's read transaction, open forever.
	count := 0
	if err := d.queryRow(ctx, query.New("SELECT COUNT(*) FROM key_value", "?", false, "")).Scan(&count); err != nil || count == 0 {
		return
	}

	if err := d.queryRow(ctx, query.New("SELECT COUNT(*) FROM kine", "?", false, "")).Scan(&count); err != nil || count != 0 {
		return
	}
`,
}}

// applyKinePatches applies patches to the kine module tree rooted at root. Each
// anchor must occur exactly once; an anchor that is missing or repeated is an error
// naming the patch, never a silent skip.
func applyKinePatches(root string, patches []kineSourcePatch) error {
	for _, p := range patches {
		path := filepath.Join(root, filepath.FromSlash(p.file))
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("kine patch %s: %w", p.name, err)
		}
		if n := bytes.Count(src, []byte(p.old)); n != 1 {
			return fmt.Errorf("kine patch %s does not apply to %s: its anchor occurs %d times, want exactly 1 (if upstream fixed it, drop the patch and change kineBuildVariant)", p.name, p.file, n)
		}
		out := bytes.Replace(src, []byte(p.old), []byte(p.new), 1)
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return fmt.Errorf("kine patch %s: %w", p.name, err)
		}
	}
	return nil
}

// buildPatchedKine builds kine at version from its module source with kinePatches
// applied, writing the binary to gopath/bin/kine. It returns the toolchain's combined
// output so a failure carries its own diagnostic.
//
// `go install module@version` cannot build a patched tree, so the steps are spelled
// out: `go mod download` fetches the module into the stable cache, checksum-verified
// against the Go checksum database exactly as `go install` would; the tree is copied
// out of the read-only cache into the scratch dir and patched there; and `go build
// -mod=readonly` builds it against kine's own go.sum, so the dependency graph is the
// one the upstream tag pins and every module is hash-checked. The flags match what
// `go install` used (no -trimpath), so dependency packages a previous build compiled
// stay cache hits. The upstream version is stamped into kine's version package, as
// kine's own release build does, so `kine --version` names the pin.
func buildPatchedKine(ctx context.Context, version, gopath, modCache string) ([]byte, error) {
	var log bytes.Buffer
	dl := exec.CommandContext(ctx, "go", "mod", "download", "-json", kineModulePath+"@"+version)
	dl.Dir = gopath
	dl.Env = append(kineBuildEnv(gopath, modCache), "GOFLAGS=")
	var stderr bytes.Buffer
	dl.Stderr = &stderr
	out, err := dl.Output()
	log.Write(out)
	log.Write(stderr.Bytes())
	if err != nil {
		return log.Bytes(), fmt.Errorf("go mod download %s@%s: %w", kineModulePath, version, err)
	}
	var mod struct{ Dir, Error string }
	if err := json.Unmarshal(out, &mod); err != nil {
		return log.Bytes(), fmt.Errorf("parse go mod download output: %w", err)
	}
	if mod.Error != "" || mod.Dir == "" {
		return log.Bytes(), fmt.Errorf("go mod download %s@%s: %s", kineModulePath, version, mod.Error)
	}

	src := filepath.Join(gopath, "src", "kine")
	if err := copyTree(mod.Dir, src); err != nil {
		return log.Bytes(), fmt.Errorf("copy kine %s source: %w", version, err)
	}
	if err := applyKinePatches(src, kinePatches); err != nil {
		return log.Bytes(), err
	}

	bin := filepath.Join(gopath, "bin", kineBinaryName)
	build := exec.CommandContext(ctx, "go", kineBuildArgs(version, bin)...)
	build.Dir = src
	build.Env = append(kineBuildEnv(gopath, modCache), "GOFLAGS=-mod=readonly")
	combined, err := build.CombinedOutput()
	log.Write(combined)
	return log.Bytes(), err
}

// kineBuildArgs is the `go build` argv for the patched kine tree.
func kineBuildArgs(version, out string) []string {
	return []string{"build", "-buildvcs=false", "-mod=readonly",
		"-ldflags", "-X " + kineModulePath + "/pkg/version.Version=" + version,
		"-o", out, "."}
}

// copyTree copies the regular files under src to dst, creating directories as it
// goes. Module trees hold only regular files and directories; anything else is
// refused rather than followed.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			return copyFile(path, target, 0o644)
		default:
			return fmt.Errorf("%s: not a regular file or directory", strings.TrimPrefix(path, src+string(filepath.Separator)))
		}
	})
}
