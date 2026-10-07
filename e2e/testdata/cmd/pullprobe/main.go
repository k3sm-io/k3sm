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

// Command pullprobe is the workload TestM10_ImagePullSecret pulls from its
// auth-gated registry. It runs from the pulled image's rootfs and does two
// things:
//
//   - prints the run's sentinel, the proof that the pulled binary executed;
//   - checks that no forbidden credential string reaches it: neither its own
//     process environment nor any regular file under its rootfs.
//
// The forbidden strings arrive only as "<length>:<sha256 hex>" so that the
// check itself never puts a credential into the pod spec, the environment or
// the log. Every window of that length in every scanned byte sequence is
// hashed and compared. On a match it names WHERE (env, or the file path) and
// never the bytes, then exits 3.
//
// The rootfs is found as the working directory (runtimed defaults it to the
// pod rootfs when the image declares no WORKDIR) and the directory holding the
// executable (the image puts it at /pullprobe); both are scanned, once each.
//
// stdlib only, CGO_ENABLED=0.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// maxScanFile bounds the bytes read from one file; a larger file is counted as
// skipped and reported, never silently passed.
const maxScanFile = 64 << 20

// forbidden is one credential string, by length and digest.
type forbidden struct {
	n   int
	sum [sha256.Size]byte
}

// forbiddenList is the repeatable -forbid-sha256 flag.
type forbiddenList []forbidden

func (f *forbiddenList) String() string { return strconv.Itoa(len(*f)) }

func (f *forbiddenList) Set(v string) error {
	ns, hx, ok := strings.Cut(v, ":")
	if !ok {
		return errors.New("want <length>:<sha256 hex>")
	}
	n, err := strconv.Atoi(ns)
	if err != nil || n <= 0 {
		return fmt.Errorf("bad length %q", ns)
	}
	raw, err := hex.DecodeString(hx)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("bad sha256 %q", hx)
	}
	var e forbidden
	e.n = n
	copy(e.sum[:], raw)
	*f = append(*f, e)
	return nil
}

// contains reports whether any window of b hashes to one of the forbidden digests.
func (f forbiddenList) contains(b []byte) bool {
	for _, e := range f {
		for i := 0; i+e.n <= len(b); i++ {
			if sha256.Sum256(b[i:i+e.n]) == e.sum {
				return true
			}
		}
	}
	return false
}

func main() {
	sentinel := flag.String("sentinel", "", "line printed first, proving the binary ran")
	var forbid forbiddenList
	flag.Var(&forbid, "forbid-sha256", "a forbidden string as <length>:<sha256 hex> (repeatable)")
	flag.Parse()
	if *sentinel == "" || len(forbid) == 0 {
		fmt.Fprintln(os.Stderr, "pullprobe: -sentinel and at least one -forbid-sha256 are required")
		os.Exit(2)
	}
	fmt.Println(*sentinel)

	leaks := 0
	env := os.Environ()
	for _, kv := range env {
		if forbid.contains([]byte(kv)) {
			k, _, _ := strings.Cut(kv, "=")
			fmt.Printf("B80-LEAK where=env name=%s\n", k)
			leaks++
		}
	}
	fmt.Printf("B80-ENV entries=%d\n", len(env))

	roots, err := scanRoots()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pullprobe: %v\n", err)
		os.Exit(2)
	}
	var files, skipped int
	var bytes int64
	for _, root := range roots {
		werr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Printf("B80-UNREADABLE path=%s\n", path)
				skipped++
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxScanFile {
				fmt.Printf("B80-SKIPPED path=%s\n", path)
				skipped++
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("B80-UNREADABLE path=%s\n", path)
				skipped++
				return nil
			}
			files++
			bytes += int64(len(b))
			if forbid.contains(b) {
				fmt.Printf("B80-LEAK where=file path=%s\n", path)
				leaks++
			}
			return nil
		})
		if werr != nil {
			fmt.Fprintf(os.Stderr, "pullprobe: walk %s: %v\n", root, werr)
			os.Exit(2)
		}
	}
	fmt.Printf("B80-ROOTS %s\n", strings.Join(roots, " "))
	fmt.Printf("B80-SCAN files=%d bytes=%d skipped=%d\n", files, bytes, skipped)
	if leaks > 0 {
		fmt.Printf("B80-CONFIDENTIALITY leaks=%d\n", leaks)
		os.Exit(3)
	}
	fmt.Println("B80-CONFIDENTIALITY clean")
}

// scanRoots returns the working directory and the executable's directory,
// symlink-resolved, with one dropped when it lies inside the other.
func scanRoots() ([]string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("getwd: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("executable: %w", err)
	}
	var roots []string
	for _, p := range []string{wd, filepath.Dir(exe)} {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", p, err)
		}
		roots = append(roots, r)
	}
	a, b := roots[0], roots[1]
	switch {
	case within(b, a):
		return []string{a}, nil
	case within(a, b):
		return []string{b}, nil
	}
	return roots, nil
}

// within reports whether p is root or lies under it.
func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
