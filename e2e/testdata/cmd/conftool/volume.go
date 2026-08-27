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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

// readfile reads -path and asserts it contains -contains and (when -mode is set)
// that its permission bits equal that octal. It reads the mount via Go's os
// package — libSystem open/fstatat, which the path-rebase DYLD shim interposes — so
// an absolute mount path (e.g. /etc/nats) resolves to the materialized copy under
// the pod data volume. A native workload is the ONLY thing that can observe a k3sm
// volume mount (a SIP platform binary like /bin/sh cannot load the shim), which is
// exactly why this is a compiled helper and not a shell script.
func readfile(args []string) {
	fs := flag.NewFlagSet("readfile", flag.ExitOnError)
	path := fs.String("path", "", "absolute mount path to read")
	contains := fs.String("contains", "", "substring the content must contain")
	mode := fs.String("mode", "", "expected octal permission bits, e.g. 0400 (optional)")
	_ = fs.Parse(args)
	if *path == "" {
		fail("readfile: -path is required")
	}

	if *mode != "" {
		var want uint32
		if _, err := fmt.Sscanf(*mode, "%o", &want); err != nil {
			fail("readfile: parse -mode %q: %v", *mode, err)
		}
		st, err := os.Stat(*path)
		if err != nil {
			fail("readfile: stat %s: %v", *path, err)
		}
		if got := uint32(st.Mode().Perm()); got != want {
			fail("readfile: %s mode = %04o, want %04o", *path, got, want)
		}
	}

	data, err := os.ReadFile(*path)
	if err != nil {
		fail("readfile: read %s: %v", *path, err)
	}
	if *contains != "" && !bytes.Contains(data, []byte(*contains)) {
		fail("readfile: %s does not contain %q", *path, *contains)
	}
	fmt.Printf("readfile: %s ok\n", *path)
}

// writeread writes a sentinel to -path, reads it back, and asserts it round-trips —
// the writable-scratch (emptyDir) assertion. Like readfile it goes through the
// path-rebase shim, so an absolute mount path lands in the materialized volume.
func writeread(args []string) {
	fs := flag.NewFlagSet("writeread", flag.ExitOnError)
	path := fs.String("path", "", "absolute mount path to write then read")
	token := fs.String("token", "conformance", "sentinel to write and verify")
	_ = fs.Parse(args)
	if *path == "" {
		fail("writeread: -path is required")
	}

	if err := os.WriteFile(*path, []byte(*token), 0o644); err != nil {
		fail("writeread: write %s: %v", *path, err)
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		fail("writeread: read %s: %v", *path, err)
	}
	if string(data) != *token {
		fail("writeread: %s = %q, want %q", *path, string(data), *token)
	}
	fmt.Printf("writeread: %s ok\n", *path)
}

// marker is the PVC-persistence probe: it creates -path with a fresh value ONLY if
// the file is absent, prints MARKER=<value> on every start, then idles so the pod
// stays Running while the test restarts it.
//
// It exists because this assertion cannot be made from /bin/sh. A PVC is symlinked
// at <rootfs><mountPath>, and with no mount namespace an absolute mount path only
// resolves there through the path-rebase DYLD shim -- which cannot be injected into
// a SIP platform binary such as /bin/sh (pkg/sandbox documents that ceiling). A Go
// helper loads the shim, so the absolute path lands in the persistent directory.
//
// Create-if-absent is the whole point: an unconditional write would re-mint the
// value on the restarted pod and the comparison would pass even if the volume were
// empty every time.
func marker(args []string) {
	fs := flag.NewFlagSet("marker", flag.ExitOnError)
	path := fs.String("path", "", "absolute mount path of the marker file")
	_ = fs.Parse(args)
	if *path == "" {
		fail("marker: -path is required")
	}

	data, err := os.ReadFile(*path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		v := fmt.Sprintf("v-%d-%d", time.Now().UnixNano(), os.Getpid())
		if werr := os.WriteFile(*path, []byte(v), 0o644); werr != nil {
			fail("marker: write %s: %v", *path, werr)
		}
		data = []byte(v)
	default:
		fail("marker: read %s: %v", *path, err)
	}

	fmt.Printf("MARKER=%s\n", string(data))
	for {
		time.Sleep(time.Hour)
	}
}
