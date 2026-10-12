//go:build integration && darwin

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

package binsign

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The C sources the real-mapping test builds. holder dlopens a dylib and keeps
// it mapped until its stdin closes; loader dlopens one in a fresh process and
// prints k3sm_ver().
const (
	holderSrc = `#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int main(int c, char **v) {
	void *h = dlopen(v[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "%s\n", dlerror()); return 1; }
	printf("mapped\n"); fflush(stdout);
	char b[1]; while (read(0, b, 1) > 0) {}
	return 0;
}
`
	loaderSrc = `#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
	void *h = dlopen(v[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "%s\n", dlerror()); return 1; }
	int (*f)(void) = (int (*)(void))dlsym(h, "k3sm_ver");
	if (!f) { fprintf(stderr, "no k3sm_ver\n"); return 1; }
	printf("%d\n", f());
	return 0;
}
`
)

// cc compiles src (written to dir/name.c) with args into dir/out.
func cc(t *testing.T, dir, name, src, out string, args ...string) string {
	t.Helper()
	c := filepath.Join(dir, name+".c")
	if err := os.WriteFile(c, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	o := filepath.Join(dir, out)
	if b, err := exec.Command("cc", append(append(args, "-o", o), c)...).CombinedOutput(); err != nil {
		t.Fatalf("cc %s: %v: %s", name, err, b)
	}
	return o
}

// holdMapped starts holder on lib and waits until the dylib is mapped. The
// holder is released and reaped at cleanup.
func holdMapped(t *testing.T, holder, lib string) {
	t.Helper()
	cmd := exec.Command(holder, lib)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "mapped" {
		t.Fatalf("holder did not map %s: %q, %v", lib, line, err)
	}
}

// load runs loader on lib in a fresh process: its output, and the signal that
// killed it (0 when it exited).
func load(t *testing.T, loader, lib string) (string, syscall.Signal, error) {
	t.Helper()
	out, err := exec.Command(loader, lib).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return string(out), ws.Signal(), err
		}
	}
	return string(out), 0, err
}

// TestReplacingAMappedDylibKeepsNewLoadsAlive is the real-kernel proof of the
// package's rule, on this host's macOS. A signed dylib is kept mapped by a live
// process (the holder, standing in for a pod that has it loaded); it is then
// replaced with new content through Install, and a FRESH process must load the
// new one and not be killed. The control subtest rewrites the mapped file in
// place instead and shows the kernel SIGKILLs the next loader, so the positive
// case is not passing for want of the failure. It also checks the signed file's
// code identifier is its final name, not the temp's.
//
// It runs on whatever macOS the host has (macOS 27 when written); macOS 26 runs
// the same code path but is not exercised here.
func TestReplacingAMappedDylibKeepsNewLoadsAlive(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no C compiler")
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("no codesign")
	}
	build := t.TempDir()
	v1 := cc(t, build, "v1", "int k3sm_ver(void) { return 1; }\n", "v1.dylib", "-dynamiclib")
	v2 := cc(t, build, "v2", "int k3sm_ver(void) { return 2; }\n", "v2.dylib", "-dynamiclib")
	holder := cc(t, build, "holder", holderSrc, "holder")
	loader := cc(t, build, "loader", loaderSrc, "loader")

	t.Run("Install over a mapped dylib: a new process loads the new one", func(t *testing.T) {
		lib := filepath.Join(t.TempDir(), "libk3sm_test.dylib")
		if err := Install(t.Context(), Codesign{}, v1, lib, 0o755); err != nil {
			t.Fatal(err)
		}
		holdMapped(t, holder, lib)
		if err := Install(t.Context(), Codesign{}, v2, lib, 0o755); err != nil {
			t.Fatal(err)
		}
		out, sig, err := load(t, loader, lib)
		if sig != 0 {
			t.Fatalf("the fresh loader was killed by %v after Install replaced a mapped dylib", sig)
		}
		if err != nil || strings.TrimSpace(out) != "2" {
			t.Fatalf("loader = %q, %v; want the new dylib (2)", out, err)
		}
		dv, _ := exec.Command("codesign", "-dv", lib).CombinedOutput()
		if !strings.Contains(string(dv), "Identifier=libk3sm_test.dylib\n") {
			t.Errorf("code identifier is not the final name:\n%s", dv)
		}
	})

	t.Run("control: an in-place rewrite of a mapped dylib gets the next load killed", func(t *testing.T) {
		lib := filepath.Join(t.TempDir(), "libk3sm_control.dylib")
		if err := Install(t.Context(), Codesign{}, v1, lib, 0o755); err != nil {
			t.Fatal(err)
		}
		holdMapped(t, holder, lib)
		// The forbidden write: same inode, truncated and rewritten.
		src, err := os.Open(v2)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = src.Close() }()
		dst, err := os.OpenFile(lib, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			t.Fatal(err)
		}
		if err := dst.Close(); err != nil {
			t.Fatal(err)
		}
		if _, sig, _ := load(t, loader, lib); sig != syscall.SIGKILL {
			t.Errorf("the loader after an in-place rewrite got signal %v, want SIGKILL: this macOS no longer reproduces the failure, so the positive subtest proves less", sig)
		}
	})
}
