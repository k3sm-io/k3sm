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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/hostshare"
)

func TestShareVerb(t *testing.T) {
	t.Parallel()
	base, err := os.MkdirTemp("/private/tmp", "k3sm-share-")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "code")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	newEnv := func(euid int) (shareEnv, *bytes.Buffer, *bytes.Buffer) {
		var out, errb bytes.Buffer
		return shareEnv{
			file: "/node/host-shares",
			euid: func() int { return euid },
			read: func(string) ([]hostshare.Entry, error) {
				return hostshare.Parse(bytes.NewReader(stored))
			},
			write:  func(_ string, b []byte) error { stored = append([]byte(nil), b...); return nil },
			stdout: &out, stderr: &errb,
		}, &out, &errb
	}

	env, _, errb := newEnv(501)
	if code := runShareWith([]string{"add", dir}, env); code != 3 {
		t.Fatalf("add as non-root = %d (%s), want 3", code, errb)
	}
	env, out, errb := newEnv(0)
	if code := runShareWith([]string{"add", dir}, env); code != 0 {
		t.Fatalf("add = %d (%s), want 0", code, errb)
	}
	if !strings.Contains(out.String(), "chmod -R +a \"user:_k3sm allow") {
		t.Errorf("add did not print the ACL command:\n%s", out)
	}
	if !strings.Contains(string(stored), "rw "+dir+"\n") {
		t.Errorf("stored list = %q, want an rw line for %s", stored, dir)
	}
	env, _, _ = newEnv(0)
	if code := runShareWith([]string{"add", "--read-only", dir}, env); code != 0 {
		t.Fatal("re-add as read-only failed")
	}
	if strings.Contains(string(stored), "rw "+dir) || !strings.Contains(string(stored), "ro "+dir) {
		t.Errorf("re-add did not replace the entry: %q", stored)
	}
	env, out, _ = newEnv(501)
	if code := runShareWith([]string{"list"}, env); code != 0 || !strings.Contains(out.String(), "ro "+dir) {
		t.Errorf("list = %d %q", code, out)
	}
	for _, args := range [][]string{
		{"add", "/Users"},
		{"add", filepath.Join(base, "missing")},
		{"add", "--socket", dir},
		{"remove", filepath.Join(base, "never")},
	} {
		env, _, _ = newEnv(0)
		if code := runShareWith(args, env); code != 1 {
			t.Errorf("share %v = %d, want 1", args, code)
		}
	}
	env, _, _ = newEnv(0)
	if code := runShareWith([]string{"add", "--read-only", "--socket", dir}, env); code != 2 {
		t.Errorf("conflicting flags = %d, want 2", code)
	}
	env, _, _ = newEnv(0)
	if code := runShareWith([]string{"remove", dir}, env); code != 0 {
		t.Fatal("remove failed")
	}
	if got, _ := hostshare.Parse(bytes.NewReader(stored)); len(got) != 0 {
		t.Errorf("after remove the list holds %v", got)
	}
}
