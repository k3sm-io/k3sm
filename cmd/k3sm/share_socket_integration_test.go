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

package main

import (
	"net"
	"path/filepath"
	"testing"
)

// TestShareDelegatedSocket is the socket leg of TestShareDelegation: after a
// delegation with the socket mode, the delegated user adds a real Unix socket
// under the prefix without root, and the connect entry is set as the owner. It
// binds a socket, so it runs only with the integration tag.
func TestShareDelegatedSocket(t *testing.T) {
	t.Parallel()
	f := newShareFixture(t)
	env, _, errb := f.env(0)
	if code := runShareWith([]string{"delegate", "--user", "dev", "--modes", "rw,socket", f.prefix}, env); code != 0 {
		t.Fatalf("delegate = %d (%s)", code, errb)
	}
	sock := filepath.Join(f.prefix, "q.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f.acl.calls = nil
	env, _, errb = f.env(int(f.me.uid))
	if code := runShareWith([]string{"add", "--socket", sock}, env); code != 0 || !f.acl.did("grant-socket "+sock) {
		t.Errorf("delegated socket add = %d (%s), calls %v", code, errb, f.acl.calls)
	}
}
