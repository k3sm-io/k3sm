//go:build darwin && integration

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

package hostacl

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestGrantSocket grants and revokes the connect entry on a real Unix socket.
// It binds one, so it runs only with the integration tag. It uses only the
// exported API, so it also compiles without cgo, where acl(3) is unavailable
// and it skips.
func TestGrantSocket(t *testing.T) {
	const uid = 4294967294 // nobody's entry, as in the unit tests
	dir, err := os.MkdirTemp("", "hostacl-sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "q.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	changed, err := GrantSocket(sock, uid)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("acl(3) needs cgo")
	}
	if err != nil || !changed {
		t.Fatalf("GrantSocket = %v, %v", changed, err)
	}
	if p, err := Allowed(sock, uid); err != nil || p&Write == 0 {
		t.Errorf("Allowed after GrantSocket = %v, %v; want write", p, err)
	}
	if changed, err := RevokeSocket(sock, uid); err != nil || !changed {
		t.Errorf("RevokeSocket = %v, %v", changed, err)
	}
	if p, err := Allowed(sock, uid); err != nil || p&Write != 0 {
		t.Errorf("Allowed after RevokeSocket = %v, %v; want no write", p, err)
	}
}
