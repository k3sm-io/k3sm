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

package keystore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRootFileServiceLinkReadsAsRoot, root-run: the service user link(2)s
// root's removed-scopes record and floor acknowledgement into a directory
// of its own, which it can, since both are root's unflagged files. Neither
// blocks anything: the record still reads and rm-scope still writes it, and
// the acknowledgement still lifts the damage it acknowledged.
func TestRootFileServiceLinkReadsAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	asService := func(f func() error) error {
		errc := make(chan error, 1)
		go func() {
			runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
			if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
				errc <- fmt.Errorf("settid: %w", errno)
				return
			}
			errc <- f()
		}()
		return <-errc
	}
	// The service user links by path, so it must search every parent: the
	// store is built under a root 0755 directory in /private/tmp, as in
	// TestRemoveScopeClearsServiceUserFlagsAsRoot.
	base, err := os.MkdirTemp("/private/tmp", "k3sm-rootlink-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", base)
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	for d := s.dataRoot; strings.HasPrefix(d, base) && d != base; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	own := filepath.Join(base, "service-own")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(own, int(svcUID), int(svcGID)); err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, []byte("\ngarbage\n"))
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	if _, err := s.RemoveScope(ctx, 1002); err != nil {
		t.Fatalf("RemoveScope: %v", err)
	}
	for _, name := range []string{removedScopesName, floorAckName} {
		if err := asService(func() error { return unix.Link(filepath.Join(s.dataRoot, name), filepath.Join(own, name)) }); err != nil {
			t.Fatalf("the service user's link of %s: %v", name, err)
		}
	}
	if r := readRecord(t, s); !r.listed(1002) {
		t.Fatal("the record linked by the service user does not list 1002")
	}
	if _, ok := s.readFloorAck(); !ok {
		t.Fatal("the acknowledgement linked by the service user is ignored")
	}
	if _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put under the linked acknowledgement: %v", err)
	}
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "re-minted")
	if _, err := s.RemoveScope(ctx, 1002); err != nil {
		t.Fatalf("rm-scope over the linked record: %v", err)
	}
}
