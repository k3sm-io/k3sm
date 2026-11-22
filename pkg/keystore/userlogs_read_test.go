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
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// failingReaderAt fails every read with EIO.
type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, unix.EIO }

// A read I/O error on the floor is transient, not damage: it is
// errLogUnreadable, never ErrCorrupt, so a withdraw seals nothing and is
// refused with errWithdrawUnsealed rather than as damage, and a read
// refuses, and it is not kept, so the next read that works is served.
func TestFloorReadErrorIsNotDamage(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	fl := s.userFloor.(*fileFloorLog).log
	// A new line, so the next read reaches the file.
	line, err := floorLine("user/1001", "token", guid(0x77), 3)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, line)
	fl.readAt = func(*os.File) io.ReaderAt { return failingReaderAt{} }
	_, _, err = u.Current(ctx, "user/1001/token")
	if !errors.Is(err, errLogUnreadable) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("current when the floor read fails: %v, want errLogUnreadable and not ErrCorrupt", err)
	}
	if fl.state.bad != nil {
		t.Fatalf("a read error was kept as damage: %v", fl.state.bad)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, errWithdrawUnsealed) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw when the floor read fails: %v, want errWithdrawUnsealed and not ErrCorrupt", err)
	}
	fl.readAt = nil
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current once the floor reads again: %v", err)
	}
}
