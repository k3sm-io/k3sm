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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
)

// ackReviewed acknowledges s's floor as root reviews it now: its size and
// unattributable damage count, then the compare-and-set.
func ackReviewed(t *testing.T, s *FileStore) error {
	t.Helper()
	view, err := s.floorAckView(context.Background())
	if err != nil {
		t.Fatalf("floorAckView: %v", err)
	}
	return s.ackFloorDamage(context.Background(), view)
}

// The acknowledgement is compare-and-set: a damaged line appended after
// root's review makes it refuse, writing nothing, and the put stays
// refused; acknowledged against the floor as it now stands, it lifts.
func TestFloorDamageAckRefusesChangedFloor(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	appendLogBytes(t, s, userFloorLogName, []byte("\ngarbage\n"))
	view, err := s.floorAckView(ctx)
	if err != nil || view.unattributable != 1 {
		t.Fatalf("floorAckView: %+v, %v; want one unattributable line", view, err)
	}
	appendLogBytes(t, s, userFloorLogName, []byte("\nmore garbage\n"))
	if err := s.ackFloorDamage(ctx, view); !errors.Is(err, errAckStale) {
		t.Fatalf("an acknowledgement of a floor that changed after review: %v, want errAckStale", err)
	}
	if _, err := os.Lstat(s.dataRoot + "/" + floorAckName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused acknowledgement wrote the file: %v", err)
	}
	if _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put after a refused acknowledgement: %v, want errFloorDegraded", err)
	}
	grown := view
	grown.size += int64(len("\nmore garbage\n"))
	if err := s.ackFloorDamage(ctx, grown); !errors.Is(err, errAckStale) {
		t.Fatalf("an acknowledgement at the new size with the old damage count: %v, want errAckStale", err)
	}
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("an acknowledgement of the floor as it stands: %v", err)
	}
	if _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put after the acknowledgement: %v", err)
	}
}

// The acknowledgement's catch-up appends a live line for an entry whose
// put lost its floor line, but none for a generation a damaged line could
// name: that line could have been its tombstone.
func TestFloorDamageAckCatchUpSkipsAttributable(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected floor write failure") }
	for _, n := range []string{"named", "plain"} {
		if _, err := u.Put(ctx, "user/1001/"+n, KindOpaque, []byte("v")); !errors.Is(err, errCommitted) {
			t.Fatalf("put of %s whose floor line fails: %v, want errCommitted", n, err)
		}
	}
	fl.write = nil
	named, plain := entryGeneration(t, server, "named"), entryGeneration(t, server, "plain")
	// A skipped line whose generation is whole taints (named, gen), and
	// garbage is unattributable damage the acknowledgement lifts.
	appendLogBytes(t, s, userFloorLogName, fmt.Appendf(nil, "\nuser/1001 named %s 7\n\ngarbage\n", hex.EncodeToString(named[:])))
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	if live, err := s.userFloor.liveGens("user/1001", "plain"); err != nil || !slices.Contains(live, plain) {
		t.Fatalf("the acknowledgement's catch-up for an untainted lost line: %x, %v; want %x", live, err, plain)
	}
	if live, err := s.userFloor.liveGens("user/1001", "named"); err != nil || slices.Contains(live, named) {
		t.Fatalf("the acknowledgement's catch-up wrote a live line for a generation a damaged line names: %x, %v", live, err)
	}
}

// The compare-and-set covers the unrecovered count: a floor rewritten in
// place to the same size and the same unattributable count, one of its
// lines turned from an unattributable tear ("use", a scope prefix too
// short to name a uid) into an unrecovered line ("usx", no tear and no
// correction), is refused against the view root took before, writing
// nothing; root has to review the unrecovered line it would lift.
func TestFloorDamageAckRefusesStaleUnrecovered(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	base := readLog(t, s, userFloorLogName)
	setFloorBytes(t, s, append(slices.Clone(base), "\nuse\n"...))
	view, err := s.floorAckView(ctx)
	if err != nil || view.unattributable != 1 || view.unrecovered != 0 {
		t.Fatalf("floorAckView over a short scope tear: %+v, %v; want one unattributable line, none unrecovered", view, err)
	}
	setFloorBytes(t, s, append(slices.Clone(base), "\nusx\n"...))
	now, err := s.floorAckView(ctx)
	if err != nil || now.size != view.size || now.unattributable != view.unattributable || now.unrecovered != 1 {
		t.Fatalf("floorAckView over the rewrite: %+v, %v; want the size and unattributable count of %+v and one unrecovered line", now, err, view)
	}
	if err := s.ackFloorDamage(ctx, view); !errors.Is(err, errAckStale) {
		t.Fatalf("an acknowledgement whose view predates an unrecovered line: %v, want errAckStale", err)
	}
	if _, err := os.Lstat(s.dataRoot + "/" + floorAckName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused acknowledgement wrote the file: %v", err)
	}
	if err := s.ackFloorDamage(ctx, now); err != nil {
		t.Fatalf("an acknowledgement of the floor as it stands: %v", err)
	}
}

// The view gives each unrecovered line's byte offset, in file order, and
// counts only those lines as unrecovered: a tear is unattributable damage
// but not unrecovered.
func TestFloorAckViewGivesUnrecoveredOffsets(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	b := readLog(t, s, userFloorLogName)
	var want []int64
	for _, l := range []string{"garbage", "use", "more garbage"} {
		b = append(b, '\n')
		if l != "use" {
			want = append(want, int64(len(b)))
		}
		b = append(b, l+"\n"...)
	}
	setFloorBytes(t, s, b)
	view, err := s.floorAckView(ctx)
	if err != nil {
		t.Fatalf("floorAckView: %v", err)
	}
	if view.size != int64(len(b)) || view.unattributable != 3 || view.unrecovered != 2 || !slices.Equal(view.unrecoveredAt, want) {
		t.Fatalf("floorAckView: %+v; want size %d, 3 unattributable, 2 unrecovered at %v", view, len(b), want)
	}
	for _, off := range view.unrecoveredAt {
		if line, _, _ := bytes.Cut(b[off:], []byte{'\n'}); !bytes.Contains(line, []byte("garbage")) {
			t.Fatalf("offset %d starts %q, not an unrecovered line", off, line)
		}
	}
}
