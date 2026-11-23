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
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// The newest-scope rule (docs/design/keystore.md § "A removed scope stays
// removed"): the removed-scopes record proves that a KEY is listed, not
// that it is the uid's newest scope. A tree-writer that kept a copy of a
// listed scope.key, or parked an interrupted run's leftover, can put it at
// the scope's name while the uid's live scope is renamed away. Only the
// real server mints a scope, and every mint writes a floor line of the
// scope (the delivery record's), so a scope minted after the proving key's
// listing leaves a line of user/<uid> past the floor position recorded at
// that listing. rm-scope exits 0 only when there is none.

// The created-twice rule, inside the same scan: every mint of a scope
// appends the same floor line for the uid, its empty delivery record at
// sequence 1 (mint, writeDeliveries), before scope.key is written, with no
// de-duplication, and the append-only floor keeps it. One such line since
// the uid's last listing is the judged scope's own mint; more than one
// means the uid's scope was created more than once since, so another scope
// of this uid may be held away from its name while rm-scope removes and
// lists the one at the name. The rule is fail-closed (an extra line only
// turns exit 0 into exit 4, so a forged line costs a false exit 4, never a
// false exit 0) and partial: a floor --rebuild between the mints and the
// rm-scope drops the earlier scope's lines and erases the evidence, and
// when the name is left empty there is no run to judge (exit 1, found
// absent). It does not close the open limit of a scope kept away from its
// name (docs/design/keystore.md § "A removed scope stays removed").

// errFloorLater is the floor scan's stop at the first later line.
var errFloorLater = errors.New("a later floor line of the uid")

// errCreatedTwice is the created-twice rule's refusal of exit 0.
var errCreatedTwice = errors.New("the floor shows this uid's scope was created more than once since its last listing")

// rmFloorOpen is the newest-scope rule's open of the floor (openOldLog);
// tests replace it to inject a failure.
var rmFloorOpen = (*FileStore).openOldLog

// newestScope is the newest-scope rule, the one gate of rm-scope's exit 0
// (finish): it returns nil only when the user-scope floor holds no line of
// user/<uid> written after the listing of the key that proves this run
// (r.held.id). For a key this run listed, the position is the floor's
// identity and size read under the store lock at the listing (list); for
// a key an earlier run listed, the uid's floor identity and size in the
// record as this run read it (prior), which is the uid's latest listing.
// A floor of another identity than the recorded one (rebuilt since), or a
// recorded identity that is not whole, makes every line of user/<uid> in
// the current floor count as later. The floor is opened and judged as
// rebuild reads it (openOldLog: root's descriptor, O_NOFOLLOW, a regular
// file flagged SF_APPEND or root's) and streamed once with floorLines,
// bounded by its size at the open and one line's buffer; a line that does
// not parse is not a mint's and is skipped. A floor that cannot be opened,
// judged or read, or a recorded position past its end, is a non-nil
// error too: never exit 0 on what cannot be judged. rm-scope holds the
// floor lock and the exclusive store lock here, so no server write runs:
// a hostile append can only add a line, which turns exit 0 into exit 4,
// never the reverse.
//
// The created-twice rule counts the uid's sequence-1 delivery-record lines
// in its own window, from the uid's position in the record as this run
// read it before any write (prior; byte 0 when the record did not list the
// uid, or when that position's floor identity is not whole or not the
// current floor's), to the floor's end at the open. For a key this run
// listed that window starts before the listing, not at it: the judged
// scope's own mint line lies before the listing position. For a key an
// earlier run listed, both windows start at prior. More than one such line
// is errCreatedTwice, judged after the later-line rule, whose text wins
// when both apply.
func (r *rmRun) newestScope() error {
	var want floorIdentity
	var from int64
	switch {
	case r.listedBefore && r.priorOK:
		from = r.prior.FloorSize
		if id := r.prior.identity(); id.whole() {
			want = id
		}
	case r.listedBefore:
		return errors.New("the record holds no floor position for this uid")
	case r.listedNow:
		want, from = r.listFloor, r.listSize
	default:
		return errors.New("this run read no floor position at the listing")
	}
	lfd, err := r.s.openLogsDir(r.dfd)
	if err != nil {
		return fmt.Errorf("the logs directory could not be opened: %s", safeText(err.Error()))
	}
	defer func() { _ = unix.Close(lfd) }() // read-only directory descriptor
	o, err := rmFloorOpen(r.s, lfd, userFloorLogName)
	if errors.Is(err, unix.ENOENT) && want.ino == 0 && from == 0 {
		// No floor at the listing and none now: no line of any scope.
		return nil
	}
	if err != nil {
		return fmt.Errorf("the floor %s could not be opened or judged: %s", userFloorLogName, safeText(err.Error()))
	}
	defer o.close()
	if want.ino == 0 || o.id != want {
		// Another floor than the one the position belongs to.
		from = 0
	}
	if from > o.size {
		return fmt.Errorf("the floor position recorded at the listing (%d bytes) is past the floor's end (%d bytes)", from, o.size)
	}
	// The created-twice window: from the uid's previous listing, whatever
	// this run listed.
	var mintFrom int64
	if r.priorOK {
		if id := r.prior.identity(); id.whole() && o.id == id {
			mintFrom = r.prior.FloorSize
		}
	}
	if mintFrom > o.size {
		return fmt.Errorf("the floor position recorded at the uid's last listing (%d bytes) is past the floor's end (%d bytes)", mintFrom, o.size)
	}
	base := min(from, mintFrom)
	scope := r.u.scope
	mints := 0
	_, _, err = floorLines(io.NewSectionReader(o.f, base, o.size-base), maxLogLine, func(line []byte, start int64, lerr error) error {
		if lerr != nil {
			return nil
		}
		rec, perr := parseFloorLine(line)
		if perr != nil || rec.key.scope != scope {
			return nil
		}
		at := base + start
		if at >= from {
			return errFloorLater
		}
		if at >= mintFrom && rec.key.name == deliveriesFloorName && !rec.tomb && rec.seq == 1 {
			mints++
		}
		return nil
	})
	switch {
	case errors.Is(err, errFloorLater) && from == 0 && want.ino != 0:
		return fmt.Errorf("the floor %s is not the file the listing recorded (it was rebuilt or replaced since) and holds a line of %s", userFloorLogName, scope)
	case errors.Is(err, errFloorLater):
		return fmt.Errorf("the floor %s holds a line of %s written after that key was listed", userFloorLogName, scope)
	case err != nil:
		return fmt.Errorf("the floor %s could not be read: %s", userFloorLogName, safeText(err.Error()))
	case mints > 1:
		return errCreatedTwice
	}
	return nil
}

// newestNote is finish's committed note when the newest-scope rule (why)
// refuses exit 0 for a removal that proved its key listed.
func (r *rmRun) newestNote(why error) string {
	if errors.Is(why, errCreatedTwice) {
		return "removed the directory at the name of " + r.u.scope + ", whose scope.key is listed in " + removedScopesName + ", but " + why.Error() + " (" + userFloorLogName + " holds more than one creation line of " + r.u.scope + "), so another scope of this uid may be held away from its name: rm-scope removed and listed the one at the name, and any other is not listed and its delivery record was not checked"
	}
	return "removed the directory at the name of " + r.u.scope + ", whose scope.key is listed in " + removedScopesName + ", but " + why.Error() + ": the floor shows activity of this uid after the listed key, or cannot be judged, so rm-scope cannot confirm that the uid's current scope is the one removed; the current scope may have been moved away from its name, and if it was, it is not listed and its delivery record was not checked"
}
