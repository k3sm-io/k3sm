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
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"sync"
	"time"
)

// The named seams of docs/design/keystore.md § "Package layout and seams".
// Each replaces one real primitive. The package's TestMain sets each to a
// stub that panics, so a unit test that forgets to inject a fake never
// reaches the host.
var (
	// generatedUIDSeam reads uid's live GeneratedUID: mbr_uid_to_uuid.
	// lookupGeneratedUID is its only caller, and puts the deadline on it.
	generatedUIDSeam = realGeneratedUID
	// uidResolverSeam resolves a macOS short name to its uid: getpwnam.
	uidResolverSeam = realLookupUID
	// timerSeam starts a timer that fires once after d: time.NewTimer. It
	// returns the channel and a function that stops the timer.
	timerSeam = realTimer
)

// generatedUIDDeadline is the one deadline every GeneratedUID lookup takes:
// the store's, the socket's, the reconciler's and the root verbs'.
const generatedUIDDeadline = 250 * time.Millisecond

// synthesizedGUIDPrefix is the fixed prefix of the compatibility UUID the
// membership API makes up for a uid with no directory record,
// FFFFEEEE-DDDD-CCCC-BBBB-AAAA followed by the uid in hex. It is no answer.
var synthesizedGUIDPrefix = []byte{0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC, 0xBB, 0xBB, 0xAA, 0xAA}

// maxOutstandingLookups bounds the GeneratedUID lookups outstanding at once,
// across uids. A lookup past its deadline cannot be cancelled and holds an
// OS thread until the call returns, so without a bound a directory service
// that never answers would pin a thread per request.
const maxOutstandingLookups = 8

// errLookupNotRun marks an ErrScopeOwnerUnknown for which no GeneratedUID
// lookup ran: the outstanding cap was reached, or an earlier lookup for the
// uid is stuck past its deadline. It is a capacity refusal, retryable, and
// unlike a lookup that ran and failed or timed out it is not evidence the
// directory service has no answer: rm, which goes ahead on the latter,
// refuses on it.
var errLookupNotRun = errors.New("no GeneratedUID lookup ran for want of capacity; try again")

// flight is one outstanding GeneratedUID lookup, which every concurrent
// caller for its uid joins.
type flight struct {
	// done is closed once the lookup returned and left lookups.inflight;
	// g and err are set before it is closed.
	done chan struct{}
	// expired is closed by the caller that started the lookup once its
	// deadline passed: a later caller then fails closed at once.
	expired chan struct{}
	g       [generationSize]byte
	err     error
}

// lookups holds the outstanding lookups, at most one per uid.
var lookups = struct {
	mu       sync.Mutex
	inflight map[uint32]*flight
}{inflight: map[uint32]*flight{}}

// generatedUIDOf is lookupGeneratedUID, or the store's test answer
// (Config.GeneratedUID) when it has one, judged as the lookup's answer is,
// with no deadline or outstanding bound since it never reaches the host.
func (s *FileStore) generatedUIDOf(uid uint32) ([generationSize]byte, error) {
	if s.generatedUID != nil {
		g, err := s.generatedUID(uid)
		return checkGeneratedUID(uid, g, err)
	}
	return lookupGeneratedUID(uid)
}

// lookupGeneratedUID reads uid's live GeneratedUID through the seam, within
// generatedUIDDeadline. A lookup past the deadline, an error, a synthesized
// answer and an all-zero one each fail closed with ErrScopeOwnerUnknown: a
// directory service that is slow or not up yet must never read as a
// changed owner, and nothing in the scope may open on a guess.
//
// At most one lookup per uid is outstanding: a caller that finds one joins
// it, and once that lookup is past its deadline every later caller for the
// uid fails closed at once and starts none. At most maxOutstandingLookups
// are outstanding across uids; past that a new uid fails closed at once.
// Those two refusals, where no lookup ran, also match errLookupNotRun. A
// lookup past its deadline is abandoned, not cancelled (the real call
// cannot be): it leaves the table when the call returns.
func lookupGeneratedUID(uid uint32) ([generationSize]byte, error) {
	var zero [generationSize]byte
	lookups.mu.Lock()
	if f, ok := lookups.inflight[uid]; ok {
		lookups.mu.Unlock()
		select {
		case <-f.done:
			return checkGeneratedUID(uid, f.g, f.err)
		case <-f.expired:
			return zero, fmt.Errorf("%w: %w: an earlier GeneratedUID lookup for uid %d is still outstanding past its %s deadline", ErrScopeOwnerUnknown, errLookupNotRun, uid, generatedUIDDeadline)
		}
	}
	if len(lookups.inflight) >= maxOutstandingLookups {
		lookups.mu.Unlock()
		return zero, fmt.Errorf("%w: %w: %d GeneratedUID lookups are already outstanding", ErrScopeOwnerUnknown, errLookupNotRun, maxOutstandingLookups)
	}
	f := &flight{done: make(chan struct{}), expired: make(chan struct{})}
	lookups.inflight[uid] = f
	lookups.mu.Unlock()
	// The seam is read here, not in the goroutine, which may outlive the
	// call and so must not read a package variable after it returns.
	lookup := generatedUIDSeam
	expired, stop := timerSeam(generatedUIDDeadline)
	defer stop()
	go func() {
		g, err := lookup(uid)
		lookups.mu.Lock()
		f.g, f.err = g, err
		delete(lookups.inflight, uid)
		lookups.mu.Unlock()
		close(f.done)
	}()
	select {
	case <-f.done:
		return checkGeneratedUID(uid, f.g, f.err)
	case <-expired:
		close(f.expired)
		return zero, fmt.Errorf("%w: the GeneratedUID lookup for uid %d did not answer within %s", ErrScopeOwnerUnknown, uid, generatedUIDDeadline)
	}
}

// checkGeneratedUID judges a lookup's answer: an error, a synthesized
// GeneratedUID or an all-zero one is ErrScopeOwnerUnknown.
func checkGeneratedUID(uid uint32, g [generationSize]byte, err error) ([generationSize]byte, error) {
	var zero [generationSize]byte
	switch {
	case err != nil:
		return zero, fmt.Errorf("%w: the GeneratedUID lookup for uid %d failed: %w", ErrScopeOwnerUnknown, uid, err)
	case bytes.HasPrefix(g[:], synthesizedGUIDPrefix):
		return zero, fmt.Errorf("%w: uid %d has no directory record (the lookup synthesized its GeneratedUID)", ErrScopeOwnerUnknown, uid)
	case g == zero:
		return zero, fmt.Errorf("%w: the GeneratedUID lookup for uid %d answered all zeros", ErrScopeOwnerUnknown, uid)
	}
	return g, nil
}

// resolveUID resolves a short name through the uid resolver within
// generatedUIDDeadline, the same deadline as the GeneratedUID lookup; past
// it the resolution fails. Like that lookup, a call past the deadline is
// abandoned, not cancelled.
func resolveUID(name string) (uint32, error) {
	type answer struct {
		uid uint32
		err error
	}
	resolve := uidResolverSeam // read before the goroutine, as in lookupGeneratedUID
	expired, stop := timerSeam(generatedUIDDeadline)
	defer stop()
	ch := make(chan answer, 1)
	go func() {
		uid, err := resolve(name)
		ch <- answer{uid, err}
	}()
	select {
	case a := <-ch:
		return a.uid, a.err
	case <-expired:
		return 0, fmt.Errorf("the account lookup did not answer within %s", generatedUIDDeadline)
	}
}

// realLookupUID is getpwnam through os/user.
func realLookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("account %s has uid %q: %w", name, u.Uid, err)
	}
	return uint32(uid), nil
}

// realTimer is time.NewTimer.
func realTimer(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}
