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
	"fmt"
	"os/user"
	"strconv"
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

// lookupGeneratedUID reads uid's live GeneratedUID through the seam, within
// generatedUIDDeadline. A lookup past the deadline, an error, a synthesized
// answer and an all-zero one each fail closed with ErrScopeOwnerUnknown: a
// directory service that is slow or not up yet must never read as a
// changed owner, and nothing in the scope may open on a guess.
//
// The real lookup cannot be cancelled, so a lookup past the deadline is
// abandoned: its goroutine ends when the call returns, and its answer is
// dropped into a buffered channel nobody reads.
func lookupGeneratedUID(uid uint32) ([generationSize]byte, error) {
	type answer struct {
		g   [generationSize]byte
		err error
	}
	// The seam is read here, not in the goroutine, which may outlive the
	// call and so must not read a package variable after it returns.
	lookup := generatedUIDSeam
	expired, stop := timerSeam(generatedUIDDeadline)
	defer stop()
	ch := make(chan answer, 1)
	go func() {
		g, err := lookup(uid)
		ch <- answer{g, err}
	}()
	var zero [generationSize]byte
	select {
	case a := <-ch:
		switch {
		case a.err != nil:
			return zero, fmt.Errorf("%w: the GeneratedUID lookup for uid %d failed: %w", ErrScopeOwnerUnknown, uid, a.err)
		case bytes.HasPrefix(a.g[:], synthesizedGUIDPrefix):
			return zero, fmt.Errorf("%w: uid %d has no directory record (the lookup synthesized its GeneratedUID)", ErrScopeOwnerUnknown, uid)
		case a.g == zero:
			return zero, fmt.Errorf("%w: the GeneratedUID lookup for uid %d answered all zeros", ErrScopeOwnerUnknown, uid)
		}
		return a.g, nil
	case <-expired:
		return zero, fmt.Errorf("%w: the GeneratedUID lookup for uid %d did not answer within %s", ErrScopeOwnerUnknown, uid, generatedUIDDeadline)
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
