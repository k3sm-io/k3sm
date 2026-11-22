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

import "fmt"

// userStaleError is a user-scope pointer below the user-scope floor
// (docs/design/keystore.md § "The user-scope floor"): Phase A's floor
// message with its last sentence replaced, since keystore-floor.json is the
// system floor and holds no user entry. It matches ErrCorrupt.
type userStaleError struct {
	name       string
	seq, floor uint64
}

func (e *userStaleError) Error() string {
	return fmt.Sprintf("keystore entry %q: its pointer (sequence %d) is older than the user-scope floor (sequence %d), so an older copy of it was put back. Do not restore from backup. If that was deliberate, run sudo k3sm keys floor --rebuild; removing keystore-floor.json does not help, since it holds no user entry", e.name, e.seq, e.floor)
}

func (e *userStaleError) Unwrap() error { return ErrCorrupt }

// flooredPointer is e's pointer, refused (userStaleError) when its sequence
// is below the highest the user-scope floor records for e's name and
// generation. A floor that cannot be read refuses the read: only a
// revocation goes ahead without it.
func (u *UserScope) flooredPointer(e *entry, k keys) (uint64, error) {
	cur, seq, err := e.pointer(k)
	if err != nil {
		return 0, err
	}
	fl, err := u.s.userFloor.floor(u.scope, e.name, e.generation)
	if err != nil {
		return 0, err
	}
	if seq < fl {
		return 0, &userStaleError{name: e.name, seq: seq, floor: fl}
	}
	return cur, nil
}
