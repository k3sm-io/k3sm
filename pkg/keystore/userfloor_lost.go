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
	"log/slog"
	"os"
	"slices"
	"sync"
)

// lostEntryLines is, per scope, the names whose put this process committed
// without its floor line (errCommitted). The next operation on the scope
// that holds the exclusive store lock catches each up (catchUpLostEntries),
// as catchUpDeliveries does the delivery record's; across a restart the
// start step's catch-up (catchUpEntries) finds them from the tree.
type lostEntryLines struct {
	mu sync.Mutex
	m  map[string]map[string]bool
}

// note records name in scope as owing its floor line.
func (l *lostEntryLines) note(scope, name string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]map[string]bool{}
	}
	if l.m[scope] == nil {
		l.m[scope] = map[string]bool{}
	}
	l.m[scope][name] = true
}

// names is scope's names owing their floor line, sorted.
func (l *lostEntryLines) names(scope string) []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for n := range l.m[scope] {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// done clears name in scope.
func (l *lostEntryLines) done(scope, name string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m[scope], name)
	if len(l.m[scope]) == 0 {
		delete(l.m, scope)
	}
}

// catchUpLostEntries appends, for an operation that holds the exclusive
// store lock and opened o, the live floor line of every entry of u's scope
// whose put this process committed without it: at the entry's
// authenticated pointer, unless the floor already holds or buries that
// generation, and never while damage could name it (catchUpEntry). It is
// best effort and runs before the operation serves: a name whose entry is
// gone, or whose pointer does not authenticate, has nothing to catch up
// and is cleared; a line the floor did not take stays owed, logged at
// Warn, for the next operation or the next start.
func (u *UserScope) catchUpLostEntries(o *openedScope) {
	names := u.s.lostLines.names(u.scope)
	if len(names) == 0 {
		return
	}
	entries, err := u.s.openSubdir(o.dir, scopeEntriesName, false)
	if err != nil {
		slog.Warn("the user-scope floor's catch-up of entries whose put lost its floor line could not open the scope's entries", "scope", u.scope, "err", err)
		return
	}
	defer func() { _ = entries.Close() }() // nothing is written in entries/
	u.catchUpLostIn(entries, o.uk, names)
}

// catchUpLostIn is catchUpLostEntries over the scope's entries directory
// and derived keys, for names.
func (u *UserScope) catchUpLostIn(entries *os.Root, uk keys, names []string) {
	for _, name := range names {
		e, err := openEntryDirRaw(entries, name)
		if err != nil {
			u.s.lostLines.done(u.scope, name)
			continue
		}
		gen, seq, ok := authenticatedPointer(e, uk)
		e.close()
		if !ok {
			u.s.lostLines.done(u.scope, name)
			continue
		}
		if err := u.catchUpEntry(name, gen, seq); err != nil {
			slog.Warn("the user-scope floor did not take an entry's catch-up line; the entry's generation rests on its tree alone", "scope", u.scope, "err", err)
			continue
		}
		u.s.lostLines.done(u.scope, name)
	}
}
