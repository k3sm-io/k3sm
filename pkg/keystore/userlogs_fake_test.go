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
	"slices"
	"sync"
)

// memFloor is an in-memory user-scope floor: the lines in order, read by
// the floor's rule (the highest seq per scope, name and generation). failAppend,
// when set, fails every append, and failRead every read. buryLimit, when
// not 0, fails every tombstone once that many have landed (buried counts
// them): a burial that fails part way.
type memFloor struct {
	mu         sync.Mutex
	lines      []memFloorLine
	failAppend bool
	failRead   bool
	buryLimit  int
	buried     int
}

type memFloorLine struct {
	scope, name string
	gen         [generationSize]byte
	seq         uint64
	tomb        bool
}

func (f *memFloor) floor(scope, name string, gen [generationSize]byte) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRead {
		return 0, errors.New("injected floor read failure")
	}
	var max uint64
	for _, l := range f.lines {
		if l.scope != scope || l.name != name || l.gen != gen {
			continue
		}
		if l.tomb {
			return 0, errFloorBuried
		}
		if l.seq > max {
			max = l.seq
		}
	}
	return max, nil
}

func (f *memFloor) append(scope, name string, gen [generationSize]byte, seq uint64, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAppend {
		return errors.New("injected floor append failure")
	}
	f.lines = append(f.lines, memFloorLine{scope: scope, name: name, gen: gen, seq: seq})
	return nil
}

func (f *memFloor) check() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRead {
		return errors.New("injected floor read failure")
	}
	return nil
}

func (f *memFloor) bury(scope, name string, gen [generationSize]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAppend {
		return errors.New("injected floor append failure")
	}
	if f.buryLimit != 0 && f.buried >= f.buryLimit {
		return errors.New("injected tombstone failure")
	}
	f.buried++
	f.lines = append(f.lines, memFloorLine{scope: scope, name: name, gen: gen, tomb: true})
	return nil
}

func (f *memFloor) liveGens(scope, name string) ([][generationSize]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRead {
		return nil, errors.New("injected floor read failure")
	}
	live := map[[generationSize]byte]bool{}
	for _, l := range f.lines {
		if l.scope != scope || l.name != name {
			continue
		}
		switch {
		case l.tomb:
			live[l.gen] = false
		default:
			if _, seen := live[l.gen]; !seen {
				live[l.gen] = true
			}
		}
	}
	var out [][generationSize]byte
	for g, ok := range live {
		if ok {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b [generationSize]byte) int { return bytes.Compare(a[:], b[:]) })
	return out, nil
}

// memAudit is an in-memory audit sink. fail, when set, fails every append.
type memAudit struct {
	mu    sync.Mutex
	lines []auditLine
	fail  bool
}

func (a *memAudit) append(l auditLine) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("injected audit append failure")
	}
	a.lines = append(a.lines, l)
	return nil
}

func (a *memAudit) all() []auditLine {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditLine(nil), a.lines...)
}

// userLogs returns s's in-memory floor and audit sink, which newTestStore
// installs.
func userLogs(s *FileStore) (*memFloor, *memAudit) {
	return s.userFloor.(*memFloor), s.auditSink.(*memAudit)
}
