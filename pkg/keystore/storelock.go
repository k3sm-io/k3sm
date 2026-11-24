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
	"sync"
	"time"
)

// This file is the store lock's in-process half: docs/design/keystore.md §
// "The audit log", "Lock modes and fairness". Every hold of the store lock
// goes through one reader-writer lock with writer preference before the
// .lock flock, so a stream of shared holds from other goroutines cannot keep
// an exclusive one waiting: once a writer waits, no new reader is admitted.
//
// The lock order, which every hold keeps: the uid's mutation lock
// (usage.go, for put, rotate and rm), then this in-process lock, then the
// .lock flock, then the user-scope floor's lock. A system-scope verb, which
// runs in a root process of its own, takes keystore-lock (the system floor)
// before the store lock.

// TreeState is the in-process state of one keystore tree that every
// FileStore over it in one process shares (Config.Tree): the store lock's
// in-process half and the user scopes' usage figures.
type TreeState struct {
	inproc *prefLock
	usage  *usageTable
}

// NewTreeState returns a fresh TreeState, for the one process that opens
// the tree.
func NewTreeState() *TreeState {
	return &TreeState{inproc: newPrefLock(), usage: newUsageTable()}
}

// Tree is the store's TreeState: Config.Tree, or the one New made for it.
func (s *FileStore) Tree() *TreeState { return s.tree }

// prefLock is a reader-writer lock in which a waiting writer blocks new
// readers, as sync.RWMutex does, whose acquisition is bounded by a wait and
// a context, which sync.RWMutex's is not.
type prefLock struct {
	mu      sync.Mutex
	readers int
	writer  bool
	// writers is how many exclusive acquisitions are waiting.
	writers int
	// changed is closed, and replaced, on every change a waiter may be
	// waiting for.
	changed chan struct{}
}

func newPrefLock() *prefLock { return &prefLock{changed: make(chan struct{})} }

// acquire takes l, exclusive or shared, waiting at most wait, or until ctx
// is done: then errLockTimeout, or ctx's error, with nothing held. A nil l,
// a store a test built without New, holds nothing.
func (l *prefLock) acquire(ctx context.Context, exclusive bool, wait time.Duration) error {
	if l == nil {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	waiting := false
	for {
		l.mu.Lock()
		switch {
		case exclusive && !l.writer && l.readers == 0:
			l.writer = true
			if waiting {
				l.writers--
			}
			l.mu.Unlock()
			return nil
		case !exclusive && !l.writer && l.writers == 0:
			l.readers++
			l.mu.Unlock()
			return nil
		case exclusive && !waiting:
			l.writers++
			waiting = true
		}
		ch := l.changed
		l.mu.Unlock()
		var err error
		select {
		case <-ch:
			continue
		case <-ctx.Done():
			err = ctx.Err()
		case <-timer.C:
			err = errLockTimeout
		}
		if waiting {
			// A writer that gives up no longer holds readers back.
			l.mu.Lock()
			l.writers--
			l.broadcast()
			l.mu.Unlock()
		}
		return err
	}
}

// release releases a hold acquire took, exclusive or shared.
func (l *prefLock) release(exclusive bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if exclusive {
		l.writer = false
	} else {
		l.readers--
	}
	l.broadcast()
	l.mu.Unlock()
}

// broadcast wakes every waiter; l.mu is held.
func (l *prefLock) broadcast() {
	close(l.changed)
	l.changed = make(chan struct{})
}
