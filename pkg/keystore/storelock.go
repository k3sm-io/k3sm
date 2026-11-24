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

// prefLock is a reader-writer lock with sync.RWMutex's fairness: a waiting
// writer blocks new readers, and a writer's release hands the lock to every
// reader already waiting, before any other writer, so neither a stream of
// readers nor a stream of writers starves the other. Unlike sync.RWMutex,
// its acquisition is bounded by a wait and a context.
type prefLock struct {
	mu      sync.Mutex
	readers int
	writer  bool
	// writers is how many exclusive acquisitions are waiting.
	writers int
	// waiting is the readers waiting, each granted by closing its channel
	// once it holds a share.
	waiting []chan struct{}
	// changed is closed, and replaced, on every change a waiting writer
	// may be waiting for.
	changed chan struct{}
}

func newPrefLock() *prefLock { return &prefLock{changed: make(chan struct{})} }

// acquire takes l, exclusive or shared, waiting at most wait, or until ctx
// is done: then errLockTimeout, or ctx's error, with nothing held. A ctx
// already done takes nothing, even an uncontended l. A nil l, a store a
// test built without New, holds nothing.
func (l *prefLock) acquire(ctx context.Context, exclusive bool, wait time.Duration) error {
	if l == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	if !exclusive {
		return l.acquireShared(ctx, timer.C)
	}
	waiting := false
	for {
		l.mu.Lock()
		if !l.writer && l.readers == 0 {
			l.writer = true
			if waiting {
				l.writers--
			}
			l.mu.Unlock()
			return nil
		}
		if !waiting {
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
		// A writer that gives up no longer holds readers back.
		l.mu.Lock()
		l.writers--
		if l.writers == 0 && !l.writer {
			l.grantReaders()
		}
		l.broadcast()
		l.mu.Unlock()
		return err
	}
}

// acquireShared takes a share: at once when no writer holds or waits, or
// else when a writer's release, or the last waiting writer giving up,
// grants it.
func (l *prefLock) acquireShared(ctx context.Context, expired <-chan time.Time) error {
	l.mu.Lock()
	if !l.writer && l.writers == 0 {
		l.readers++
		l.mu.Unlock()
		return nil
	}
	granted := make(chan struct{})
	l.waiting = append(l.waiting, granted)
	l.mu.Unlock()
	var err error
	select {
	case <-granted:
		return nil
	case <-ctx.Done():
		err = ctx.Err()
	case <-expired:
		err = errLockTimeout
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-granted:
		// Granted as it gave up: the share it was handed is given back.
		l.readers--
		l.broadcast()
	default:
		for i, c := range l.waiting {
			if c == granted {
				l.waiting = append(l.waiting[:i], l.waiting[i+1:]...)
				break
			}
		}
	}
	return err
}

// release releases a hold acquire took, exclusive or shared. A writer's
// release grants every waiting reader its share first.
func (l *prefLock) release(exclusive bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if exclusive {
		l.writer = false
		l.grantReaders()
	} else {
		l.readers--
	}
	l.broadcast()
	l.mu.Unlock()
}

// grantReaders hands a share to every waiting reader; l.mu is held and no
// writer holds l.
func (l *prefLock) grantReaders() {
	for _, c := range l.waiting {
		l.readers++
		close(c)
	}
	l.waiting = nil
}

// broadcast wakes every waiting writer; l.mu is held.
func (l *prefLock) broadcast() {
	close(l.changed)
	l.changed = make(chan struct{})
}
