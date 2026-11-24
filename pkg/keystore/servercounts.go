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

import "sync"

// serverCounts is the server's two counts past the pre-frame ones, which
// the server-counts file (PreFrameDroppedName) persists beside them: each
// uid's post-frame refused lines dropped and not yet summarized
// (countClassPostFrame), and the committed revocations whose audit line
// could not be written (countClassUnaudited). The socket's bridge and the
// user-scope revocations change them; the store's ServerLogs is their one
// writer: it reads them back at open and at every reopen (merge) and
// writes them with the pre-frame counts. A pointer on FileStore, so a copy
// of the store shares it; New allocates it.
type serverCounts struct {
	mu sync.Mutex // guards what follows; a leaf: nothing else is called under it
	// d is the counts: post-frame by uid in d.uids, the post-frame others
	// and the unaudited count in d.others.
	d preFrameDropped
	// written is d's part of the file as last written or read.
	written preFrameDropped
	// gen moves on every change d takes from the server, so the writer
	// knows whether what it last wrote is current.
	gen uint64
	// notify is called, outside mu, after a change: the writer's coalesced
	// write. Nil writes nothing until the writer's next call.
	notify func()
}

func newServerCounts() *serverCounts {
	return &serverCounts{d: newPreFrameDropped(), written: newPreFrameDropped()}
}

// change runs fn on d under mu, moves gen, then calls notify outside mu.
func (c *serverCounts) change(fn func(d preFrameDropped)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	fn(c.d)
	c.gen++
	notify := c.notify
	c.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// setNotify makes fn the call after each change.
func (c *serverCounts) setNotify(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notify = fn
}

// snapshot is a copy of the counts and their generation.
func (c *serverCounts) snapshot() (preFrameDropped, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.d.clone(), c.gen
}

// generation is the counts' generation.
func (c *serverCounts) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// wrote records d, a snapshot's counts, as what the file now holds.
func (c *serverCounts) wrote(d preFrameDropped) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = d.clone()
}

// merge moves each count by what file, the file's part for these counts,
// gained or lost since it was last written or read (mergeDelta): a count
// already in memory is not added twice, and one a root rotate wrote to the
// audit log and took out of the file leaves memory too. It moves no
// generation: what memory gained from the file is already in it.
func (c *serverCounts) merge(file preFrameDropped) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mergeDelta(c.d.uids, file.uids, c.written.uids)
	mergeDelta(c.d.others, file.others, c.written.others)
	c.written = file.clone()
}

// postFrameKey is uid's post-frame count's key.
func postFrameKey(uid uint32) preFrameKey { return preFrameKey{class: countClassPostFrame, uid: uid} }

// AddPostFrameDropped adds n to uid's post-frame refused lines dropped and
// not yet summarized: the socket's bridge hands each line its limiter or
// the caller's share dropped, and each summary that could not be written,
// to the store here, which persists the count (PreFrameDroppedName) until
// a summary line or root's next audit --rotate writes it.
func (s *FileStore) AddPostFrameDropped(uid uint32, n uint64) {
	if n == 0 {
		return
	}
	s.counts.change(func(d preFrameDropped) {
		d.uids[postFrameKey(uid)] = satAdd(d.uids[postFrameKey(uid)], n)
	})
}

// PostFrameDropped is uid's post-frame refused lines dropped and not yet
// summarized.
func (s *FileStore) PostFrameDropped(uid uint32) uint64 {
	if s.counts == nil {
		return 0
	}
	s.counts.mu.Lock()
	defer s.counts.mu.Unlock()
	return s.counts.d.uids[postFrameKey(uid)]
}

// PostFrameSummarized takes n, a summary line just written for uid, out of
// uid's post-frame count, held at 0.
func (s *FileStore) PostFrameSummarized(uid uint32, n uint64) {
	if n == 0 {
		return
	}
	s.counts.change(func(d preFrameDropped) {
		k := postFrameKey(uid)
		if v := satSub(d.uids[k], n); v > 0 {
			d.uids[k] = v
		} else {
			delete(d.uids, k)
		}
	})
}

// countUnaudited counts one committed operation whose audit line was not
// written: a revocation (rm, rotate, withdraw) that commits first and
// appends after, and goes ahead while appends fail.
func (s *FileStore) countUnaudited() {
	s.counts.change(func(d preFrameDropped) {
		d.others[countClassUnaudited] = satAdd(d.others[countClassUnaudited], 1)
	})
}

// UnauditedOps is the number of committed user-scope operations whose audit
// line could not be written and no root audit --rotate has written yet: the
// count doctor shows (U112). It is persisted in the server-counts file
// (PreFrameDroppedName), read back when the store's ServerLogs opens and
// at every reopen, so it outlasts a restart.
func (s *FileStore) UnauditedOps() uint64 {
	if s.counts == nil {
		return 0
	}
	s.counts.mu.Lock()
	defer s.counts.mu.Unlock()
	return s.counts.d.others[countClassUnaudited]
}
