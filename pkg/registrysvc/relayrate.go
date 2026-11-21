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

package registrysvc

import (
	"sync"
	"time"
)

// THE RATE FLOOR. The progress deadline (relayWriteProgress) frees a dead slot
// but not a slow one: a client that reads a little inside every window holds
// its slot for good, so a few source addresses at their share can hold every
// slot of a listening address while further pulls wait. A plain rate floor is
// not safe, because the node's puller does not resume a cut layer and a client
// may pause for minutes while it unpacks one. So the floor is enforced only
// under contention, when it costs nothing an honest client would notice:
//
//   - it is checked only while the listener is at its connection cap AND a
//     further connection has been accepted and waits for a slot. On a listener
//     with a free slot nothing is ever cut for slowness, whatever the rate;
//   - the rate is the bytes of a response written to the peer, divided by the
//     time spent inside those writes, that is, waiting on the client to take
//     them. Time the relay spends waiting on the registry behind it is never
//     counted, so a slow registry never makes a client look slow. Only a
//     response in flight is measured; an idle keep-alive between responses is
//     not, the age and request caps already turn it over;
//   - it is averaged over the last one to two windows of the response;
//   - a connection younger than one window, or a response that has written
//     less than one window's worth at the floor, is measured but never cut, so
//     TLS setup, TCP slow start and short responses never count;
//   - at most one connection is cut per window on each listening address: the
//     one with the lowest rate below the floor. None is cut while every
//     measured connection is above it. The cut closes the connection once the
//     write in progress returns, or at once when none is, which frees its slot
//     for the waiting connection.
const (
	// relayRateFloor is the floor, in bytes a second: about one fifteenth of a
	// 1 Mbit/s link. A mesh pull at 64 KiB/s is eight times it.
	relayRateFloor = 8 << 10
	// relayRateWindow is the window the rate is averaged over, the grace a
	// connection and a response get, and the least time between two cuts on
	// one listening address. 2.4 MB at the floor.
	relayRateWindow = 5 * time.Minute
	// relayRateChecks is how many times a window a connection waiting for a
	// slot looks again for one to cut.
	relayRateChecks = 30
)

// rateBucket is the response bytes written, and the time spent writing them,
// in one window that started at start.
type rateBucket struct {
	start time.Time
	bytes int64
	wait  time.Duration
}

// rateMeter measures one relay connection's response rate. Its methods are
// safe on a nil meter, which measures nothing and is never cut. mu guards
// every field below it: a response is written from the handler's goroutine and
// the serving goroutine, and the listener reads the rate from its own.
type rateMeter struct {
	now    func() time.Time
	window time.Duration
	opened time.Time

	mu        sync.Mutex
	inFlight  bool      // a response is being served
	respBytes int64     // bytes written of the response in flight
	writing   bool      // a write is in progress
	wroteAt   time.Time // when the write in progress started
	cur, prev rateBucket
	cut       bool // the listener cut this connection for its rate
}

func newRateMeter(now func() time.Time, window time.Duration) *rateMeter {
	return &rateMeter{now: now, window: window, opened: now()}
}

// begin starts measuring a response.
func (m *rateMeter) begin() {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlight, m.respBytes = true, 0
	m.cur, m.prev = rateBucket{start: now}, rateBucket{}
}

// end stops measuring: the response is written and the connection is idle.
func (m *rateMeter) end() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlight = false
}

// startWrite records that a write to the peer starts.
func (m *rateMeter) startWrite() {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writing, m.wroteAt = true, now
}

// endWrite records a write that took n bytes, and reports whether the
// connection has been cut, so the writer closes it now.
func (m *rateMeter) endWrite(n int) (cut bool) {
	if m == nil {
		return false
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writing = false
	if m.inFlight {
		m.roll(now)
		m.respBytes += int64(n)
		m.cur.bytes += int64(n)
		m.cur.wait += now.Sub(m.wroteAt)
	}
	return m.cut
}

// roll moves the current bucket to the previous one once it is a window old.
// A bucket two windows old is dropped. It is called with m.mu held.
func (m *rateMeter) roll(now time.Time) {
	switch age := now.Sub(m.cur.start); {
	case age >= 2*m.window:
		m.cur, m.prev = rateBucket{start: now}, rateBucket{}
	case age >= m.window:
		m.cur, m.prev = rateBucket{start: now}, m.cur
	}
}

// rateSample is one connection's measured rate.
type rateSample struct {
	bytes int64
	wait  time.Duration
}

// perSecond is the sample's rate in bytes a second.
func (s rateSample) perSecond() float64 { return float64(s.bytes) / s.wait.Seconds() }

// sample returns the connection's rate at now, with ok false when it may not be
// cut for its rate whatever the rate is: no response in flight, a connection
// or a response younger than a window, a response under a window's worth at
// floor, or no time yet spent waiting on the peer. The time of a write still in
// progress counts as waiting; its bytes count once it returns.
func (m *rateMeter) sample(now time.Time, floor float64) (s rateSample, ok bool) {
	if m == nil {
		return rateSample{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.inFlight || m.cut || now.Sub(m.opened) < m.window {
		return rateSample{}, false
	}
	if float64(m.respBytes) < floor*m.window.Seconds() {
		return rateSample{}, false
	}
	m.roll(now)
	from := m.cur.start
	if !m.prev.start.IsZero() {
		from = m.prev.start
	}
	if now.Sub(from) < m.window {
		return rateSample{}, false
	}
	s = rateSample{bytes: m.cur.bytes + m.prev.bytes, wait: m.cur.wait + m.prev.wait}
	if m.writing {
		s.wait += now.Sub(later(m.wroteAt, from))
	}
	return s, s.wait > 0
}

// markCut marks the connection cut and reports whether it can be closed now,
// which is when no write is in progress. Otherwise the writer closes it when
// its write returns.
func (m *rateMeter) markCut() (closeNow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cut = true
	return !m.writing
}

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// rateFloor is a listener's floor state: its live connections and when it last
// cut one. mu guards both.
type rateFloor struct {
	floor  float64       // bytes a second; 0 disables the floor
	window time.Duration // 0 disables the floor

	mu      sync.Mutex
	conns   map[*limitConn]struct{}
	lastCut time.Time
}

// enabled reports whether the floor is in force.
func (f *rateFloor) enabled() bool { return f.floor > 0 && f.window > 0 }

// add tracks c as live.
func (f *rateFloor) add(c *limitConn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conns == nil {
		f.conns = map[*limitConn]struct{}{}
	}
	f.conns[c] = struct{}{}
}

// remove stops tracking c.
func (f *rateFloor) remove(c *limitConn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.conns, c)
}

// pick chooses the connection to cut at now, if any: none inside a window of
// the last cut, else the one with the lowest rate below the floor. It records
// the cut, so a second pick inside the window chooses none.
func (f *rateFloor) pick(now time.Time) (*limitConn, rateSample, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.lastCut.IsZero() && now.Sub(f.lastCut) < f.window {
		return nil, rateSample{}, false
	}
	var (
		slow     *limitConn
		slowRate float64
		slowS    rateSample
	)
	for c := range f.conns {
		s, ok := c.meter.sample(now, f.floor)
		if !ok {
			continue
		}
		if r := s.perSecond(); r < f.floor && (slow == nil || r < slowRate) {
			slow, slowRate, slowS = c, r, s
		}
	}
	if slow == nil {
		return nil, rateSample{}, false
	}
	f.lastCut = now
	return slow, slowS, true
}
