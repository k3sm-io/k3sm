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
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// testRateFloor is the floor the rate tests shrink the relay to.
	testRateFloor = 1 << 10
	// rateLen is the length of rateBlob: more than any pull in these tests
	// reads before it ends.
	rateLen = 8 << 20
	// slowCutMsg is part of the rate floor's cut line.
	slowCutMsg = "below the rate floor"
)

var rateBlob = "/v2/team/app/blobs/sha256:" + strings.Repeat("d", 64)

// rateRegistry serves rateBlob as fast as the relay takes it, in 4 KiB
// writes, and answers anything else with an empty 200.
func rateRegistry() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != rateBlob {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(rateLen))
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		chunk := make([]byte, 4<<10)
		for range rateLen / len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
}

// rateLimits caps the relay at two connections, one a source, with the test
// floor and the production window.
func rateLimits() relayLimits {
	lim := defaultRelayLimits
	lim.maxConns = 2
	lim.maxConnsPerSource = 1
	lim.rateFloor = testRateFloor
	lim.rateWindow = relayRateWindow
	return lim
}

// ratePull is a blob GET whose peer reads at a set rate. pause, while set,
// stops it reading.
type ratePull struct {
	mu     sync.Mutex
	n      int
	err    error
	paused bool
}

func (p *ratePull) read() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n, p.err
}

func (p *ratePull) setPaused(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = v
}

// startPull opens a GET for rateBlob from src and reads perSecond bytes of its
// body each second of the bubble's clock, in the background, until the body
// fails or ends.
func startPull(t *testing.T, f *relayLimitFixture, src string, perSecond int) *ratePull {
	t.Helper()
	c := f.dial(t, src)
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\n\r\n", rateBlob); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(c, 512), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("GET from %s: %v", src, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET from %s = %d, want 200", src, resp.StatusCode)
	}
	p := &ratePull{}
	stop := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() { close(stop); _ = c.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, perSecond)
		for {
			tick := time.NewTimer(time.Second)
			select {
			case <-tick.C:
			case <-stop:
				tick.Stop()
				return
			}
			p.mu.Lock()
			paused := p.paused
			p.mu.Unlock()
			if paused {
				continue
			}
			n, err := io.ReadFull(resp.Body, buf)
			p.mu.Lock()
			p.n += n
			p.err = err
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

// getAsync sends a GET for the manifest from src on a fresh connection and
// delivers its status, or -1 when it fails, on the channel it returns. The
// connection is dialled here; the request runs in the background, because the
// relay may hold the connection until a slot frees.
func getAsync(t *testing.T, f *relayLimitFixture, src string) <-chan int {
	t.Helper()
	c := f.dial(t, src)
	out := make(chan int, 1)
	go func() {
		defer c.Close()
		if _, err := fmt.Fprintf(c, "GET /v2/team/app/manifests/v1 HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n\r\n"); err != nil {
			out <- -1
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodGet})
		if err != nil {
			out <- -1
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		out <- resp.StatusCode
	}()
	return out
}

// awaitStatus moves the bubble's clock a second at a time until got delivers,
// for at most within, and returns what it delivered.
func awaitStatus(t *testing.T, got <-chan int, within time.Duration) int {
	t.Helper()
	for waited := time.Duration(0); waited < within; waited += time.Second {
		select {
		case code := <-got:
			return code
		default:
		}
		advance(t, time.Second)
	}
	t.Fatalf("no answer within %v", within)
	return 0
}

// TestRelayRateFloorCutsOnlyUnderContention is the gate for the rate floor: on
// a relay capped at two connections, one pull reading below the floor and one
// above it hold both slots. With nobody waiting, neither is cut for three
// windows. A third connection then waits for a slot, and the relay cuts the
// slow pull, and only it, serves the third, and logs one warning naming the
// slow pull's source. It runs in a synctest bubble.
func TestRelayRateFloorCutsOnlyUnderContention(t *testing.T) {
	relayBubble(t, func(t *testing.T) {
		const slowPeer, fastPeer, newPeer = "100.64.1.5", "100.64.2.5", "100.64.3.5"
		lim := rateLimits()
		f, rec := newCutLogFixtureWith(t, lim, rateRegistry())
		slow := startPull(t, f, slowPeer, testRateFloor/2)
		fast := startPull(t, f, fastPeer, 4*testRateFloor)

		advance(t, 3*lim.rateWindow)
		if got := rec.warnings(slowCutMsg); len(got) != 0 {
			t.Fatalf("cut lines = %v with no connection waiting, want none", got)
		}
		slowN, err := slow.read()
		if err != nil {
			t.Fatalf("the slow pull ended with no connection waiting after %d bytes: %v", slowN, err)
		}
		// Past the grace: the slow pull is old enough, and has written enough,
		// to be cut once a connection waits.
		if slowN < int(lim.rateFloor*lim.rateWindow.Seconds()) {
			t.Fatalf("the slow pull read %d bytes in three windows, too few to leave its grace", slowN)
		}
		if _, err := fast.read(); err != nil {
			t.Fatalf("the fast pull ended with no connection waiting: %v", err)
		}

		third := getAsync(t, f, newPeer)
		if code := awaitStatus(t, third, time.Minute); code != http.StatusOK {
			t.Fatalf("the waiting connection's GET = %d, want 200", code)
		}
		// The slow peer reads once a second; let it see its connection end.
		advance(t, 2*time.Second)
		if n, err := slow.read(); err == nil {
			t.Errorf("the slow pull is still served after %d bytes, want it cut", n)
		}
		fastN, err := fast.read()
		if err != nil {
			t.Fatalf("the fast pull was cut: %v", err)
		}
		advance(t, 10*time.Second)
		if n, err := fast.read(); err != nil || n <= fastN {
			t.Errorf("the fast pull after the cut: %d bytes (was %d), err %v; want it still streaming", n, fastN, err)
		}
		got := rec.warnings(slowCutMsg)
		if len(got) != 1 {
			t.Fatalf("cut lines = %v, want exactly one", got)
		}
		if got[0]["source"] != slowPeer || got[0]["addr"] != f.front.Addr().String() {
			t.Errorf("cut line = %v, want source=%s addr=%s", got[0], slowPeer, f.front.Addr())
		}
		if got[0]["floor"] != strconv.Itoa(testRateFloor) || got[0]["bytes"] == "" || got[0]["elapsed"] == "" {
			t.Errorf("cut line = %v, want floor=%d with bytes and elapsed", got[0], testRateFloor)
		}
	})
}

// TestRelayRateFloorSparesAPausedPullWithAFreeSlot: a pull that pauses for
// longer than a window, so that its rate over the window falls far below the
// floor, is not cut while the relay has a free slot, even when another
// connection arrives and takes that slot, and it streams on once it reads
// again. The progress window is widened past the pause so that only the rate
// floor is under test. It runs in a synctest bubble.
func TestRelayRateFloorSparesAPausedPullWithAFreeSlot(t *testing.T) {
	relayBubble(t, func(t *testing.T) {
		const pausedPeer, otherPeer = "100.64.1.6", "100.64.2.6"
		lim := rateLimits()
		lim.writeProgress = 4 * lim.rateWindow
		f, rec := newCutLogFixtureWith(t, lim, rateRegistry())
		p := startPull(t, f, pausedPeer, 4*testRateFloor)

		advance(t, 2*lim.rateWindow)
		p.setPaused(true)
		advance(t, lim.rateWindow+lim.rateWindow/2)
		if code := awaitStatus(t, getAsync(t, f, otherPeer), time.Minute); code != http.StatusOK {
			t.Fatalf("a connection to the free slot: GET = %d, want 200", code)
		}
		before, err := p.read()
		if err != nil {
			t.Fatalf("the paused pull was cut with a free slot: %v", err)
		}
		p.setPaused(false)
		advance(t, 10*time.Second)
		if n, err := p.read(); err != nil || n <= before {
			t.Errorf("the pull after its pause: %d bytes (was %d), err %v; want it streaming", n, before, err)
		}
		if got := rec.warnings(slowCutMsg); len(got) != 0 {
			t.Errorf("cut lines = %v with a free slot, want none", got)
		}
	})
}

// TestRelayRateFloorSparesAMeshPull pins the floor's arithmetic at the
// production floor and window on a fake clock: a pull at 64 KiB/s, a mesh
// link's rate, is never picked however long it runs, while one at 4 KiB/s is
// picked once it is past its grace, and only once a window.
func TestRelayRateFloorSparesAMeshPull(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	f := &rateFloor{floor: relayRateFloor, window: relayRateWindow}
	conn := func() *limitConn {
		c := &limitConn{meter: newRateMeter(clock, relayRateWindow)}
		c.meter.begin()
		f.add(c)
		return c
	}
	mesh, slow := conn(), conn()
	// One write a second each: 64 KiB taking 1 s for the mesh pull, 4 KiB
	// taking 1 s for the slow one.
	step := func() {
		mesh.meter.startWrite()
		slow.meter.startWrite()
		now = now.Add(time.Second)
		mesh.meter.endWrite(64 << 10)
		slow.meter.endWrite(4 << 10)
	}
	for i := 0; i < int(3*relayRateWindow/time.Second); i++ {
		step()
		c, _, ok := f.pick(now)
		if ok && c == mesh {
			t.Fatalf("the mesh pull was picked at %v", time.Duration(i+1)*time.Second)
		}
		if ok {
			if el := time.Duration(i+1) * time.Second; el < relayRateWindow {
				t.Fatalf("the slow pull was picked inside its grace, at %v", el)
			}
			if again, _, ok := f.pick(now); ok {
				t.Fatalf("a second pick in the same window chose %p", again)
			}
			return
		}
	}
	t.Fatal("the 4 KiB/s pull was never picked")
}
