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
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// gateUpstreamBodyProgress bounds how long the gate waits for the next byte of
// a loopback registry response body once its headers have arrived. The
// response-header bounds end when headers arrive, and the relay's progress
// watch acts only on the client's side, so without this a registry that
// answers and then goes silent mid-body holds the gate's connection, and the
// relay slot behind it, until the client gives up. It is the relay's own
// progress window, for the same reason: it frees a dead connection and never
// cuts a slow transfer that keeps moving. The relay passes its own configured
// window when it builds its gate, so the two cannot drift; this constant is
// the default for a gate built without one.
//
// The relay's connection-deadline progress types are not reused here: the
// upstream body sits behind a pooled transport, so there is no connection
// deadline this code owns, and the cut works by closing the body instead.
const gateUpstreamBodyProgress = relayWriteProgress

// errUpstreamBodyStalled is the read error of an upstream body the gate cut
// for making no progress.
var errUpstreamBodyStalled = errors.New("the local registry sent no response bytes within the progress window")

// progressBody is an upstream response body that is cut when a single Read
// on the upstream body blocks for longer than window. The clock runs only
// while a Read is waiting on the registry: it starts when Read is called and
// stops when Read returns, with bytes, io.EOF or an error. Time the caller
// spends between Reads, such as the reverse proxy writing to a slow client,
// never counts, so only a silent registry is cut, never a slow consumer.
// Cutting closes the upstream body, which fails the blocked Read and with it
// the reverse proxy's copy loop; the proxy then drops the client connection
// and releases the upstream one. onStall runs once per cut, and every Read
// from then on fails with errUpstreamBodyStalled. Close is idempotent and safe
// against a concurrent Read; after io.EOF, an error or Close no timer remains.
type progressBody struct {
	body    io.ReadCloser
	window  time.Duration
	onStall func(passed int64, elapsed time.Duration)
	wrapped time.Time // when the body was wrapped

	mu       sync.Mutex
	passed   int64       // bytes read from the upstream body so far
	timer    *time.Timer // nil until the first Read
	reading  bool        // a Read is waiting on the upstream body
	done     bool        // closed, ended, or cut: no timer is armed again
	deadline time.Time   // when the Read in flight is cut
	stalled  bool

	closeOnce sync.Once
	closeErr  error
}

// newProgressBody wraps body. No timer runs until the first Read. onStall
// runs once, before the body is closed, when the body is cut, with the bytes
// passed so far and the time since the body was wrapped.
func newProgressBody(body io.ReadCloser, window time.Duration, onStall func(passed int64, elapsed time.Duration)) *progressBody {
	return &progressBody{body: body, window: window, onStall: onStall, wrapped: time.Now()}
}

// stall is the timer's callback. A firing that raced a Read which already
// returned, or a later Read that moved the deadline, does nothing.
func (p *progressBody) stall() {
	p.mu.Lock()
	if p.done || !p.reading || time.Now().Before(p.deadline) {
		p.mu.Unlock()
		return
	}
	p.done, p.stalled = true, true
	passed := p.passed
	p.mu.Unlock()
	p.onStall(passed, time.Since(p.wrapped))
	p.closeBody()
}

// Read reads from the upstream body with the timer armed for the duration
// of the call only. The first error, io.EOF included, ends the watch.
func (p *progressBody) Read(b []byte) (int, error) {
	p.mu.Lock()
	if p.stalled {
		p.mu.Unlock()
		return 0, errUpstreamBodyStalled
	}
	if !p.done {
		p.reading = true
		p.deadline = time.Now().Add(p.window)
		if p.timer == nil {
			p.timer = time.AfterFunc(p.window, p.stall)
		} else {
			p.timer.Reset(p.window)
		}
	}
	p.mu.Unlock()

	n, err := p.body.Read(b)

	p.mu.Lock()
	p.reading = false
	p.passed += int64(n)
	if p.timer != nil {
		p.timer.Stop()
	}
	if err != nil {
		p.done = true
	}
	stalled := p.stalled
	p.mu.Unlock()
	if stalled {
		err = errUpstreamBodyStalled
	}
	return n, err
}

// Close stops the timer and closes the upstream body once. It is safe to call
// more than once and concurrently with Read.
func (p *progressBody) Close() error {
	p.mu.Lock()
	p.done = true
	if p.timer != nil {
		p.timer.Stop()
	}
	p.mu.Unlock()
	return p.closeBody()
}

func (p *progressBody) closeBody() error {
	p.closeOnce.Do(func() { p.closeErr = p.body.Close() })
	return p.closeErr
}

// watchesBody reports whether resp has a body a progress timer should watch:
// not a HEAD, not an empty or absent body, not a protocol switch (whose body
// the proxy takes over as the connection).
func watchesBody(resp *http.Response) bool {
	if resp.Body == nil || resp.Body == http.NoBody || resp.ContentLength == 0 {
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return false
	}
	return resp.Request == nil || resp.Request.Method != http.MethodHead
}
