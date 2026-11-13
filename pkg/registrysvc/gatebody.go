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
// cuts a slow transfer that keeps moving.
const gateUpstreamBodyProgress = relayWriteProgress

// errUpstreamBodyStalled is the read error of an upstream body the gate cut
// for making no progress.
var errUpstreamBodyStalled = errors.New("the local registry sent no response bytes within the progress window")

// progressBody is an upstream response body that closes itself when no byte
// arrives for window. Closing it fails the reverse proxy's copy loop, which
// drops the client connection and releases the upstream one.
type progressBody struct {
	body    io.ReadCloser
	window  time.Duration
	onStall func()
	timer   *time.Timer

	mu       sync.Mutex
	done     bool      // closed, ended, or cut: the timer must not act again
	deadline time.Time // when the body is cut if no byte arrives first
	stalled  bool

	closeOnce sync.Once
	closeErr  error
}

// newProgressBody wraps body and arms its progress timer. onStall runs once,
// before the body is closed, when the body is cut.
func newProgressBody(body io.ReadCloser, window time.Duration, onStall func()) *progressBody {
	p := &progressBody{body: body, window: window, onStall: onStall, deadline: time.Now().Add(window)}
	p.timer = time.AfterFunc(window, p.stall)
	return p
}

// stall is the timer's callback. A firing that raced a Read which moved the
// deadline returns; the timer that Read re-armed fires again at the new one.
func (p *progressBody) stall() {
	p.mu.Lock()
	if p.done || time.Now().Before(p.deadline) {
		p.mu.Unlock()
		return
	}
	p.done, p.stalled = true, true
	p.mu.Unlock()
	p.onStall()
	p.closeBody()
}

// Read reads from the upstream body and re-arms the timer on progress. The
// first error, io.EOF included, ends the watch.
func (p *progressBody) Read(b []byte) (int, error) {
	n, err := p.body.Read(b)
	p.mu.Lock()
	switch {
	case p.done:
	case err != nil:
		p.done = true
		p.timer.Stop()
	case n > 0:
		p.deadline = time.Now().Add(p.window)
		p.timer.Reset(p.window)
	}
	stalled := p.stalled
	p.mu.Unlock()
	if err != nil && stalled {
		err = errUpstreamBodyStalled
	}
	return n, err
}

// Close stops the timer and closes the upstream body once. It is safe to call
// more than once and concurrently with Read.
func (p *progressBody) Close() error {
	p.mu.Lock()
	p.done = true
	p.timer.Stop()
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
