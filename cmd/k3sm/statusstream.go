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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/status"
)

// The NDJSON stream `k3sm status --watch -o json` writes when stdout is not a
// terminal. docs/user/status-json.md (The stream) is its reader-facing
// contract; the numbers below are the ones that page states.
const (
	// streamLineCap is the longest frame the stream writes, newline included:
	// 2 MiB, the line limit of the app's framer. A report that would not fit
	// is replaced by a frame-too-large error frame.
	streamLineCap = 2 << 20
	// streamDebounce is how long a change trigger waits for the next one
	// before the report is re-collected, so a burst of watch events costs one
	// collect.
	streamDebounce = 250 * time.Millisecond
	// streamMinGap is the shortest time between two collects: at most two per
	// second, whatever the watch delivers.
	streamMinGap = 500 * time.Millisecond
	// streamMaxDelay bounds the debounce under a steady stream of events, so
	// a cluster that never goes quiet is still re-collected once a second.
	streamMaxDelay = time.Second
	// streamHeartbeat is the longest the stream goes without a collect. The
	// launchd, TLS, DNS, readyz and registry rows have no watch to trigger
	// them, so this is how fast a change there reaches the consumer.
	streamHeartbeat = 30 * time.Second
	// streamLifetime is how long one stream runs before its closing frame,
	// plus up to streamLifetimeJitter so streams started together do not
	// all end together.
	streamLifetime       = 30 * time.Minute
	streamLifetimeJitter = 3 * time.Minute
	// streamRetryMin and streamRetryMax bound the watch's reconnect backoff.
	streamRetryMin = 2 * time.Second
	streamRetryMax = time.Minute
	// streamWatchTimeout is the server-side timeout asked of each watch
	// request; the watch is re-opened from its last resource version after.
	streamWatchTimeout = 5 * time.Minute
)

// exitAuthRefused is the status the stream exits with after an auth-refused
// frame: the apiserver refused the credential, and running the stream again
// with it will be refused again.
const exitAuthRefused = 7

// The stream's frame kinds and error codes. They are a contract, documented in
// docs/user/status-json.md, and change like an API.
const (
	frameReport  = "report"
	frameError   = "error"
	frameClosing = "closing"

	// codeAuthRefused: the apiserver refused this credential (HTTP 401). The
	// stream exits exitAuthRefused after the frame.
	codeAuthRefused = "auth-refused"
	// codeApiserverUnreachable: the watch could not reach the apiserver; it
	// retries, and the heartbeat keeps the reports coming.
	codeApiserverUnreachable = "apiserver-unreachable"
	// codeWatchForbidden: this identity may not list or watch nodes or pods;
	// the stream carries on with the heartbeat alone.
	codeWatchForbidden = "watch-forbidden"
	// codeNoCredentials: there is no kubeconfig to watch with; the stream
	// carries on with the heartbeat alone.
	codeNoCredentials = "no-credentials"
	// codeFrameTooLarge: a report did not fit in streamLineCap.
	codeFrameTooLarge = "frame-too-large"
	// codeLifetime is the closing frame's code: the stream reached its
	// lifetime and ends with exit 0.
	codeLifetime = "lifetime"
)

// streamFrame is one line of the stream.
type streamFrame struct {
	Kind          string         `json:"kind"`
	SchemaVersion int            `json:"schemaVersion"`
	Report        *status.Report `json:"report,omitempty"`
	Code          string         `json:"code,omitempty"`
	Message       string         `json:"message,omitempty"`
}

// errNoStreamCredentials is the watch's answer when there is no client to
// watch with.
var errNoStreamCredentials = errors.New("no kubeconfig to watch the cluster with")

// watchSignal is one thing the cluster watch reports: a change (err nil), or
// why the watch is not running.
type watchSignal struct{ err error }

// streamClock is the stream's time: Now, and a channel that fires after d.
type streamClock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// realClock is the wall clock.
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// statusStream is the stream mode's seams.
type statusStream struct {
	// collect builds one full report, exactly as `k3sm status -o json` does.
	// A non-nil error means the apiserver refused the credential; every other
	// failure is a row in the report.
	collect func(context.Context) (status.Report, error)
	// watch reports changes to the cluster's nodes and pods until ctx ends.
	// The channel may close, after which only the heartbeat triggers.
	watch    func(context.Context) <-chan watchSignal
	clock    streamClock
	lifetime time.Duration
}

// streamLoop is one stream's state. It is owned by runStream's goroutine.
type streamLoop struct {
	r           statusRunner
	s           *statusStream
	last        *status.Report
	lastCollect time.Time
	pending     bool
	firstMark   time.Time
	due         time.Time
	lastErrCode string
}

// runStream writes the NDJSON stream until its lifetime ends, the context
// ends, or the credential is refused. The Collector stays one-shot: every
// trigger (a node or pod change, the heartbeat) runs a fresh collect, and a
// report is written only when it says something the last written one did not
// (status.SameState).
func (r statusRunner) runStream(ctx context.Context) int {
	s := r.stream
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	signals := s.watch(ctx)
	end := s.clock.Now().Add(s.lifetime)
	l := &streamLoop{r: r, s: s}
	if code, done := l.collect(ctx); done {
		return code
	}
	for {
		now := s.clock.Now()
		if !now.Before(end) {
			return l.close()
		}
		next := end
		if hb := l.lastCollect.Add(streamHeartbeat); hb.Before(next) {
			next = hb
		}
		if l.pending && l.due.Before(next) {
			next = l.due
		}
		if wait := next.Sub(now); wait > 0 {
			select {
			case <-ctx.Done():
				return 0
			case sig, ok := <-signals:
				if !ok {
					signals = nil
					continue
				}
				if code, done := l.signal(sig); done {
					return code
				}
				continue
			case <-s.clock.After(wait):
			}
		}
		now = s.clock.Now()
		if !now.Before(end) {
			continue
		}
		if (l.pending && !now.Before(l.due)) || !now.Before(l.lastCollect.Add(streamHeartbeat)) {
			if code, done := l.collect(ctx); done {
				return code
			}
		}
	}
}

// trigger schedules a collect: streamDebounce after this trigger, no sooner
// than streamMinGap after the last collect, and no later than streamMaxDelay
// after the first trigger it is folding in.
func (l *streamLoop) trigger() {
	now := l.s.clock.Now()
	if !l.pending {
		l.pending, l.firstMark = true, now
	}
	due := now.Add(streamDebounce)
	if bound := l.firstMark.Add(streamMaxDelay); due.After(bound) {
		due = bound
	}
	if gap := l.lastCollect.Add(streamMinGap); due.Before(gap) {
		due = gap
	}
	l.due = due
}

// signal handles one watch signal. A refused credential ends the stream; any
// other failure is reported once per kind of failure and also triggers a
// collect, since what broke the watch may show in the report.
func (l *streamLoop) signal(sig watchSignal) (int, bool) {
	if sig.err == nil {
		l.lastErrCode = ""
		l.trigger()
		return 0, false
	}
	if apierrors.IsUnauthorized(sig.err) {
		return l.refused(sig.err)
	}
	code := codeApiserverUnreachable
	switch {
	case apierrors.IsForbidden(sig.err):
		code = codeWatchForbidden
	case errors.Is(sig.err, errNoStreamCredentials):
		code = codeNoCredentials
	}
	if code != l.lastErrCode {
		l.lastErrCode = code
		if err := l.write(streamFrame{Kind: frameError, Code: code, Message: status.Redact(sig.err.Error())}); err != nil {
			return l.writeFailed(err)
		}
	}
	l.trigger()
	return 0, false
}

// collect runs one collect and writes its report when it changed.
func (l *streamLoop) collect(ctx context.Context) (int, bool) {
	rep, err := l.s.collect(ctx)
	l.lastCollect, l.pending = l.s.clock.Now(), false
	if err != nil {
		return l.refused(err)
	}
	if l.last != nil && status.SameState(*l.last, rep) {
		return 0, false
	}
	l.last = &rep
	if err := l.write(streamFrame{Kind: frameReport, Report: &rep}); err != nil {
		return l.writeFailed(err)
	}
	return 0, false
}

// refused writes the auth-refused frame and ends the stream.
func (l *streamLoop) refused(err error) (int, bool) {
	if werr := l.write(streamFrame{Kind: frameError, Code: codeAuthRefused, Message: status.Redact(err.Error())}); werr != nil {
		return l.writeFailed(werr)
	}
	return exitAuthRefused, true
}

// close writes the closing frame at the end of the stream's lifetime.
func (l *streamLoop) close() int {
	msg := fmt.Sprintf("the stream ends after %s; start a new one", l.s.lifetime.Round(time.Second))
	if err := l.write(streamFrame{Kind: frameClosing, Code: codeLifetime, Message: msg}); err != nil {
		code, _ := l.writeFailed(err)
		return code
	}
	return 0
}

// writeFailed reports a write failure and ends the stream.
func (l *streamLoop) writeFailed(err error) (int, bool) {
	fmt.Fprintln(l.r.errOut, "k3sm status: write stream:", err)
	return exitInternalError, true
}

// write encodes one frame as one line, in one write. A report frame over
// streamLineCap is replaced by a frame-too-large error frame.
func (l *streamLoop) write(f streamFrame) error {
	f.SchemaVersion = status.SchemaVersion
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}
	if len(b)+1 > streamLineCap {
		if f.Kind != frameReport {
			return fmt.Errorf("a %s frame of %d bytes is over the %d-byte line cap", f.Kind, len(b), streamLineCap)
		}
		return l.write(streamFrame{Kind: frameError, Code: codeFrameTooLarge,
			Message: fmt.Sprintf("the report encodes to %d bytes, over the %d-byte line cap", len(b), streamLineCap)})
	}
	_, err = l.r.out.Write(append(b, '\n'))
	return err
}

// newStatusStream wires the production stream for o.
func newStatusStream(o statusOptions) *statusStream {
	return &statusStream{
		collect:  streamCollect(o),
		watch:    streamWatch,
		clock:    realClock{},
		lifetime: streamLifetime + rand.N(streamLifetimeJitter),
	}
}

// streamCollect is one full collect, as `k3sm status -o json` makes it, that
// also reports whether the apiserver refused the credential: the report only
// says the apiserver row failed, and the stream must tell a refused credential
// apart from an unreachable server, because only the first must not be retried.
func streamCollect(o statusOptions) func(context.Context) (status.Report, error) {
	return func(ctx context.Context) (status.Report, error) {
		c := o.scopeDatavol(newStatusCollector())
		refusal := &authRefusal{}
		c.Kube = refusal.wrap(c.Kube)
		if user := c.UserKube; user != nil {
			c.UserKube = func() (status.Kube, string, error) {
				k, source, err := user()
				return refusal.wrap(k), source, err
			}
		}
		rep := c.Collect(ctx)
		return rep, refusal.get()
	}
}

// authRefusal records the first 401 any apiserver call of one collect got.
type authRefusal struct {
	mu  sync.Mutex
	err error
}

// wrap returns kube observed for 401s, or nil for a nil kube.
func (a *authRefusal) wrap(kube status.Kube) status.Kube {
	if kube == nil {
		return nil
	}
	return authObservedKube{Kube: kube, refusal: a}
}

func (a *authRefusal) note(err error) {
	if err == nil || !apierrors.IsUnauthorized(err) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err == nil {
		a.err = err
	}
}

func (a *authRefusal) get() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// authObservedKube is a Kube whose calls report a 401 to its authRefusal.
type authObservedKube struct {
	status.Kube
	refusal *authRefusal
}

// RawGet performs the GET and notes a refusal.
func (k authObservedKube) RawGet(ctx context.Context, path string) ([]byte, error) {
	b, err := k.Kube.RawGet(ctx, path)
	k.refusal.note(err)
	return b, err
}

// Nodes lists the nodes and notes a refusal.
func (k authObservedKube) Nodes(ctx context.Context) ([]corev1.Node, error) {
	n, err := k.Kube.Nodes(ctx)
	k.refusal.note(err)
	return n, err
}

// Pods lists the pods and notes a refusal.
func (k authObservedKube) Pods(ctx context.Context) ([]corev1.Pod, error) {
	p, err := k.Kube.Pods(ctx)
	k.refusal.note(err)
	return p, err
}

// streamWatchedKinds are the two kinds the stream watches: the node and
// workloads rows read them, and the report's identity may already list them.
// No other kind is watched.
var streamWatchedKinds = []schema.GroupVersionResource{
	{Version: "v1", Resource: "nodes"},
	{Version: "v1", Resource: "pods"},
}

// streamWatch watches nodes and pods, metadata only, with the credential the
// report uses (reportTopKube), and signals each change. The watch holds no
// cache: an event only triggers a collect, which reads the cluster afresh.
func streamWatch(ctx context.Context) <-chan watchSignal {
	out := make(chan watchSignal, 1)
	kube, err := reportTopKube()
	rk, ok := kube.(restKube)
	if err != nil || !ok || rk.cfg == nil {
		if err == nil {
			err = errNoStreamCredentials
		} else {
			err = fmt.Errorf("%w: %v", errNoStreamCredentials, err)
		}
		go func() {
			defer close(out)
			sendSignal(ctx, out, watchSignal{err: err})
		}()
		return out
	}
	// The report's client carries a short whole-request timeout, which would
	// end a watch after a few seconds; the watch uses the same credential with
	// that one setting cleared, and asks the server for its own timeout.
	cfg := rest.CopyConfig(rk.cfg)
	cfg.Timeout = 0
	mc, err := metadata.NewForConfig(cfg)
	if err != nil {
		go func() {
			defer close(out)
			sendSignal(ctx, out, watchSignal{err: err})
		}()
		return out
	}
	var wg sync.WaitGroup
	for _, gvr := range streamWatchedKinds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			watchKind(ctx, mc.Resource(gvr), out)
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// sendSignal delivers a signal unless ctx ends first.
func sendSignal(ctx context.Context, out chan<- watchSignal, sig watchSignal) {
	select {
	case out <- sig:
	case <-ctx.Done():
	}
}

// signalChange delivers a change without blocking: a change already waiting
// in the channel stands for this one too.
func signalChange(out chan<- watchSignal) {
	select {
	case out <- watchSignal{}:
	default:
	}
}

// watchKind watches one kind until ctx ends or the identity is refused. It
// starts from a one-item list's resource version, so no synthetic events
// replay the cluster, re-opens the watch from the last version it saw, lists
// again on 410 Gone, and backs off on any other failure. A failure is
// signalled; the re-established watch then signals a change, since events may
// have been missed while it was down.
func watchKind(ctx context.Context, res metadata.ResourceInterface, out chan<- watchSignal) {
	backoff := streamRetryMin
	failed := false
	rv := ""
	timeout := int64(streamWatchTimeout / time.Second)
	fail := func(err error) bool {
		sendSignal(ctx, out, watchSignal{err: err})
		if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
			return false
		}
		failed = true
		if !sleepUntil(ctx, backoff) {
			return false
		}
		backoff = min(backoff*2, streamRetryMax)
		return true
	}
	for ctx.Err() == nil {
		if rv == "" {
			list, err := res.List(ctx, metav1.ListOptions{Limit: 1})
			if err != nil {
				if !fail(err) {
					return
				}
				continue
			}
			rv = list.ResourceVersion
		}
		w, err := res.Watch(ctx, metav1.ListOptions{ResourceVersion: rv, AllowWatchBookmarks: true, TimeoutSeconds: &timeout})
		if err != nil {
			if apierrors.IsResourceExpired(err) || apierrors.IsGone(err) {
				rv = ""
				signalChange(out)
				continue
			}
			if !fail(err) {
				return
			}
			continue
		}
		if failed {
			failed, backoff = false, streamRetryMin
			signalChange(out)
		}
		rv = drainWatch(ctx, w, rv, out)
	}
}

// drainWatch reads one watch until it ends and returns the resource version
// to resume from: "" after 410 Gone or an error event, which makes the caller
// list again.
func drainWatch(ctx context.Context, w watch.Interface, rv string, out chan<- watchSignal) string {
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return rv
		case ev, ok := <-w.ResultChan():
			if !ok {
				return rv
			}
			if ev.Type == watch.Error {
				signalChange(out)
				return ""
			}
			if a, err := meta.Accessor(ev.Object); err == nil && a.GetResourceVersion() != "" {
				rv = a.GetResourceVersion()
			}
			if ev.Type != watch.Bookmark {
				signalChange(out)
			}
		}
	}
}
