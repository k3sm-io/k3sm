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

package vkadapter

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	vklog "github.com/virtual-kubelet/virtual-kubelet/log"
)

// vkLogRepeatWindow is how long an identical Virtual Kubelet warning (same
// message, same error text) is held back after it was last emitted. VK retries a
// failing status PATCH or Lease update every 10 s, so without the window an
// outage of a few minutes would print the same line dozens of times; with it the
// line appears at most once per window and says how many repeats it stood for.
const vkLogRepeatWindow = 30 * time.Second

// vkLogMaxValue caps a single string field. VK attaches the whole node-status
// patch to its "Failed to patch node status" line; the error names the cause and
// the patch is kilobytes of conditions nobody reads in a log.
const vkLogMaxValue = 256

// vkLogMaxKeys bounds the repeat limiter's memory. A key is a message plus an
// error text, so a stream of distinct errors could otherwise grow it forever.
const vkLogMaxKeys = 256

// vkLogger is the virtual-kubelet log.Logger over slog.
//
// Virtual Kubelet's logger defaults to a no-op, so its own account of a failed
// status PATCH, a failed Lease update or a failed Ping was discarded and a node
// that stopped heartbeating did so without a line in the log. This adapter is
// what makes those lines reach the daemon log. Levels are mapped so the useful
// lines are visible and the chatty ones are not:
//
//   - Debug and Info go to slog Debug. VK's Info is per-pod bookkeeping
//     ("Updated k8s pod status") that would otherwise drown the log.
//   - Warn and Error go to slog Warn. Every VK Error on this path is a retried
//     apiserver failure ("failed to update node lease"), a condition an
//     operator should see but not a fault of this process.
//   - Fatal goes to slog Error. VK never calls it on k3sm's path, and this
//     adapter never exits the process for it.
//
// Warn lines are rate-limited per (message, error) by a limiter shared across
// every logger derived from one root, so the repeat count holds however VK
// threads its fields.
type vkLogger struct {
	log   *slog.Logger
	attrs []any
	lim   *repeatLimiter
}

var _ vklog.Logger = (*vkLogger)(nil)

// newVKLogger returns the adapter over l.
func newVKLogger(l *slog.Logger) *vkLogger {
	return &vkLogger{log: l, lim: newRepeatLimiter(vkLogRepeatWindow, time.Now)}
}

// vkLoggerOnce guards the process-wide vklog.L assignment: VK reads it from any
// goroutine, so it is written once, before the first node runs.
var vkLoggerOnce sync.Once

// installVKLogger makes l the default Virtual Kubelet logger for the process.
// Only the first call has an effect; a process runs one node, and the per-node
// logger also rides every context Node.Run hands VK (vklog.WithLogger), which
// is where VK's node and lease controllers read it from.
func installVKLogger(l vklog.Logger) {
	vkLoggerOnce.Do(func() { vklog.L = l })
}

func (l *vkLogger) with(kv ...any) *vkLogger {
	attrs := make([]any, 0, len(l.attrs)+len(kv))
	attrs = append(attrs, l.attrs...)
	attrs = append(attrs, kv...)
	return &vkLogger{log: l.log, attrs: attrs, lim: l.lim}
}

// emit writes msg at level with the logger's fields. Warn and above pass the
// repeat limiter first.
func (l *vkLogger) emit(level slog.Level, msg string) {
	ctx := context.Background()
	if !l.log.Enabled(ctx, level) {
		return
	}
	attrs := l.attrs
	if level >= slog.LevelWarn {
		ok, suppressed := l.lim.allow(msg + "\x00" + addrPort.ReplaceAllString(errorText(attrs), "<addr>"))
		if !ok {
			return
		}
		if suppressed > 0 {
			attrs = append(append([]any(nil), attrs...), "repeats_suppressed", suppressed)
		}
	}
	l.log.Log(ctx, level, msg, attrs...)
}

func (l *vkLogger) Debug(args ...any) { l.emit(slog.LevelDebug, fmt.Sprint(args...)) }
func (l *vkLogger) Debugf(format string, args ...any) {
	l.emit(slog.LevelDebug, fmt.Sprintf(format, args...))
}
func (l *vkLogger) Info(args ...any) { l.emit(slog.LevelDebug, fmt.Sprint(args...)) }
func (l *vkLogger) Infof(format string, args ...any) {
	l.emit(slog.LevelDebug, fmt.Sprintf(format, args...))
}
func (l *vkLogger) Warn(args ...any) { l.emit(slog.LevelWarn, fmt.Sprint(args...)) }
func (l *vkLogger) Warnf(format string, args ...any) {
	l.emit(slog.LevelWarn, fmt.Sprintf(format, args...))
}
func (l *vkLogger) Error(args ...any) { l.emit(slog.LevelWarn, fmt.Sprint(args...)) }
func (l *vkLogger) Errorf(format string, args ...any) {
	l.emit(slog.LevelWarn, fmt.Sprintf(format, args...))
}
func (l *vkLogger) Fatal(args ...any) { l.emit(slog.LevelError, fmt.Sprint(args...)) }
func (l *vkLogger) Fatalf(format string, args ...any) {
	l.emit(slog.LevelError, fmt.Sprintf(format, args...))
}

// WithField implements vklog.Logger.
func (l *vkLogger) WithField(key string, val any) vklog.Logger {
	return l.with(key, clampValue(val))
}

// WithFields implements vklog.Logger.
func (l *vkLogger) WithFields(f vklog.Fields) vklog.Logger {
	kv := make([]any, 0, 2*len(f))
	for k, v := range f {
		kv = append(kv, k, clampValue(v))
	}
	return l.with(kv...)
}

// WithError implements vklog.Logger.
func (l *vkLogger) WithError(err error) vklog.Logger {
	if err == nil {
		return l
	}
	return l.with("error", clampValue(err.Error()))
}

// addrPort matches an IPv4 or bracketed IPv6 address with its port. Repeats are
// keyed on the error text with these blanked, because every redial after a
// roam picks a new source port and would otherwise make each line unique.
var addrPort = regexp.MustCompile(`(\[[0-9A-Fa-f:.]+(%[0-9A-Za-z]+)?\]|\d{1,3}(\.\d{1,3}){3}):\d+`)

// errorText returns the value of the last "error" field in attrs, the part of a
// warning that distinguishes one failure from another.
func errorText(attrs []any) string {
	for i := len(attrs) - 2; i >= 0; i -= 2 {
		if k, ok := attrs[i].(string); ok && k == "error" {
			return fmt.Sprint(attrs[i+1])
		}
	}
	return ""
}

// clampValue shortens a long string (or []byte, or Stringer) field to
// vkLogMaxValue bytes.
func clampValue(v any) any {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case []byte:
		s = string(t)
	case fmt.Stringer:
		s = t.String()
	default:
		return v
	}
	if len(s) > vkLogMaxValue {
		return s[:vkLogMaxValue] + "...(truncated)"
	}
	return s
}

// repeatLimiter lets a key through at most once per window and counts what it
// held back in between. Safe for concurrent use; mu guards seen.
type repeatLimiter struct {
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]*repeatEntry
}

type repeatEntry struct {
	last       time.Time
	suppressed int
}

func newRepeatLimiter(window time.Duration, now func() time.Time) *repeatLimiter {
	return &repeatLimiter{window: window, now: now, seen: make(map[string]*repeatEntry)}
}

// allow reports whether key may be emitted now and, when it may, how many
// repeats of it were held back since it was last emitted.
func (r *repeatLimiter) allow(key string) (bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if e, ok := r.seen[key]; ok {
		if now.Sub(e.last) < r.window {
			e.suppressed++
			return false, 0
		}
		n := e.suppressed
		e.last, e.suppressed = now, 0
		return true, n
	}
	if len(r.seen) >= vkLogMaxKeys {
		for k, e := range r.seen {
			if now.Sub(e.last) >= r.window {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= vkLogMaxKeys {
			// Every key is inside its window: forget them all rather than grow.
			// The cost is one extra line per key, never an unbounded map.
			clear(r.seen)
		}
	}
	r.seen[key] = &repeatEntry{last: now}
	return true, 0
}
