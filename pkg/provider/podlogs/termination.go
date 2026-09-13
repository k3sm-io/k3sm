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

package podlogs

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
)

// Ported from k8s.io/kubernetes@v1.36.2
// pkg/kubelet/kuberuntime/kuberuntime_container.go
// (readLastStringFromContainerLogs) and pkg/kubelet/container/runtime.go (the
// constants), Apache-2.0.
//
// terminationMessagePolicy: FallbackToLogsOnError is what makes a crashed
// container explain itself in `kubectl describe pod` without the image having to
// write a message file. It is computed NODE-side, from the instance's own log
// file, which is why it lives here and not in the runtime: the runtime does not
// read log files.

const (
	// MaxContainerTerminationMessageLogLines is how many trailing FILE lines are
	// considered for the fallback message.
	MaxContainerTerminationMessageLogLines = 80
	// MaxContainerTerminationMessageLogLength is the byte ceiling on the
	// resulting message. It is a TAIL: when the 80 lines exceed it, the END is
	// kept, because the last thing a dying process printed is the thing worth
	// reading.
	MaxContainerTerminationMessageLogLength = 2048

	// ReasonContainerCannotRun is the terminated reason that suppresses the
	// fallback. A container that could not be started produced no output, so
	// reading its log would replace a real reason with an empty string.
	ReasonContainerCannotRun = "ContainerCannotRun"
)

// ShouldFallbackToLogs reports whether a terminated container's message should be
// taken from its log file: the pod asked for FallbackToLogsOnError, the container
// failed, it failed for a reason other than never having run, and nothing else
// already supplied a message.
func ShouldFallbackToLogs(policy corev1.TerminationMessagePolicy, exitCode int32, reason, message string) bool {
	return policy == corev1.TerminationMessageFallbackToLogsOnError &&
		exitCode != 0 &&
		reason != ReasonContainerCannotRun &&
		message == ""
}

// TerminationMessageFromLogs returns the tail of a container instance's log file
// as its termination message, or the upstream-verbatim error string when the file
// cannot be read. It never returns an error: an unreadable log is itself the most
// useful thing the status can say, and a status field is not a place to fail.
func TerminationMessageFromLogs(ctx context.Context, path string, log *slog.Logger) string {
	lines := int64(MaxContainerTerminationMessageLogLines)
	buf := newTailRing(MaxContainerTerminationMessageLogLength)
	opts := &Options{TailLines: &lines}
	// Both streams into the same ring, so stdout and stderr appear interleaved in
	// the order they were written — the same view `kubectl logs` gives.
	if err := ReadLogs(ctx, path, opts, nil, log, buf, buf); err != nil {
		return fmt.Sprintf("Error on reading termination message from logs: %v", err)
	}
	return string(buf.Bytes())
}

// tailRing is a fixed-capacity ring of bytes that keeps the LAST n written. It is
// the local stand-in for upstream's TypedRingFixed[byte], and the ring (rather
// than a truncating buffer) is what makes the message a tail instead of a head.
type tailRing struct {
	buf  []byte
	pos  int
	full bool
}

// newTailRing returns a ring holding at most n bytes. n <= 0 yields a ring that
// keeps nothing, which is a degenerate but well-defined configuration.
func newTailRing(n int) *tailRing {
	if n < 0 {
		n = 0
	}
	return &tailRing{buf: make([]byte, n)}
}

// Write appends p, discarding whatever the ring no longer has room for. It never
// returns an error: a full ring is the intended steady state, not a short write.
func (r *tailRing) Write(p []byte) (int, error) {
	n := len(p)
	if len(r.buf) == 0 {
		return n, nil
	}
	// Anything before the last cap(buf) bytes of p can never survive, so copy
	// only the tail and mark the ring full.
	if len(p) >= len(r.buf) {
		copy(r.buf, p[len(p)-len(r.buf):])
		r.pos = 0
		r.full = true
		return n, nil
	}
	for _, b := range p {
		r.buf[r.pos] = b
		r.pos++
		if r.pos == len(r.buf) {
			r.pos = 0
			r.full = true
		}
	}
	return n, nil
}

// Bytes returns the retained bytes in write order.
func (r *tailRing) Bytes() []byte {
	if !r.full {
		return r.buf[:r.pos]
	}
	out := make([]byte, 0, len(r.buf))
	out = append(out, r.buf[r.pos:]...)
	return append(out, r.buf[:r.pos]...)
}
