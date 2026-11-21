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
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// gateReadWarnInterval is how often, at most, the gate warns for each cause
// that a read could not reach the local registry. A registry that is down
// fails every pull a peer makes; one warning a minute says so, and the
// failures in between are Debug and counted in the next warning.
const gateReadWarnInterval = time.Minute

// readCause is why a read could not reach the local registry: a closed set,
// so the limiter's state is bounded however many distinct errors there are.
type readCause uint8

const (
	causeRefused readCause = iota // nothing listens on the registry's port
	causeTimeout                  // the dial or the response headers timed out
	causeOther                    // anything else
	numCauses
)

func (c readCause) String() string {
	switch c {
	case causeRefused:
		return "refused"
	case causeTimeout:
		return "timeout"
	default:
		return "other"
	}
}

// readCauseOf classifies a read's upstream error by its type, never by its
// text, path or peer. The caller handles context.Canceled before this.
func readCauseOf(err error) readCause {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return causeRefused
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return causeTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return causeTimeout
	}
	return causeOther
}

// upstreamWarnLimiter decides, per cause, whether a failure to reach the
// local registry is the one warning of its interval. The gate keeps one for
// reads and one for writes. Each cause has its own warnGate, the same gate
// the relay's limit listener uses.
type upstreamWarnLimiter struct {
	byCause [numCauses]warnGate
}

// allow reports whether a failure of cause c at now is to be a warning, and
// if so how many failures of c were suppressed since the last one. It does
// not log.
func (l *upstreamWarnLimiter) allow(now time.Time, c readCause) (warn bool, suppressed int) {
	suppressed, warn = l.byCause[c].allow(now, gateReadWarnInterval)
	return warn, suppressed
}
