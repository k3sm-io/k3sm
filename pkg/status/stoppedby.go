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

package status

import (
	"fmt"
	"time"
)

// StoppedBy says who stopped k3sm on this Mac, from the stop marker `k3sm
// stop` writes. It is additive and carries no verdict or state word: the
// stopped and disabled states stay what they were.
type StoppedBy struct {
	// Actor is "user" or "auto".
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
	// At is when the stop began, RFC 3339.
	At time.Time `json:"at"`
	// Phase is "stopping" (a stop left something behind) or "stopped".
	Phase string `json:"phase"`
}

// stoppedBy reads the stop marker through the StopMarker seam. An absent,
// unreadable or unparseable marker yields nil and never fails the report.
func (c Collector) stoppedBy() *StoppedBy {
	if c.StopMarker == nil {
		return nil
	}
	m, present, err := c.StopMarker()
	if !present || err != nil {
		return nil
	}
	return &StoppedBy{Actor: m.Actor, Reason: m.Reason, At: m.At, Phase: string(m.Phase)}
}

// stoppedByLine is the human view's one line, or "" when the report has none.
func stoppedByLine(r Report) string {
	sb := r.StoppedBy
	if sb == nil {
		return ""
	}
	line := fmt.Sprintf("%s by %s", sb.Phase, sb.Actor)
	if sb.Reason != "" {
		line += ": " + sb.Reason
	}
	if !sb.At.IsZero() && !r.Timestamp.IsZero() {
		line += ", " + r.Timestamp.Sub(sb.At).Round(time.Second).String() + " ago"
	}
	return line
}
