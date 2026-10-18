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

package provider

import (
	"context"
	"fmt"
	"math"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// PodProcessCounter is an OPTIONAL Runtime capability: a Runtime whose daemon
// keeps a process ledger can say how many live processes its pods hold. The
// node-status loop reads it for the per-uid leg of PIDPressure (see
// pidPressureUsedPercent).
//
// The count comes from the runtime's own ListPodStats answer, never from the
// provider walking the process table: the daemon that records each pod's
// process group is the only party that can count its members without racing a
// pod that forks or exits mid-walk. The runtimed runtime implements it;
// HostProcess does not, so a node running it has no per-uid leg.
type PodProcessCounter interface {
	// PodProcessCount returns the sum of the process counts the pods report,
	// and reported=false when no pod reports one.
	PodProcessCount(ctx context.Context) (count int64, reported bool, err error)
}

// sumPodProcessCounts sums PodStats.process.process_count over the pods that
// carry it. A pod whose process is nil does not report (a vm pod today) and is
// left out of the sum; it is not counted as zero. A present zero is a real
// count. reported is false when no pod reports, which skips the per-uid leg.
//
// The sum is a lower bound on the processes the pods' uid holds: a process that
// left its pod's process group (setsid) is not a member, and a pod that does
// not report adds nothing.
func sumPodProcessCounts(stats []*runtimev1.PodStats) (count int64, reported bool) {
	var total uint64
	for _, ps := range stats {
		p := ps.GetProcess()
		if p == nil {
			continue
		}
		reported = true
		n := p.GetProcessCount()
		if n > math.MaxInt64-total {
			return math.MaxInt64, true
		}
		total += n
	}
	return int64(total), reported
}

// PodProcessCount implements PodProcessCounter over one ListPodStats call.
func (r *runtimedRuntime) PodProcessCount(ctx context.Context) (int64, bool, error) {
	resp, err := r.rt.ListPodStats(ctx, &runtimev1.ListPodStatsRequest{})
	if err != nil {
		return 0, false, fmt.Errorf("runtimed list pod stats: %w", err)
	}
	count, reported := sumPodProcessCounts(resp.GetPodStats())
	return count, reported, nil
}

// PodProcessCounter returns the backing Runtime's optional PodProcessCounter
// capability, comma-ok. A Runtime without a process ledger (HostProcess)
// reports false, and the node's PIDPressure has the systemwide leg only.
func (v *VKProvider) PodProcessCounter() (PodProcessCounter, bool) {
	c, ok := v.rt.(PodProcessCounter)
	return c, ok
}
