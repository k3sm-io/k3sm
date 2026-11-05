//go:build darwin

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
	"fmt"

	"golang.org/x/sys/unix"
)

// sampleCPUCoreSplit reads the logical CPUs of the two performance levels
// (hw.perflevel0 is the performance cluster, hw.perflevel1 the efficiency
// cluster). A host that reports fewer than two levels has no split.
func sampleCPUCoreSplit() (cpuCoreSplit, error) {
	levels, err := unix.SysctlUint32("hw.nperflevels")
	if err != nil {
		return cpuCoreSplit{}, fmt.Errorf("sysctl hw.nperflevels: %w", err)
	}
	if levels < 2 {
		return cpuCoreSplit{}, nil
	}
	perf, err := unix.SysctlUint32("hw.perflevel0.logicalcpu")
	if err != nil {
		return cpuCoreSplit{}, fmt.Errorf("sysctl hw.perflevel0.logicalcpu: %w", err)
	}
	eff, err := unix.SysctlUint32("hw.perflevel1.logicalcpu")
	if err != nil {
		return cpuCoreSplit{}, fmt.Errorf("sysctl hw.perflevel1.logicalcpu: %w", err)
	}
	return cpuCoreSplit{performance: int64(perf), efficiency: int64(eff), split: true}, nil
}
