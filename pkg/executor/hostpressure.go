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

package executor

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"

	"golang.org/x/sys/unix"
)

// The host-pressure reading behind the slow bring-up classification.
//
// The node budget's pressure monitor (pkg/provider) cannot be imported here:
// pkg/provider imports this package. So this is the narrow slice the slow
// bring-up needs, the one-minute load average per core, read from the same
// vm.loadavg sysctl uptime(1) prints.

// HostLoadPerCorePressured is the one-minute load average per core at or above
// which the host counts as under pressure. Two runnable threads per core means
// every core has a queue, which is when a ninety-second apiserver health wait
// stops measuring the apiserver and starts measuring the scheduler.
const HostLoadPerCorePressured = 2.0

// HostUnderPressure reports whether the host's one-minute load average per
// core is at or above HostLoadPerCorePressured. An error is returned when the
// load cannot be read; a caller treats that as "not under pressure".
func HostUnderPressure() (bool, error) {
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return false, err
	}
	load, err := decodeLoadavg1(raw)
	if err != nil {
		return false, err
	}
	return loadPressured(load, runtime.NumCPU()), nil
}

// loadPressured is the pure verdict over a load average and a core count.
func loadPressured(load float64, cores int) bool {
	if cores < 1 {
		cores = 1
	}
	return load/float64(cores) >= HostLoadPerCorePressured
}

// decodeLoadavg1 decodes the one-minute figure from a raw vm.loadavg answer,
// struct loadavg { fixpt_t ldavg[3]; long fscale; } in host byte order: three
// uint32 fixed-point values, four bytes of padding, then the int64 scale.
func decodeLoadavg1(raw []byte) (float64, error) {
	if len(raw) != 24 {
		return 0, fmt.Errorf("sysctl vm.loadavg: %d-byte answer, want 24 (struct loadavg)", len(raw))
	}
	ld := binary.NativeEndian.Uint32(raw[0:4])
	scale := int64(binary.NativeEndian.Uint64(raw[16:24]))
	if scale <= 0 || scale > math.MaxInt32 {
		return 0, fmt.Errorf("sysctl vm.loadavg: implausible fscale %d", scale)
	}
	return float64(ld) / float64(scale), nil
}
