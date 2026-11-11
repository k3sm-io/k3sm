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
// bring-up needs, the one- and five-minute load averages per core, read from
// the same vm.loadavg sysctl uptime(1) prints.

// HostLoadPerCorePressured is the load average per core at or above which the
// host counts as under pressure. Two runnable threads per core means every core
// has a queue, which is when a ninety-second apiserver health wait stops
// measuring the apiserver and starts measuring the scheduler.
const HostLoadPerCorePressured = 2.0

// HostLoad is one vm.loadavg sample and the core count it is judged against.
type HostLoad struct {
	Load1, Load5 float64
	Cores        int
}

// Pressured reports whether the load is sustained: BOTH the one-minute and the
// five-minute average per core are at or above HostLoadPerCorePressured. The
// one-minute figure alone is a spike detector, and a spike that started a
// minute before the timeout (often the bring-up's own burst) did not make a
// ninety-second wait run out; a host that has been queued for five minutes did.
func (l HostLoad) Pressured() bool {
	cores := l.Cores
	if cores < 1 {
		cores = 1
	}
	return l.Load1/float64(cores) >= HostLoadPerCorePressured &&
		l.Load5/float64(cores) >= HostLoadPerCorePressured
}

// String is the sample as the bring-up record's Detail carries it.
func (l HostLoad) String() string {
	return fmt.Sprintf("host load average 1m %.2f, 5m %.2f on %d cores (pressure at %.1f per core on both)",
		l.Load1, l.Load5, l.Cores, HostLoadPerCorePressured)
}

// ReadHostLoad samples vm.loadavg.
func ReadHostLoad() (HostLoad, error) {
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return HostLoad{}, err
	}
	l1, l5, err := decodeLoadavg(raw)
	if err != nil {
		return HostLoad{}, err
	}
	return HostLoad{Load1: l1, Load5: l5, Cores: runtime.NumCPU()}, nil
}

// HostUnderPressure reports whether the host's load is sustained at or above
// HostLoadPerCorePressured (HostLoad.Pressured), with the sample rendered for
// the record. An error is returned when the load cannot be read; a caller
// treats that as "not under pressure".
func HostUnderPressure() (pressured bool, reading string, err error) {
	l, err := ReadHostLoad()
	if err != nil {
		return false, "", err
	}
	return l.Pressured(), l.String(), nil
}

// decodeLoadavg decodes the one- and five-minute figures from a raw vm.loadavg
// answer, struct loadavg { fixpt_t ldavg[3]; long fscale; } in host byte order:
// three uint32 fixed-point values, four bytes of padding, then the int64 scale.
func decodeLoadavg(raw []byte) (load1, load5 float64, err error) {
	if len(raw) != 24 {
		return 0, 0, fmt.Errorf("sysctl vm.loadavg: %d-byte answer, want 24 (struct loadavg)", len(raw))
	}
	scale := int64(binary.NativeEndian.Uint64(raw[16:24]))
	if scale <= 0 || scale > math.MaxInt32 {
		return 0, 0, fmt.Errorf("sysctl vm.loadavg: implausible fscale %d", scale)
	}
	load1 = float64(binary.NativeEndian.Uint32(raw[0:4])) / float64(scale)
	load5 = float64(binary.NativeEndian.Uint32(raw[4:8])) / float64(scale)
	return load1, load5, nil
}
