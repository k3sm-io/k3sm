//go:build darwin && cgo

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

/*
#include <stdint.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_host.h>

// k3sm_cpuload carries the aggregate HOST_CPU_LOAD_INFO tick counters, each
// widened from a 32-bit natural_t to uint64 so the Go side handles no C integer
// type, plus the tick rate the counters are expressed in.
typedef struct {
	uint64_t user;
	uint64_t system;
	uint64_t idle;
	uint64_t nice;
	uint64_t clk_tck;
} k3sm_cpuload;

// k3sm_cpuload_read fills out from ONE host_statistics(HOST_CPU_LOAD_INFO) call:
// the machine-wide sum across every CPU, in fixed-size storage (no vm_allocate,
// unlike host_processor_info, so nothing to deallocate). Returns 0 on success, a
// negative kern_return_t on a Mach failure, or -1 on a short answer or an
// unusable tick rate.
//
// The counters are scheduler TICKS at sysconf(_SC_CLK_TCK) Hz. They are NOT
// mach_absolute_time units, so the mach timebase ratio must not be applied.
static int k3sm_cpuload_read(mach_port_t host, k3sm_cpuload *out) {
	host_cpu_load_info_data_t info;
	mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
	kern_return_t kr = host_statistics(host, HOST_CPU_LOAD_INFO, (host_info_t)&info, &count);
	if (kr != KERN_SUCCESS) {
		return -(int)kr;
	}
	if (count < HOST_CPU_LOAD_INFO_COUNT) {
		return -1;
	}
	long tck = sysconf(_SC_CLK_TCK);
	if (tck <= 0) {
		return -1;
	}
	out->user = (uint64_t)info.cpu_ticks[CPU_STATE_USER];
	out->system = (uint64_t)info.cpu_ticks[CPU_STATE_SYSTEM];
	out->idle = (uint64_t)info.cpu_ticks[CPU_STATE_IDLE];
	out->nice = (uint64_t)info.cpu_ticks[CPU_STATE_NICE];
	out->clk_tck = (uint64_t)tck;
	return 0;
}
*/
import "C"

import "fmt"

// readHostCPUTicks returns one raw aggregate HOST_CPU_LOAD_INFO reading: the
// user, system and nice tick counters (each a 32-bit natural_t that wraps) and
// the tick rate in Hz. Idle is read but not returned; node CPU usage excludes it.
func readHostCPUTicks() (cpuTicks, error) {
	var st C.k3sm_cpuload
	if rc := C.k3sm_cpuload_read(machHostPort(), &st); rc != 0 {
		return cpuTicks{}, fmt.Errorf("host_statistics(HOST_CPU_LOAD_INFO): rc %d", int(rc))
	}
	return cpuTicks{
		user:   uint64(st.user),
		system: uint64(st.system),
		nice:   uint64(st.nice),
		hz:     uint64(st.clk_tck),
	}, nil
}

// hostCPUSupported reports whether this build reads the host CPU counters.
const hostCPUSupported = true
