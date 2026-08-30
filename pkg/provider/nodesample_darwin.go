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
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#include <sys/types.h>

// k3sm_vmstat carries exactly the page classes the node-pressure memory formula
// needs, widened to uint64 so the Go side never handles a C bitfield width.
typedef struct {
	uint64_t page_size;
	uint64_t wire;
	uint64_t internal;
	uint64_t purgeable;
	uint64_t compressor;
} k3sm_vmstat;

// k3sm_required_vm_count is the number of natural_t units host_statistics64 must
// have written for every field we read to be valid. internal_page_count is the
// LAST field this shim touches, so covering it covers all of them. We compute it
// from offsetof rather than trusting HOST_VM_INFO64_COUNT: the kernel returns
// min(requested, available) in *count, and an older kernel that fills fewer units
// would otherwise hand us uninitialised trailing fields as page counts.
static mach_msg_type_number_t k3sm_required_vm_count(void) {
	return (mach_msg_type_number_t)
		((offsetof(vm_statistics64_data_t, internal_page_count) + sizeof(natural_t)) / sizeof(natural_t));
}

// k3sm_vmstat_read fills out from one host_statistics64(HOST_VM_INFO64) reading
// plus host_page_size, both taken through the caller-supplied host port. Returns
// 0 on success, or a negative kern_return_t / positive errno-style code.
//
// The page size comes from host_page_size in the SAME call, never from a compiled
// constant: Apple Silicon reports 16384, and a reflexive 4096 would under-report
// the working set by 4x and trip an absolute memory floor on a healthy machine.
static int k3sm_vmstat_read(mach_port_t host, k3sm_vmstat *out) {
	vm_statistics64_data_t st;
	mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
	kern_return_t kr = host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&st, &count);
	if (kr != KERN_SUCCESS) {
		return -(int)kr;
	}
	if (count < k3sm_required_vm_count()) {
		return -1;
	}
	vm_size_t ps = 0;
	kr = host_page_size(host, &ps);
	if (kr != KERN_SUCCESS) {
		return -(int)kr;
	}
	out->page_size = (uint64_t)ps;
	out->wire = (uint64_t)st.wire_count;
	out->internal = (uint64_t)st.internal_page_count;
	out->purgeable = (uint64_t)st.purgeable_count;
	out->compressor = (uint64_t)st.compressor_page_count;
	return 0;
}

// k3sm_proc_count reports how many entries the global process table currently
// holds, via a SIZE-ONLY sysctl(KERN_PROC_ALL) query: oldp is NULL, so the kernel
// answers with the byte length it would need and copies out NO process data at
// all. Nothing about any individual process is read.
//
// The kernel's size answer includes a small slack allowance over the true count
// (single digits on a live host), so the result is a slight over-estimate — the
// safe direction for a pressure signal.
static int k3sm_proc_count(uint64_t *out) {
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
	size_t len = 0;
	if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0) {
		return errno;
	}
	*out = (uint64_t)(len / sizeof(struct kinfo_proc));
	return 0;
}
*/
import "C"

import (
	"fmt"
	"sync"
)

// machHostPort is the Mach host port every sample reads through, acquired ONCE
// for the lifetime of the process.
//
// mach_host_self() increments a send-right user reference count on every call, so
// calling it per status tick leaks a send right per minute in the one process
// whose death takes the whole node down. Acquiring it once and never deallocating
// it is the correct lifetime here: the port is needed for as long as the process
// samples, which is until it exits.
var machHostPort = sync.OnceValue(func() C.mach_port_t { return C.mach_host_self() })

// sampleHostMemory returns available and total physical memory in bytes.
//
// available = capacity - workingSet, with
//
//	workingSet = (wire + internal - purgeable + compressor) * pageSize
//
// See hostStats.MemAvailableBytes for why speculative and inactive pages are
// absent from that sum; this function is the sole producer of that contract.
// capacity is supplied by the caller (hw.memsize) rather than re-derived from the
// page classes, so the minuend is the same host fact the node advertises as
// Capacity.
func sampleHostMemory(capacityBytes int64) (int64, error) {
	var st C.k3sm_vmstat
	if rc := C.k3sm_vmstat_read(machHostPort(), &st); rc != 0 {
		return 0, fmt.Errorf("host_statistics64: rc %d", int(rc))
	}
	pageSize := int64(st.page_size)
	if pageSize <= 0 {
		return 0, fmt.Errorf("host_page_size reported %d", pageSize)
	}
	// purgeable pages are a SUBSET of internal ones, so the subtraction cannot
	// take the page total negative on a coherent reading; clamp anyway rather
	// than publish a negative working set if the kernel ever disagrees.
	pages := int64(st.wire) + int64(st.internal) - int64(st.purgeable) + int64(st.compressor)
	if pages < 0 {
		pages = 0
	}
	workingSet := pages * pageSize
	available := capacityBytes - workingSet
	if available < 0 {
		available = 0
	}
	return available, nil
}

// sampleProcessCount returns the number of processes in the machine's global
// process table. See the k3sm_proc_count shim for why this is a size-only query
// and why the answer is a slight over-estimate.
func sampleProcessCount() (int64, error) {
	var n C.uint64_t
	if rc := C.k3sm_proc_count(&n); rc != 0 {
		return 0, fmt.Errorf("sysctl kern.proc.all (size query): errno %d", int(rc))
	}
	return int64(n), nil
}
