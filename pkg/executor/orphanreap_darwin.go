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

package executor

/*
#include <libproc.h>
#include <sys/proc_info.h>
*/
import "C"

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// defaultOrphanSeams reads the process table with sysctl(3) and each process's
// executable with proc_pidpath(3), the kernel's own record of the vnode it
// exec'd. That is the deliberate choice over kern.procargs2's exec path, which
// lives in the target's own memory and so is whatever the process says it is.
var defaultOrphanSeams = orphanSeams{
	list:   listOrphanCandidates,
	lookup: lookupOrphanCandidate,
	kill:   func(pid int, sig syscall.Signal) error { return unix.Kill(pid, sig) },
}

// listOrphanCandidates lists the live processes of this effective uid: the only
// ones a server's children can be, and the only ones it may signal.
func listOrphanCandidates() ([]orphanProc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.uid: %w", err)
	}
	out := make([]orphanProc, 0, len(kps))
	for i := range kps {
		if p, ok := orphanFromKinfo(&kps[i]); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// lookupOrphanCandidate re-reads one pid; ok is false when it is gone, a zombie,
// or its executable can no longer be read.
func lookupOrphanCandidate(pid int) (orphanProc, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(kp.Proc.P_pid) != pid {
		return orphanProc{}, false
	}
	return orphanFromKinfo(kp)
}

func orphanFromKinfo(kp *unix.KinfoProc) (orphanProc, bool) {
	pid := int(kp.Proc.P_pid)
	if pid <= 0 || kp.Proc.P_stat == pStatZombie {
		return orphanProc{}, false
	}
	exe, ok := procPIDPath(pid)
	if !ok {
		return orphanProc{}, false
	}
	return orphanProc{
		pid:           pid,
		ppid:          int(kp.Eproc.Ppid),
		pgid:          int(kp.Eproc.Pgid),
		startUnixNano: kp.Proc.P_starttime.Nano(),
		exe:           exe,
	}, true
}

// procPIDPath is proc_pidpath(3): the path of the executable pid is running.
func procPIDPath(pid int) (string, bool) {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", false
	}
	return C.GoStringN(&buf[0], n), true
}

// ProcessStartTime reports this process's kernel start time (kinfo_proc
// p_starttime), the "started before this server" bound ReapOrphanedControlPlane
// takes.
func ProcessStartTime() (time.Time, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return time.Time{}, fmt.Errorf("read this process's start time: %w", err)
	}
	return time.Unix(0, kp.Proc.P_starttime.Nano()), nil
}
