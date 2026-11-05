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
	"bytes"
	"errors"
	"log/slog"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pStatZombie is SZOMB from <sys/proc.h>: the process has exited and is waiting
// to be reaped. It is a stable, documented kernel constant (not a private SPI),
// but golang.org/x/sys/unix does not export it, so it is spelled out here.
const pStatZombie = 5

// processExited reports whether pid has exited — either already reaped, or a
// zombie awaiting its wait4. It asks the kernel DIRECTLY (kern.proc.pid), on the
// caller's own goroutine, so the answer does not depend on the reaper goroutine
// having been scheduled; that independence is the whole point (see awaitHealthy).
//
// The verdict comes from ONE kern.proc.pid snapshot. A second read could straddle
// the reaper's wait4: the first read sees the zombie, the reap empties the slot,
// and the second read finds nothing, which reads as "running" for a dead child. A
// single snapshot is either the zombie (exited) or an empty slot (exited), so once
// this reports true for a child it keeps reporting true across the reap.
//
// It fails safe: any inconclusive answer reports false ("still running"), so the
// health deadline keeps its meaning rather than being defeated by a probe error.
// A recycled PID likewise reports the live stranger as running, which is the
// conservative verdict.
func processExited(pid int) bool {
	return processExitedVia(procSysctlRaw, pid)
}

// procSysctlRaw is the kernel read behind processExited, a seam so a test can
// feed a record of any size or reap between two reads.
var procSysctlRaw = func(pid int) ([]byte, error) {
	return unix.SysctlRaw("kern.proc.pid", pid)
}

// procSizeWarnOnce limits the unexpected-record-size warning to one line per
// process lifetime; procSizeWarn is the seam that emits it.
var (
	procSizeWarnOnce sync.Once
	procSizeWarn     = func(got, want int) {
		slog.Warn("kern.proc.pid returned an unexpected record size; process exit cannot be detected directly and children read as running",
			"length", got, "expected", want)
	}
)

func processExitedVia(read func(int) ([]byte, error), pid int) bool {
	if pid <= 0 {
		return false
	}
	// kern.proc.pid for a PID that has left the process table succeeds with a
	// ZERO-length read (it is not an error), so the length — not the error — is
	// what says "gone". ESRCH is the same verdict by a different path.
	raw, err := read(pid)
	if err != nil {
		return errors.Is(err, unix.ESRCH)
	}
	switch len(raw) {
	case 0:
		return true
	case unix.SizeofKinfoProc:
		// The PID is still in the table; only SZOMB means it has actually exited.
		// Decode the bytes of this same read rather than asking again (see above).
		// This is the copy x/sys's own SysctlKinfoProc does in effect: the kernel
		// wrote a struct kinfo_proc in native layout, which unix.KinfoProc mirrors.
		var kp unix.KinfoProc
		copy((*[unix.SizeofKinfoProc]byte)(unsafe.Pointer(&kp))[:], raw)
		return kp.Proc.P_stat == pStatZombie
	default:
		procSizeWarnOnce.Do(func() { procSizeWarn(len(raw), unix.SizeofKinfoProc) })
		return false
	}
}

// processIsEtcd reports whether pid is a live (not zombie) process whose command name
// is etcd. A recycled pid that now names something else reads false, which is what
// keeps a stale status record from refusing a restore forever; an inconclusive kernel
// answer reads true, the conservative verdict for a check that guards a data dir.
func processIsEtcd(pid int) bool {
	if pid <= 0 || processExited(pid) {
		return false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return true
	}
	comm := kp.Proc.P_comm[:]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	return string(comm) == etcdBinaryName
}
