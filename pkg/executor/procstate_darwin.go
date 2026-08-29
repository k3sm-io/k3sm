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
	"errors"

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
// It fails safe: any inconclusive answer reports false ("still running"), so the
// health deadline keeps its meaning rather than being defeated by a probe error.
// A recycled PID likewise reports the live stranger as running, which is the
// conservative verdict.
func processExited(pid int) bool {
	if pid <= 0 {
		return false
	}
	// kern.proc.pid for a PID that has left the process table succeeds with a
	// ZERO-length read (it is not an error), so the length — not the error — is
	// what says "gone". ESRCH is the same verdict by a different path.
	raw, err := unix.SysctlRaw("kern.proc.pid", pid)
	if err != nil {
		return errors.Is(err, unix.ESRCH)
	}
	if len(raw) == 0 {
		return true
	}
	// The PID is still in the table; only SZOMB means it has actually exited.
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return false
	}
	return kp.Proc.P_stat == pStatZombie
}
