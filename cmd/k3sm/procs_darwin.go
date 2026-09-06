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

package main

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/status"
)

// vmHostComm is the process name a Linux-container pod's Virtualization.framework
// host runs under. It is matched against kinfo_proc's p_comm, which the kernel
// truncates to MAXCOMLEN — "k3sm-vmhost" is well inside that, so no prefix match
// is needed and an exact comparison is the tighter test.
const vmHostComm = "k3sm-vmhost"

// procStatZombie is SZOMB from <sys/proc.h>: a process that has exited and is
// awaiting its parent's wait4. It is still in the process table, so a count that
// did not exclude it would report a vm pod that is already gone as running.
const procStatZombie = 5

// procTable is the production Procs seam over sysctl(3). It shells out to
// nothing and needs no cgo: kern.proc.all is a plain sysctl read.
type procTable struct{}

// Liveness probes a pid with signal 0 and reports the THREE answers the kernel
// actually gives. EPERM is the one that matters here: an ordinary account
// probing a root daemon gets it, and reading that as "dead" would report a
// healthy control plane as gone.
func (procTable) Liveness(pid int) status.Liveness {
	if pid <= 0 {
		return status.LivenessDead
	}
	switch err := unix.Kill(pid, 0); {
	case err == nil:
		return status.LivenessRunning
	case errors.Is(err, unix.EPERM):
		return status.LivenessUnknown
	default:
		return status.LivenessDead
	}
}

// VMHosts counts the live vm hosts the control plane has spawned.
func (procTable) VMHosts(serverPID int) (int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all", 0)
	if err != nil {
		return 0, err
	}
	return countVMHosts(procs, serverPID), nil
}

// countVMHosts is the pure filter behind VMHosts, split out so the three
// conditions that make a process count — the right name, not a zombie, and this
// server as its parent — are testable against a constructed table rather than
// against whatever happens to be running.
//
// The parent test is what makes the number honest on a Mac running more than one
// k3sm: a vm host belonging to a foreground `k3sm server` is not a workload of
// the installed daemon, and counting it would attribute someone else's pods.
func countVMHosts(procs []unix.KinfoProc, serverPID int) int {
	if serverPID <= 0 {
		return 0
	}
	n := 0
	for i := range procs {
		p := &procs[i]
		if comm(p.Proc.P_comm[:]) != vmHostComm {
			continue
		}
		if p.Proc.P_stat == procStatZombie {
			continue
		}
		if int(p.Eproc.Ppid) != serverPID {
			continue
		}
		n++
	}
	return n
}

// comm decodes a NUL-terminated fixed-width kernel process-name field.
func comm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
