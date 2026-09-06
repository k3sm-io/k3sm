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
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/status"
)

// proc builds one kinfo_proc entry: a process name, a state, and a parent.
func proc(name string, stat int8, ppid int32) unix.KinfoProc {
	var p unix.KinfoProc
	copy(p.Proc.P_comm[:], name)
	p.Proc.P_stat = stat
	p.Eproc.Ppid = ppid
	return p
}

// TestVMHostsFiltersZombiesAndForeignParents pins the three conditions that make
// a process count as one of THIS control plane's vm hosts. Each is load-bearing:
// a zombie is a pod that has already exited, and a host with a different parent
// belongs to somebody else's k3sm — counting either would attribute workloads
// this cluster is not running.
func TestVMHostsFiltersZombiesAndForeignParents(t *testing.T) {
	t.Parallel()

	const serverPID = 840
	const running = int8(2) // SRUN

	tests := []struct {
		name  string
		procs []unix.KinfoProc
		pid   int
		want  int
	}{
		{"an empty table", nil, serverPID, 0},
		{
			name:  "two live hosts under this server",
			procs: []unix.KinfoProc{proc(vmHostComm, running, serverPID), proc(vmHostComm, running, serverPID)},
			pid:   serverPID, want: 2,
		},
		{
			name:  "a zombie host does not count",
			procs: []unix.KinfoProc{proc(vmHostComm, running, serverPID), proc(vmHostComm, procStatZombie, serverPID)},
			pid:   serverPID, want: 1,
		},
		{
			name:  "a host under a different parent does not count",
			procs: []unix.KinfoProc{proc(vmHostComm, running, serverPID), proc(vmHostComm, running, 999)},
			pid:   serverPID, want: 1,
		},
		{
			name:  "an unrelated process does not count",
			procs: []unix.KinfoProc{proc("kube-apiserver", running, serverPID), proc("k3sm", running, serverPID)},
			pid:   serverPID, want: 0,
		},
		{
			name:  "a name that merely starts the same does not count",
			procs: []unix.KinfoProc{proc("k3sm-vmhostess", running, serverPID)},
			pid:   serverPID, want: 0,
		},
		{
			name:  "no server pid means nothing is attributable",
			procs: []unix.KinfoProc{proc(vmHostComm, running, serverPID)},
			pid:   0, want: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := countVMHosts(tc.procs, tc.pid); got != tc.want {
				t.Fatalf("countVMHosts = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestProcTableLivenessOfSelf asserts the real probe reports this very process as
// running, and a pid that cannot exist as dead. It needs no privilege: signalling
// yourself with signal 0 is always permitted.
func TestProcTableLivenessOfSelf(t *testing.T) {
	t.Parallel()
	if got := (procTable{}).Liveness(unix.Getpid()); got != status.LivenessRunning {
		t.Errorf("Liveness(self) = %v, want running", got)
	}
	if got := (procTable{}).Liveness(0); got.Exists() {
		t.Errorf("Liveness(0) reports a process exists")
	}
}
