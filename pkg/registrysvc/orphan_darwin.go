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

package registrysvc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// procStateZombie is SZOMB from <sys/proc.h>; x/sys/unix does not export it.
const procStateZombie = 5

// listOwnProcesses lists the live processes of this process's effective uid
// with their argv (kern.proc.uid, then kern.procargs2 per pid). A process that
// exits between the two reads, or whose arguments cannot be read, is left out.
func listOwnProcesses() ([]procEntry, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.uid: %w", err)
	}
	out := make([]procEntry, 0, len(kps))
	for i := range kps {
		if p, ok := procEntryOf(&kps[i]); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// lookupOwnProcess re-reads one pid; false when it is gone, a zombie, or its
// arguments cannot be read.
func lookupOwnProcess(pid int) (procEntry, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(kp.Proc.P_pid) != pid {
		return procEntry{}, false
	}
	return procEntryOf(kp)
}

// procEntryOf reads one process's argv beside its kinfo. A zombie, launchd or a
// process whose arguments cannot be read is not an entry.
func procEntryOf(kp *unix.KinfoProc) (procEntry, bool) {
	pid := int(kp.Proc.P_pid)
	if pid <= 1 || kp.Proc.P_stat == procStateZombie {
		return procEntry{}, false
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return procEntry{}, false
	}
	argv, err := procargsArgv(raw)
	if err != nil {
		return procEntry{}, false
	}
	return procEntry{pid: pid, ppid: int(kp.Eproc.Ppid), pgid: int(kp.Eproc.Pgid), uid: int(kp.Eproc.Ucred.Uid), argv: argv}, true
}

// procargsArgv extracts argv from a kern.procargs2 buffer: a native-endian
// int32 argc, the NUL-terminated exec path, NUL padding, then argc
// NUL-terminated arguments (the environment follows and is not read).
func procargsArgv(raw []byte) ([]string, error) {
	if len(raw) < 4 {
		return nil, errors.New("kern.procargs2 is too short")
	}
	argc := int(int32(binary.NativeEndian.Uint32(raw[:4])))
	if argc < 0 {
		return nil, errors.New("kern.procargs2 carries a negative argc")
	}
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return nil, errors.New("kern.procargs2 carries no exec path")
	}
	rest = rest[end:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	argv := make([]string, 0, argc)
	for range argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, errors.New("kern.procargs2 ends inside argv")
		}
		argv = append(argv, string(rest[:end]))
		rest = rest[end+1:]
	}
	return argv, nil
}
