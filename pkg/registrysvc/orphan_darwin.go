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
	for _, kp := range kps {
		pid := int(kp.Proc.P_pid)
		if pid <= 1 || kp.Proc.P_stat == procStateZombie {
			continue
		}
		raw, err := unix.SysctlRaw("kern.procargs2", pid)
		if err != nil {
			continue
		}
		argv, err := procargsArgv(raw)
		if err != nil {
			continue
		}
		out = append(out, procEntry{pid: pid, ppid: int(kp.Eproc.Ppid), pgid: int(kp.Eproc.Pgid), argv: argv})
	}
	return out, nil
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
