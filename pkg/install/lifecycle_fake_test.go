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

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"sync"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
)

// fakeLifecycle is the fake's model of the stop marker, the runtime's vm
// helper records and the unified log. The zero value is a node that was never
// stopped and runs no vm pod.
type fakeLifecycle struct {
	// markers is the stop marker content by path.
	markers map[string][]byte
	// vmhosts is what ReadVMHostRecords answers.
	vmhosts []VMHostRecord
	// disableIgnored are labels whose LaunchctlDisable succeeds and changes
	// nothing: the read-back then says enabled.
	disableIgnored map[string]bool
	// vmRejected are record files ReadVMHostRecords refused to trust.
	vmRejected []string
	// shorten is what ShortenVMHostStop answers, by pgid; a pgid with no
	// entry answers as a helper that predates the request (unsupported).
	shorten map[int]sandbox.VMHostShortenOutcome
	// shortenRendezvous, when > 0, makes every ShortenVMHostStop wait until
	// that many requests are in flight at once (or fail after 2s): a stop that
	// sent its requests one after another never gets there.
	shortenRendezvous int
	shortenArrived    int
	shortenAll        chan struct{}
	// shortenMu guards the fields above and f.calls for the requests, which
	// the teardown sends concurrently.
	shortenMu sync.Mutex
	// procs is what ProcessExecutable answers, by pid.
	procs map[int]fakeProc
	// oslog is every line OSLog was handed, as "<LEVEL> <msg>".
	oslog []string
}

// fakeProc is one process's executable and effective uid.
type fakeProc struct {
	exe string
	uid uint32
}

// putStopMarker seeds a stop marker in phase, as an earlier stop wrote it.
func (f *fakeSystem) putStopMarker(path string, phase StopPhase) {
	data, err := json.Marshal(StopMarker{Version: stopMarkerVersion, Phase: phase, Actor: ActorUser, Reason: "seeded"})
	if err != nil {
		panic(err)
	}
	if f.life.markers == nil {
		f.life.markers = map[string][]byte{}
	}
	f.life.markers[path] = data
}

// stopMarker returns the marker at path and whether there is one.
func (f *fakeSystem) stopMarker(path string) (StopMarker, bool) {
	raw, ok := f.life.markers[path]
	if !ok {
		return StopMarker{}, false
	}
	var m StopMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	return m, true
}

// failOn makes the seam call recorded as call fail with err.
func (f *fakeSystem) failOn(call string, err error) {
	if f.failures == nil {
		f.failures = map[string]error{}
	}
	f.failures[call] = err
}

func (f *fakeSystem) LaunchctlDisable(label string) error {
	call := "Disable:" + label
	f.calls = append(f.calls, call)
	if err := f.failures[call]; err != nil {
		return err
	}
	if f.life.disableIgnored[label] {
		return nil
	}
	if f.disabled == nil {
		f.disabled = map[string]bool{}
	}
	f.disabled[label] = true
	return nil
}

func (f *fakeSystem) LaunchctlDisabled(label string) (bool, error) {
	call := "Disabled:" + label
	f.calls = append(f.calls, call)
	if err := f.failures[call]; err != nil {
		return false, err
	}
	return f.disabled[label], nil
}

// ReadStopMarker is not recorded in calls: every install, restart and
// uninstall reads it, and the call sequences other tests pin predate it. Its
// effect is what the lifecycle tests assert.
func (f *fakeSystem) ReadStopMarker(path string) ([]byte, error) {
	if raw, ok := f.life.markers[path]; ok {
		return slices.Clone(raw), nil
	}
	return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

// WriteStopMarker records "WriteStopMarker:<phase>" (the phase read out of
// the bytes), which is also its failures key.
func (f *fakeSystem) WriteStopMarker(path string, data []byte) error {
	var m StopMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("fake: marker is not JSON: %w", err)
	}
	call := "WriteStopMarker:" + string(m.Phase)
	f.calls = append(f.calls, call)
	if err := f.failures[call]; err != nil {
		return err
	}
	if f.life.markers == nil {
		f.life.markers = map[string][]byte{}
	}
	f.life.markers[path] = slices.Clone(data)
	return nil
}

func (f *fakeSystem) RemoveStopMarker(path string) error {
	f.calls = append(f.calls, "RemoveStopMarker")
	if err := f.failures["RemoveStopMarker"]; err != nil {
		return err
	}
	delete(f.life.markers, path)
	return nil
}

// ShortenVMHostStop is the fake control socket: it records the request and
// answers from f.life.shorten, or with the error failOn set for its call.
func (f *fakeSystem) ShortenVMHostStop(_ context.Context, socket string, pid int, bound time.Duration) (sandbox.VMHostShortenOutcome, error) {
	call := fmt.Sprintf("Shorten:%d:%s:%s", pid, socket, bound)
	l := &f.life
	l.shortenMu.Lock()
	f.calls = append(f.calls, call)
	err := f.failures[call]
	out, ok := l.shorten[pid]
	var all chan struct{}
	if l.shortenRendezvous > 0 {
		if l.shortenAll == nil {
			l.shortenAll = make(chan struct{})
		}
		l.shortenArrived++
		all = l.shortenAll
		if l.shortenArrived == l.shortenRendezvous {
			close(all)
		}
	}
	l.shortenMu.Unlock()
	if all != nil {
		select {
		case <-all:
		case <-time.After(2 * time.Second):
			return sandbox.VMHostShortenOutcome{}, fmt.Errorf("fake: request for %d waited alone; the requests were not concurrent", pid)
		}
	}
	if err != nil {
		return sandbox.VMHostShortenOutcome{}, err
	}
	if ok {
		return out, nil
	}
	return sandbox.VMHostShortenOutcome{Reason: "the helper answered with its banner only"}, nil
}

func (f *fakeSystem) ReadVMHostRecords(dataRoot string, owners []uint32) (VMHostStore, error) {
	f.calls = append(f.calls, "ReadVMHostRecords:"+dataRoot)
	if err := f.failures["ReadVMHostRecords"]; err != nil {
		return VMHostStore{}, err
	}
	if !slices.Contains(owners, fakeServiceUID) {
		return VMHostStore{}, fmt.Errorf("fake: owners %v do not include the service uid", owners)
	}
	return VMHostStore{Records: slices.Clone(f.life.vmhosts), Rejected: slices.Clone(f.life.vmRejected)}, nil
}

// fakeServiceUID is the uid the fake's service user has (the purge fake's).
const fakeServiceUID = 271

// ServiceUID is a directory lookup, not recorded in calls.
func (f *fakeSystem) ServiceUID(string) (uint32, error) { return fakeServiceUID, nil }

// ProcessExecutable answers from life.procs and is not recorded in calls. A
// pid with no entry cannot be read.
func (f *fakeSystem) ProcessExecutable(pid int) (string, uint32, error) {
	p, ok := f.life.procs[pid]
	if !ok {
		return "", 0, fmt.Errorf("fake: no process %d", pid)
	}
	return p.exe, p.uid, nil
}

func (f *fakeSystem) OSLog(level slog.Level, msg string) {
	f.life.oslog = append(f.life.oslog, level.String()+" "+msg)
}
