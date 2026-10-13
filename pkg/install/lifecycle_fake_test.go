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
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
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
	// oslog is every line OSLog was handed, as "<LEVEL> <msg>".
	oslog []string
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

func (f *fakeSystem) ReadVMHostRecords(dataRoot string) ([]VMHostRecord, error) {
	f.calls = append(f.calls, "ReadVMHostRecords:"+dataRoot)
	if err := f.failures["ReadVMHostRecords"]; err != nil {
		return nil, err
	}
	return slices.Clone(f.life.vmhosts), nil
}

func (f *fakeSystem) OSLog(level slog.Level, msg string) {
	f.life.oslog = append(f.life.oslog, level.String()+" "+msg)
}
