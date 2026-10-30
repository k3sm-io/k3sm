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

import "golang.org/x/sys/unix"

// sampleMemorystatus reads macOS's own memory-pressure readings: the VM
// pressure level (kern.memorystatus_vm_pressure_level: 1 normal, 2 warning, 4
// critical) and the percent of memory it counts as free
// (kern.memorystatus_level). Both read without privilege. They are information
// only for the node budget, so a failed read yields nil and never fails the
// host sample.
func sampleMemorystatus() (vmPressureLevel, memorystatusLevel *int64) {
	if v, err := unix.SysctlUint32("kern.memorystatus_vm_pressure_level"); err == nil {
		vmPressureLevel = i64(int64(v))
	}
	if v, err := unix.SysctlUint32("kern.memorystatus_level"); err == nil {
		memorystatusLevel = i64(int64(v))
	}
	return vmPressureLevel, memorystatusLevel
}
