//go:build !(darwin && cgo)

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

import "errors"

// errHostCPUUnavailable is returned by the CPU sampler off darwin/cgo. Without the
// Mach host_statistics shim there is no node CPU counter, so the node publishes no
// CPU or memory rows (the pair is joint), matching the CGO=0 posture of the other
// cgo-backed probes.
var errHostCPUUnavailable = errors.New("node cpu sampling unavailable: requires darwin with cgo")

// readHostCPUTicks is unavailable off darwin/cgo.
func readHostCPUTicks() (cpuTicks, error) { return cpuTicks{}, errHostCPUUnavailable }

// hostCPUSupported reports whether this build reads the host CPU counters.
const hostCPUSupported = false
