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

// errHostSampleUnsupported is returned by the memory and process-table samplers
// off darwin/cgo. Both read Mach and BSD interfaces that exist only on macOS, so
// there is nothing to degrade to; production runs on darwin with cgo enabled.
var errHostSampleUnsupported = errors.New("node host sampling requires darwin with cgo")

// sampleHostMemory is unsupported off darwin/cgo.
func sampleHostMemory(int64) (int64, error) { return 0, errHostSampleUnsupported }

// sampleProcessCount is unsupported off darwin/cgo.
func sampleProcessCount() (int64, error) { return 0, errHostSampleUnsupported }
