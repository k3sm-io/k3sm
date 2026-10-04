//go:build !darwin

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

// errHeadroomUnsupported is returned off darwin: the compressor and swap
// counters are macOS sysctls, and a zero reading would read as "no pressure".
var errHeadroomUnsupported = errors.New("memory headroom sampling requires darwin")

// sampleMemoryHeadroom is unsupported off darwin.
func sampleMemoryHeadroom() (memoryHeadroom, error) {
	return memoryHeadroom{}, errHeadroomUnsupported
}
