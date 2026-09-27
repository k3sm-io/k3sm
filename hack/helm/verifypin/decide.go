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
	"fmt"
	"strings"
)

// decide parses a helm .sha256sum file ("<hex>  <asset>", one line) and returns
// the published digest when it names asset and equals pin, or an error saying
// which of the two does not hold.
func decide(file, asset, pin string) (string, error) {
	fields := strings.Fields(file)
	if len(fields) != 2 {
		return "", fmt.Errorf("checksum file is not \"<sha256>  <asset>\": %q", strings.TrimSpace(file))
	}
	sum, name := fields[0], strings.TrimPrefix(fields[1], "*")
	if name != asset {
		return "", fmt.Errorf("checksum file names %q, want %q", name, asset)
	}
	if sum != pin {
		return "", fmt.Errorf("published sha256 %s for %s differs from the pin %s", sum, asset, pin)
	}
	return sum, nil
}
