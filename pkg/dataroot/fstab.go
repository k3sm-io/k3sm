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

package dataroot

import "strings"

// FstabPath is the fstab(5) file Read consults. It is a var only so tests can
// point it at a fixture; production never changes it.
var FstabPath = "/etc/fstab"

// fstabEntry is the parsed shape of one fstab(5) line. Only the first two
// fields matter here: what to mount, and where.
type fstabEntry struct {
	// Spec is the device/volume specification (UUID=…, LABEL=…, a device node).
	Spec string
	// Dir is the mount point.
	Dir string
}

// parseFstab extracts the entries from fstab(5) content. Blank lines and
// comments are ignored, fields are whitespace-separated (tabs or spaces), and a
// line with fewer than two fields is skipped rather than guessed at — a
// malformed line declares nothing.
func parseFstab(data []byte) []fstabEntry {
	var out []fstabEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, fstabEntry{Spec: fields[0], Dir: fields[1]})
	}
	return out
}
