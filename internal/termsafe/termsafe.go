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

// Package termsafe renders text that came from outside this process (the
// cluster, a file on disk) as data on an operator's terminal or log. It is the
// one implementation `k3sm status` (pkg/status) and the root-run install and
// start readers (pkg/install) share; it lives here rather than in pkg/status
// because pkg/status imports pkg/install, so the reverse import would cycle.
package termsafe

import (
	"strings"
	"unicode"

	"k3sm.io/k3sm/pkg/executor"
)

// Strip removes characters that can change what the operator sees from text
// that came from the cluster or a file on disk (apiserver errors, node names,
// records), so a hostile apiserver, proxy or file cannot put terminal escape
// sequences on the operator's TTY, reorder the line against what is copied, or
// hide text. It drops every rune for which unicode.IsControl is true (C0, DEL,
// C1), every rune in the Unicode format category Cf (the bidi embedding,
// override and isolate controls and the bidi marks, the zero-width characters,
// the soft hyphen, the interlinear annotation characters and the tag
// characters), and the line and paragraph separators U+2028 and U+2029
// (categories Zl and Zp), which some terminals break a line on. Every other
// rune is kept, including U+FFFD, which is what an invalid byte becomes. Only
// a human renderer calls it; a JSON output carries the value as data and its
// encoder already escapes controls.
func Strip(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}

// Component is a crash-loop record's component name as a human screen or log
// may show it. The record is writable by the service uid and its readers may
// run as root, so a value executor.IsComponentName refuses is data, not a name:
// the fixed word "unknown" stands in.
func Component(name string) string {
	if executor.IsComponentName(name) {
		return name
	}
	return "unknown"
}
