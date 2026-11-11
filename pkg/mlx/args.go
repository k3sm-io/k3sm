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

package mlx

import "strings"

// MatchArgPrefix reports which of flags the option name (the part of an
// argument before any "=") selects the way argparse would: name equals a
// flag, or name is "--" plus at least one character and a prefix of exactly
// one flag. A name that abbreviates several flags, or that is merely another
// option sharing leading letters, selects none. It is the one matcher every
// spec.runtime.args refusal in pkg/mlx and pkg/mlx/operator uses.
func MatchArgPrefix(name string, flags []string) (string, bool) {
	if !strings.HasPrefix(name, "--") || len(name) <= len("--") {
		return "", false
	}
	match, n := "", 0
	for _, flag := range flags {
		if flag == name {
			return flag, true
		}
		if strings.HasPrefix(flag, name) {
			match, n = flag, n+1
		}
	}
	if n != 1 {
		return "", false
	}
	return match, true
}
