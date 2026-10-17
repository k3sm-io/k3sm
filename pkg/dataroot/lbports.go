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

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// LBPrivilegedPortsFlag is the flag naming the LoadBalancer ports below 1024
// the root network helper may bind for the svclb hoster. `k3sm server` and
// `k3sm agent` take it so it is recorded with the node's other arguments, and
// the installer renders the same value into `k3sm netd`'s argv: netd reads the
// list from its own root-owned launchd job, never from a request.
//
// It is named here, beside the record validation, because the three places
// that must agree on its grammar (the argument records, the installer that
// renders netd's job, and netd itself) all reach this package.
const LBPrivilegedPortsFlag = "lb-privileged-ports"

// DefaultLBPrivilegedPorts is the list a node takes when its arguments name
// none: the two web ports.
const DefaultLBPrivilegedPorts = "80,443"

// ParseLBPrivilegedPorts parses an --lb-privileged-ports value: a
// comma-separated list of ports from 1 to 1023, surrounding spaces ignored.
// An empty (or all-space) value is the empty list, which allows no port. The
// result is sorted and deduplicated.
func ParseLBPrivilegedPorts(value string) ([]uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var out []uint16
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		n, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("--%s: %q is not a port number", LBPrivilegedPortsFlag, field)
		}
		if n < 1 || n > 1023 {
			return nil, fmt.Errorf("--%s: port %d is out of range 1-1023 (a port of 1024 or above needs no root bind)", LBPrivilegedPortsFlag, n)
		}
		out = append(out, uint16(n))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// LastFlagValue returns the value of the LAST occurrence of the named flag
// (dashes stripped) in args, the one Go's flag package keeps, in either
// spelling (--name value / --name=value), and whether the flag is present at
// all, so an explicit empty value is told apart from none.
func LastFlagValue(args []string, name string) (string, bool) {
	value, found := "", false
	for i, a := range args {
		if recordArgFlagName(a) != name {
			continue
		}
		found = true
		if _, v, inline := strings.Cut(a, "="); inline {
			value = v
			continue
		}
		value = ""
		if i+1 < len(args) {
			value = args[i+1]
		}
	}
	return value, found
}

// CheckLBPrivilegedPortsArg refuses node daemon arguments whose
// --lb-privileged-ports the daemon or netd would refuse at start: a value
// ParseLBPrivilegedPorts refuses, or a bare flag ending args with no value
// (Go's flag package refuses that, where it is not an empty list). A bad value
// thereby fails where it is recorded or rendered, never as a root helper that
// crash-loops. Absent is fine: the default applies.
func CheckLBPrivilegedPortsArg(args []string) error {
	v, ok := LastFlagValue(args, LBPrivilegedPortsFlag)
	if !ok {
		return nil
	}
	if last := args[len(args)-1]; recordArgFlagName(last) == LBPrivilegedPortsFlag && !strings.Contains(last, "=") {
		return fmt.Errorf("--%s needs a value (an empty list is --%s=)", LBPrivilegedPortsFlag, LBPrivilegedPortsFlag)
	}
	if _, err := ParseLBPrivilegedPorts(v); err != nil {
		return err
	}
	return nil
}

// validateLBPrivilegedPorts is CheckLBPrivilegedPortsArg under a record's
// rejection sentinel.
func validateLBPrivilegedPorts(args []string, rejected error) error {
	if err := CheckLBPrivilegedPortsArg(args); err != nil {
		return fmt.Errorf("%w: %w", rejected, err)
	}
	return nil
}
