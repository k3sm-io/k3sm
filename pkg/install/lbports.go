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
	"fmt"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
)

// netdLBPrivilegedPorts is the --lb-privileged-ports value netd's plist
// carries: the one the node daemon's own arguments for this Role name, else
// dataroot.DefaultLBPrivilegedPorts. It is always rendered, because netd's own
// default is the empty list: a netd job written before the flag existed
// allows no port.
func (c Config) netdLBPrivilegedPorts() string {
	args := c.resolvedExtraServerArgs()
	if c.Role == RoleAgent {
		args = c.resolvedExtraAgentArgs()
	}
	if v, ok := dataroot.LastFlagValue(args, dataroot.LBPrivilegedPortsFlag); ok {
		return strings.TrimSpace(v)
	}
	return dataroot.DefaultLBPrivilegedPorts
}

// checkNetdLBPrivilegedPorts refuses to render a netd job from a list netd
// would refuse at start: the bad value fails the install, where the operator
// is looking, instead of leaving the root helper crash-looping.
func (c Config) checkNetdLBPrivilegedPorts() error {
	args := c.resolvedExtraServerArgs()
	if c.Role == RoleAgent {
		args = c.resolvedExtraAgentArgs()
	}
	if err := dataroot.CheckLBPrivilegedPortsArg(args); err != nil {
		return fmt.Errorf("install: render the netd job: %w. Nothing has been written for it", err)
	}
	if _, err := dataroot.ParseLBPrivilegedPorts(c.netdLBPrivilegedPorts()); err != nil {
		return fmt.Errorf("install: render the netd job: %w. Nothing has been written for it", err)
	}
	return nil
}
