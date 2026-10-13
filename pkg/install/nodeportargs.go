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
	"errors"
	"fmt"
	"strings"
)

// ErrNodePortAddressesWithoutDatapath is the named refusal of a non-empty
// --nodeport-addresses on a node whose datapath is off (--network none): no
// Service proxy runs there, so no NodePort is bound anywhere and the setting
// would be silently ignored. `k3sm server`, `k3sm agent` and `k3sm install`
// all refuse with it.
var ErrNodePortAddressesWithoutDatapath = errors.New("--nodeport-addresses needs the node datapath, and --network none turns it off")

// networkNone is the --network value that turns the node datapath off.
const networkNone = "none"

// CheckNodePortPosture refuses a non-empty --nodeport-addresses beside
// --network none. Both values are compared after trimming, so a
// whitespace-only setting counts as unset.
func CheckNodePortPosture(network, nodePortAddresses string) error {
	if strings.TrimSpace(network) == networkNone && strings.TrimSpace(nodePortAddresses) != "" {
		return fmt.Errorf("%w: drop --nodeport-addresses, or run the node with a network backend", ErrNodePortAddressesWithoutDatapath)
	}
	return nil
}

// checkNodePortPosture is CheckNodePortPosture over the arguments this install
// will render for its role: the carried ones with this install's
// --nodeport-addresses merged in. It runs before anything is written.
func checkNodePortPosture(sys System, cfg Config, serverArgs []string) error {
	var args []string
	if cfg.Role == RoleAgent {
		carried, err := installedAgentArgs(sys, cfg)
		if err != nil {
			return err
		}
		cfg.ExtraAgentArgs = carried
		args = cfg.resolvedExtraAgentArgs()
	} else {
		cfg.ExtraServerArgs = serverArgs
		args = cfg.resolvedExtraServerArgs()
	}
	if err := CheckNodePortPosture(flagValue(args, "network"), flagValue(args, nodePortAddressesFlag)); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// setNodePortAddressesArg applies c.NodePortAddresses to args: nil leaves them
// as carried; a value that is empty or only whitespace drops any
// --nodeport-addresses (every interface, the default); any other value,
// trimmed, replaces it.
func (c Config) setNodePortAddressesArg(args []string) []string {
	if c.NodePortAddresses == nil {
		return args
	}
	out := dropValueArg(args, nodePortAddressesFlag)
	v := strings.TrimSpace(*c.NodePortAddresses)
	if v == "" {
		return out
	}
	return append(out, "--"+nodePortAddressesFlag, v)
}
