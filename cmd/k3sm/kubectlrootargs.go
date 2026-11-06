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
	"os"
	"strings"
)

// namedKubeconfigRemedy closes a refusal of what `sudo k3sm kubectl` was asked to
// read by flag.
const namedKubeconfigRemedy = "run `kubectl` directly without sudo to use it as it stands, or name one file whose credentials and CA are inline and that sets no proxy-url"

// rootKubectlChoice is the kubeconfig and arguments kubectl runs with as root. An
// explicit --kubeconfig wins over every other source, as it does in kubectl, and
// goes through the checks of any other file root is pointed at by name
// (rootKubeSources.loadNamed). The flag leaves the arguments: kubectl gets the
// checked bytes by the handoff and no path.
//
// A named file keeps its own CA and server name. The root-held CA and name pin are
// for the cluster this node belongs to, and a person may name a file for another
// one, as `k3s kubectl` allows. Its entries are held to the same inline list as
// every other file root reads, whichever cluster they name.
func rootKubectlChoice(in kubectlInputs, args []string) (kubectlConfig, []string, error) {
	path, rest, err := splitNamedKubeconfig(args)
	if err != nil {
		return kubectlConfig{}, nil, err
	}
	if path == "" {
		cfg, err := kubectlVerbConfig("k3sm kubectl", in)
		return cfg, args, err
	}
	c, err := in.root.loadNamedWith(path, lastContextFlag(rest), namedKubeconfigRemedy)
	if err != nil {
		return kubectlConfig{}, nil, fmt.Errorf("--kubeconfig: %w", err)
	}
	return kubectlConfig{checked: c}, rest, nil
}

// splitNamedKubeconfig returns the file args name with --kubeconfig, and args
// without that flag. kubectl takes the flag on either side of a subcommand, in
// both forms, up to the `--` that ends its flags, and does not read what follows,
// which belongs to a command run in a pod. It refuses what it cannot reduce to one
// file root can read and check. --kuberc is refused because preferences can set
// flags after this check; kubectl looks for it by substring, so this does too.
func splitNamedKubeconfig(args []string) (string, []string, error) {
	var (
		named     []string
		mayBeFlag bool
	)
	rest := make([]string, 0, len(args))
scan:
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i == 0 || !flagMayTakeNext(args[i-1]) {
				rest = append(rest, args[i:]...)
				break scan
			}
			// The flag before it may take this as its value, in which case flags
			// go on after it.
			mayBeFlag = true
			rest = append(rest, a)
		case a == "--kuberc" || strings.Contains(a, "--kuberc="):
			return "", nil, fmt.Errorf("--kuberc is not read as root, because preferences can change flags already checked, refused; %s", namedKubeconfigRemedy)
		case a == "--kubeconfig" || strings.HasPrefix(a, "--kubeconfig="):
			if mayBeFlag {
				return "", nil, fmt.Errorf("--kubeconfig follows a `--` the flag before it may take as its value, so root cannot tell whether kubectl would read it, refused; %s", namedKubeconfigRemedy)
			}
			value, inline := strings.CutPrefix(a, "--kubeconfig=")
			if !inline {
				value = ""
				if i+1 < len(args) {
					i++
					value = args[i]
				}
			}
			named = append(named, value)
		default:
			rest = append(rest, a)
		}
	}
	if len(named) == 0 {
		return "", args, nil
	}
	path := named[0]
	switch {
	case len(named) > 1:
		return "", nil, fmt.Errorf("--kubeconfig is given more than once, and root checks one file, refused; %s", namedKubeconfigRemedy)
	case path == "":
		return "", nil, fmt.Errorf("--kubeconfig names no file, refused; %s", namedKubeconfigRemedy)
	case path == "-":
		return "", nil, fmt.Errorf("--kubeconfig - would read standard input, which root does not read as a kubeconfig, refused; %s", namedKubeconfigRemedy)
	case strings.ContainsRune(path, os.PathListSeparator):
		return "", nil, fmt.Errorf("--kubeconfig %q is a list of files, and root checks one file, refused; %s", path, namedKubeconfigRemedy)
	}
	return path, rest, nil
}

// flagMayTakeNext reports whether a is a flag that may take the next argument as
// its value. Which flags do is kubectl's to say, so this assumes any flag written
// without a value might.
func flagMayTakeNext(a string) bool {
	return strings.HasPrefix(a, "-") && a != "-" && a != "--" && !strings.Contains(a, "=")
}

// lastContextFlag is the value of the last --context in args, the one kubectl
// honors, or "" for none. A wrong answer cannot widen what kubectl gets: it is
// handed one checked context, and fails on a name it does not hold.
func lastContextFlag(args []string) string {
	var name string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return name
		case a == "--context" && i+1 < len(args):
			i++
			name = args[i]
		case strings.HasPrefix(a, "--context="):
			name = strings.TrimPrefix(a, "--context=")
		}
	}
	return name
}
