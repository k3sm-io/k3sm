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
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// managedServerFlags are the `k3sm server` flags ServerPlist renders ITSELF, by
// flag name with the leading dashes stripped. They are re-derived from the
// current Config on every install — the token most importantly, which is
// re-minted in lockstep with the admin kubeconfig — so carrying the on-disk
// values over would pin a stale credential into the daemon a reinstall exists to
// refresh. Every OTHER argument on the installed plist is the operator's and is
// preserved verbatim.
var managedServerFlags = map[string]bool{
	"runtime": true,
	"token":   true,
}

// installedServerArgs returns the operator-supplied `k3sm server` arguments
// carried on the server plist ALREADY INSTALLED, or nil when there is none (a
// first install).
//
// It fails the install on a plist that exists but cannot be parsed, rather than
// proceeding with an empty carry-over. Proceeding would silently re-render the
// bare template over an operator's configuration — precisely the defect this
// exists to fix, and invisible until the cluster came back single-node. The
// error names the file and the remedy, so the operator can delete it and
// reinstall deliberately.
func installedServerArgs(sys System, cfg Config) ([]string, error) {
	path := cfg.plistPath(ServerLabel)
	raw, err := sys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // first install: nothing to carry over
		}
		return nil, fmt.Errorf("install: read installed server plist %s: %w", path, err)
	}
	args, err := parseProgramArguments(raw)
	if err != nil {
		return nil, fmt.Errorf("install: cannot read the arguments of the installed server plist %s: %w (remove the file to reinstall from the stock template — doing so discards any --mesh-ip/--registry-port it carried)", path, err)
	}
	return preservedServerArgs(args), nil
}

// preservedServerArgs returns the arguments of an installed server plist that
// the next render must carry over: everything that is not install-managed, in
// its original order.
//
// The first two elements are dropped by position — they are the installed binary
// path and the `server` subcommand, both re-derived from the Config. After that
// the walk is by flag NAME rather than by index, so an operator who reordered
// the arguments (or wrote --token=… inline) still gets the same answer; a
// managed flag's separated value is consumed with it.
//
// A non-flag argument is preserved as-is. `k3sm server` takes no positional
// operands today, so in practice this only carries values through, but dropping
// an argument merely because it did not start with a dash would be the same
// silent loss in a different shape.
func preservedServerArgs(installed []string) []string {
	var out []string
	for i := 2; i < len(installed); i++ {
		name, _, inline := splitFlag(installed[i])
		if name == "" || !managedServerFlags[name] {
			out = append(out, installed[i])
			continue
		}
		if !inline {
			i++ // the managed flag's value is a separate argument
		}
	}
	return out
}

// splitFlag decomposes a command-line argument into its flag name (leading
// dashes stripped, so -mesh-ip and --mesh-ip are one name — Go's flag package
// accepts both) and its inline value. A non-flag argument yields an empty name.
func splitFlag(arg string) (name, value string, inline bool) {
	if !strings.HasPrefix(arg, "-") {
		return "", "", false
	}
	trimmed := strings.TrimLeft(arg, "-")
	if n, v, ok := strings.Cut(trimmed, "="); ok {
		return n, v, true
	}
	return trimmed, "", false
}

// flagValue returns the value of the named flag (dashes stripped) in args, in
// either spelling (--name value / --name=value), or "" when absent.
func flagValue(args []string, name string) string {
	for i, a := range args {
		n, v, inline := splitFlag(a)
		if n != name {
			continue
		}
		if inline {
			return v
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// parseProgramArguments extracts the ProgramArguments array of a launchd plist.
// It streams the XML rather than unmarshalling into a struct because a plist
// dict is a flat key/value SEQUENCE, not a mapping any Go struct shape mirrors:
// the array we want is the element that FOLLOWS the <key>ProgramArguments</key>.
//
// A plist with no such key is an error, not an empty result — a server plist
// without a ProgramArguments array is one launchd cannot run, and treating it as
// "no arguments" would quietly discard whatever it did carry.
func parseProgramArguments(plist []byte) ([]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(plist))
	var (
		key         strings.Builder
		val         strings.Builder
		inKey       bool
		inString    bool
		expectArray bool
		inArray     bool
		found       bool
		args        []string
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode plist XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			// The array must be the very next element after the key; anything else
			// means ProgramArguments maps to something that is not an array.
			if expectArray && t.Name.Local != "array" {
				expectArray = false
			}
			switch t.Name.Local {
			case "key":
				inKey = true
				key.Reset()
			case "array":
				if expectArray {
					inArray, found, expectArray = true, true, false
				}
			case "string":
				if inArray {
					inString = true
					val.Reset()
				}
			}
		case xml.CharData:
			// Character data arrives in arbitrarily many chunks (an escaped & splits
			// it), so it is accumulated and only harvested at the closing tag.
			if inKey {
				key.Write(t)
			}
			if inString {
				val.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "key":
				inKey = false
				if key.String() == "ProgramArguments" {
					expectArray = true
				}
			case "string":
				if inString {
					args = append(args, val.String())
					inString = false
				}
			case "array":
				inArray = false
			}
		}
	}
	if !found {
		return nil, errors.New("no ProgramArguments array")
	}
	return args, nil
}
