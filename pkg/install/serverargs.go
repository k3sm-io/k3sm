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
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/version"
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

// installedServerArgs returns the operator-supplied `k3sm server` arguments the
// next render must carry over, or nil when there are none (a genuine first
// install).
//
// It has TWO sources, in this precedence:
//
//  1. the server plist ALREADY INSTALLED — authoritative, because it is what
//     launchd is running right now. This is the in-place-upgrade path and it is
//     unchanged;
//  2. the server-arguments record inside the data root, consulted only when
//     there is no plist to read.
//
// The second source exists because `k3sm uninstall` removes the plist. Before
// it, uninstall-then-install — the clean cutover the install docs recommend
// between channels — re-rendered the stock template over an operator's
// configuration, dropping --mesh-ip and --registry-port with no log line and
// bringing the cluster back single-node. The data root is preserved by the same
// uninstall, so a record kept there bridges exactly that gap.
//
// It fails the install on a plist that exists but cannot be parsed, rather than
// proceeding with an empty carry-over: proceeding would be the same silent
// re-render in a different shape. The error names the file, the remedy, and —
// when there is one — the record whose arguments a deliberate reinstall would
// then carry instead.
func installedServerArgs(sys System, cfg Config) ([]string, error) {
	path := cfg.plistPath(ServerLabel)
	raw, err := sys.ReadFile(path)
	switch {
	case err == nil:
		args, perr := parseProgramArguments(raw)
		if perr != nil {
			return nil, unreadablePlistError(sys, cfg, path, perr)
		}
		return preservedServerArgs(args), nil
	case errors.Is(err, fs.ErrNotExist):
		return recordedServerArgs(sys, cfg)
	default:
		return nil, fmt.Errorf("install: read installed server plist %s: %w", path, err)
	}
}

// OperatorServerArgs returns the operator-supplied `k3sm server` arguments an
// installed server plist carries — everything on its argv that the installer
// does not render itself, in the original order.
//
// It is exported for `k3sm status`, which reports the same answer read-only so
// an operator can see what the daemon is configured with without reading XML.
// The parse lives here rather than being re-implemented there: two readers of
// one plist would be two chances to disagree about what is preserved.
func OperatorServerArgs(plist []byte) ([]string, error) {
	args, err := parseProgramArguments(plist)
	if err != nil {
		return nil, err
	}
	return preservedServerArgs(args), nil
}

// recordedServerArgs returns the arguments the server-arguments record inside
// the data root carries, or nil when there is no record.
//
// A record that cannot be read is an ERROR, never an empty answer: the whole
// reason it exists is that "no arguments" and "the arguments could not be read"
// look identical in the rendered plist, and only one of them is safe to render.
// The remedy names the file, because deleting it is a decision (it discards the
// flags it lists) and not something an installer may take on an operator's
// behalf.
func recordedServerArgs(sys System, cfg Config) ([]string, error) {
	path := dataroot.ServerArgsRecordPath(cfg.DataRoot)
	rec, err := dataroot.ReadServerArgsRecord(systemFiles{sys}, path)
	if err != nil {
		return nil, fmt.Errorf("install: %w (`rm %s` to reinstall from the stock template, which discards the arguments it lists)", err, path)
	}
	if rec == nil {
		warnNothingCarried(cfg)
		return nil, nil
	}
	if len(rec.Args) > 0 {
		cfg.Logger.Info("carried the operator-supplied server arguments over from the recorded ones (the installed plist is gone, as after an uninstall)",
			"args", strings.Join(rec.Args, " "), "record", path, "recorded-at", rec.CreatedAt.Format(time.RFC3339), "recorded-by", rec.CreatedBy)
	}
	return rec.Args, nil
}

// warnNothingCarried says, once, that a data root with prior cluster state in it
// is being given a stock server plist.
//
// It is keyed on the DATA ROOT HAVING CONTENT, never on the record being absent:
// a Mac installed before records existed, and uninstalled since, has no record
// and never will — that is exactly the machine this warning is for, and one
// keyed on the record would stay silent on it. An empty data root is a first
// install and gets nothing to read.
func warnNothingCarried(cfg Config) {
	used, err := dataRootHasContent(cfg.DataRootFS, cfg.DataRoot)
	if err != nil || !used {
		return
	}
	cfg.Logger.Warn("no operator-supplied server arguments were carried over: neither the installed server plist nor a recorded set is on disk, so the server is being rendered from the stock template — any --mesh-ip or --registry-port this node had is NOT set",
		"data-root", cfg.DataRoot,
		"set-them", "add the flags to ProgramArguments in "+cfg.plistPath(ServerLabel)+", then `sudo launchctl kickstart -k system/"+ServerLabel+"`; the next install carries them over by itself")
}

// unreadablePlistError is the refusal for a server plist that is there and
// cannot be parsed. It names the record when one exists, because the operator's
// next move — remove the plist and reinstall — has a different outcome depending
// on whether anything is left to carry over.
func unreadablePlistError(sys System, cfg Config, path string, cause error) error {
	recPath := dataroot.ServerArgsRecordPath(cfg.DataRoot)
	if rec, err := dataroot.ReadServerArgsRecord(systemFiles{sys}, recPath); err == nil && rec != nil {
		return fmt.Errorf("install: cannot read the arguments of the installed server plist %s: %w (remove %s to reinstall; the recorded operator arguments (%s) from %s in %s will be carried over)",
			path, cause, path, strings.Join(rec.Args, " "), rec.CreatedAt.Format(time.RFC3339), recPath)
	}
	return fmt.Errorf("install: cannot read the arguments of the installed server plist %s: %w (remove the file to reinstall from the stock template — doing so discards any --mesh-ip/--registry-port it carried)", path, cause)
}

// writeServerArgsRecord records the arguments this install rendered, so the next
// one can carry them over even with no plist to read.
//
// It writes the FULL preserved set, never a distilled one: --mesh-ip and
// --registry-port are the two that made the defect visible, but the contract is
// "everything the installer does not own", and a record that kept only the
// famous two would lose the next flag an operator adds.
func writeServerArgsRecord(sys System, cfg Config) error {
	path := dataroot.ServerArgsRecordPath(cfg.DataRoot)
	rec := dataroot.ServerArgsRecord{
		Args: cfg.ExtraServerArgs,
		// "k3sm <version>", the same one-line provenance the data-volume record
		// carries. Info.String() is the multi-line `k3sm version` screen and would
		// put a paragraph in a json field.
		CreatedBy: "k3sm " + version.Get().Version,
		CreatedAt: time.Now().UTC(),
	}
	if err := sys.WriteServerArgsRecord(path, rec); err != nil {
		return fmt.Errorf("install: write the server arguments record %s: %w", path, err)
	}
	return nil
}

// systemFiles adapts the installer's privileged read seam to the one method
// pkg/dataroot's record readers need. The installer reads as root through
// System, not through a dataroot.FS, and a unit test's fake System is what makes
// the carry-over testable without privilege.
type systemFiles struct{ sys System }

// ReadFile implements dataroot.FileReader.
func (s systemFiles) ReadFile(path string) ([]byte, error) { return s.sys.ReadFile(path) }

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
