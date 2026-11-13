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
	"io/fs"
	"strings"
	"testing"
)

// TestShellQuoteGolden pins shellQuote's bytes as literals, so the remedy
// tables below are checked against a fixed spelling rather than against the
// function they test.
func TestShellQuoteGolden(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "plain", `'plain'`},
		{"embedded single quote", "it's", `'it'\''s'`},
		{"newline", "a\nb", "'a\nb'"},
		{"leading dash", "-rf", `'-rf'`},
		{"empty string", "", `''`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shellQuote(tc.in); got != tc.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// remedyPath is the hostile path every remedy below is fed: a leading dash an
// unquoted operand would read as an option, a space that would split it, and a
// single quote. remedyQuoted is its shell-quoted spelling, written out by hand.
const (
	remedyPath   = "-k3sm data/it's here"
	remedyQuoted = `'-k3sm data/it'\''s here'`
)

// TestRemediesQuoteTheirPaths pins that a remedy printing a command pastes
// back as ONE argument, after `--` wherever the tool accepts it: a path with a
// space would split into two operands, and one with a leading dash would be
// read as an option. The expected commands are literals.
func TestRemediesQuoteTheirPaths(t *testing.T) {
	const q = remedyQuoted
	if !strings.HasPrefix(DeveloperModeMarkerPath, "/") {
		t.Errorf("DeveloperModeMarkerPath = %q, want an absolute path (the chmod -N row has no `--`)", DeveloperModeMarkerPath)
	}
	cases := []struct {
		name   string
		remedy func(t *testing.T) string
		want   []string
		// prose, when set, says why the remedy also names the path raw in its
		// diagnosis sentence, so the raw-copy check is skipped for the row.
		prose string
	}{
		{"stuck developer-mode marker", func(t *testing.T) string {
			return stuckMarkerRemedy(remedyPath)
		}, []string{
			"`sudo chflags -- nouchg " + q + "`",
			"`sudo rm -- " + q + "`",
			"`ls -lO@e -- " + q + "`",
			"`sudo chflags -- noschg " + q + "`",
			// No `--` here: macOS chmod reads a `--` after -N as a file name
			// (verified on a Mac: `chmod -N -- f` fails with "Failed to clear
			// ACL on file --"). The operand is the absolute constant
			// DeveloperModeMarkerPath, so it cannot be read as an option.
			"`sudo chmod -N " + q + "`",
		}, ""},
		{"unreadable agent arguments record", func(t *testing.T) string {
			f := newFakeSystem(t)
			f.putFile(remedyPath, []byte("not json"))
			_, err := recordedAgentArgs(f, Config{AgentArgsRecord: remedyPath})
			if err == nil {
				t.Fatal("recordedAgentArgs read an unparseable record")
			}
			return err.Error()
		}, []string{"`sudo rm -- " + q + "`"},
			"the diagnosis sentence names the path raw before the quoted command"},
		{"unreadable server arguments record", func(t *testing.T) string {
			f := newFakeSystem(t)
			f.putFile(remedyPath, []byte("not json"))
			_, err := recordedServerArgs(f, Config{ServerArgsRecord: remedyPath})
			if err == nil {
				t.Fatal("recordedServerArgs read an unparseable record")
			}
			return err.Error()
		}, []string{"`sudo rm -- " + q + "`"},
			"the diagnosis sentence names the path raw before the quoted command"},
		{"unreadable server plist with an unreadable record", func(t *testing.T) string {
			f := newFakeSystem(t)
			f.putFile(remedyPath, []byte("not json"))
			return unreadablePlistError(f, Config{ServerArgsRecord: remedyPath}, "/Library/LaunchDaemons/io.k3sm.server.plist", errors.New("EIO")).Error()
		}, []string{"`sudo rm -- " + q + "`"},
			"the diagnosis sentence names the path raw before the quoted command"},
		{"join token file readable by others", func(t *testing.T) string {
			f := newFakeSystem(t)
			f.putFile(remedyPath, []byte("K10abc::node:secret"))
			if f.modes == nil {
				f.modes = map[string]fs.FileMode{}
			}
			f.modes[remedyPath] = 0o644
			_, _, err := operatorJoinToken(f, Config{TokenFile: remedyPath})
			if err == nil {
				t.Fatal("operatorJoinToken accepted a group- and world-readable token file")
			}
			return err.Error()
		}, []string{"`chmod -- 600 " + q + "`"},
			"the diagnosis sentence names the path raw before the quoted command"},
		{"link directory owned by another account", func(t *testing.T) string {
			err := linkDirVerdict(remedyPath, "", linkDirFacts{UID: 501, Mode: 0o755 | fs.ModeDir, IsDir: true}, 0)
			if err == nil {
				t.Fatal("linkDirVerdict accepted a directory owned by uid 501")
			}
			return err.Error()
		}, []string{"sudo chown -- root:wheel " + q + " && sudo chmod -- 755 " + q},
			"the diagnosis sentence names the path raw before the quoted command"},
		{"absent launcher directory", func(t *testing.T) string {
			err := linkDirVerdict("/usr/local", remedyPath, linkDirFacts{Absent: true}, 0)
			if err == nil {
				t.Fatal("linkDirVerdict accepted an absent ancestor")
			}
			return err.Error()
		}, []string{"sudo mkdir -p -- " + q + " && sudo chown -- root:wheel " + q + " && sudo chmod -- 755 " + q},
			"the diagnosis sentence names the path raw before the quoted command"},
		{"first-install tree that could not be withdrawn", func(t *testing.T) string {
			f := &failingSwap{fakeSystem: newFakeSystem(t)}
			return withdrawFirstInstallTree(f, Config{InstallDir: remedyPath}, errors.New("cause")).Error()
		}, []string{"`sudo rm -rf -- " + q + "`"},
			"the diagnosis sentence names the path raw before the quoted command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.remedy(t)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("remedy %q does not carry %q", got, w)
				}
			}
			// An unquoted copy of the path must not ride along with the
			// quoted one.
			if rest := strings.ReplaceAll(got, q, ""); strings.Contains(rest, "k3sm data") {
				if tc.prose != "" {
					t.Skip(tc.prose)
				}
				t.Errorf("remedy %q carries a raw copy of the path outside %q", got, q)
			}
		})
	}
}

// TestLegacyRefusalEscapesEntryNames pins that a file name read from the
// service-user-writable agent work dir reaches the operator Go-quoted: an ESC
// or newline byte in the name must not land on the terminal raw.
func TestLegacyRefusalEscapesEntryNames(t *testing.T) {
	cfg := agentCfg(t).withDefaults()
	dir := cfg.agentWorkDir()
	name := "x\x1b[2Jy\nz"
	cases := []struct {
		name string
		seed func(f *fakeSystem)
		want string
	}{
		{"unreadable unrecognised file", func(f *fakeSystem) {
			f.putOwned(dir+"/"+name, 0, 0, 0o600, EntryRegular)
		}, `"` + dir + `/x\x1b[2Jy\nz"`},
		{"known name that is not a regular file", func(f *fakeSystem) {
			f.putOwned(dir+"/"+agentMeshKeyName, 0, 0, 0o777, EntrySymlink)
		}, `"` + dir + "/" + agentMeshKeyName + `" (`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSystem(t)
			f.putOwned(dir, legacyServiceUID, ServiceTreeGID, AgentTokenDirMode, EntryDir)
			tc.seed(f)
			err := adoptLegacyAgentFiles(f, cfg, legacyServiceUID)
			if err == nil {
				t.Fatal("adoptLegacyAgentFiles accepted the work dir")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not carry %q", err, tc.want)
			}
			if strings.ContainsAny(err.Error(), "\x1b\n\r") {
				t.Errorf("error %q carries a raw control byte", err)
			}
		})
	}
}
