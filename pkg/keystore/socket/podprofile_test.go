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

package socket

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// generatorFold is the case-folding spelling of keystore- the generator
// writes: each ASCII letter a class, k and s alternations with the
// Kelvin sign and the long s.
const generatorFold = "(K|k|\u212a)[Ee][Yy](S|s|\u017f)[Tt][Oo][Rr][Ee]-"

// rootForms are the data root's spellings for sock.
var rootForms = []string{"/var/lib/k3sm", "/private/var/lib/k3sm", "/System/Volumes/Data/private/var/lib/k3sm"}

// TestPrefixMixedCaseProbes: the mixed-case probes change two or more
// letters at once, which no single-letter folding does.
func TestPrefixMixedCaseProbes(t *testing.T) {
	if got, want := prefixMixedCase(), []string{"KEystore-", "kEyStOrE-"}; !slices.Equal(got, want) {
		t.Fatalf("prefixMixedCase = %q, want %q", got, want)
	}
}

// stanzaFor renders a keystore-style deny over dirs: a file deny and a
// unix connect deny, each with one subpath per dir and the generator's
// case-folding regex for every spelling of sock's data root.
func stanzaFor(dirs ...string) string {
	return stanzaWith(func(root string) string { return "^" + root + "/" + generatorFold }, dirs...)
}

// stanzaWith is stanzaFor with the regex for each data-root spelling
// pattern returns; "" writes none.
func stanzaWith(pattern func(root string) string, dirs ...string) string {
	var file, conn strings.Builder
	for _, root := range rootForms {
		if p := pattern(root); p != "" {
			fmt.Fprintf(&file, "  (regex #\"%s\")\n", p)
			fmt.Fprintf(&conn, "  (remote unix-socket (regex #\"%s\"))\n", p)
		}
	}
	for _, d := range dirs {
		fmt.Fprintf(&file, "  (subpath %q)\n", d)
		fmt.Fprintf(&conn, "  (remote unix-socket (subpath %q))\n", d)
	}
	return ";; KEYSTORE: a comment with a ( and a \" in it\n" +
		"(deny file-read* file-read-metadata file-test-existence file-write* file-link\n" + file.String() + "  )\n" +
		"(deny network-outbound\n" + conn.String() + "  )\n"
}

const sock = "/var/lib/k3sm/keystore-sock/keys.sock"

var allForms = []string{
	"/var/lib/k3sm/keystore-sock",
	"/private/var/lib/k3sm/keystore-sock",
	"/System/Volumes/Data/private/var/lib/k3sm/keystore-sock",
}

func TestSocketDirForms(t *testing.T) {
	for _, tt := range []struct {
		dir  string
		want []string
	}{
		{"/var/lib/k3sm/keystore-sock", allForms},
		{"/private/var/lib/k3sm/keystore-sock", allForms[1:]},
		{"/Volumes/k3sm/keystore-sock", []string{"/Volumes/k3sm/keystore-sock", "/System/Volumes/Data/Volumes/k3sm/keystore-sock"}},
		{"/System/Volumes/Data/x/keystore-sock", []string{"/System/Volumes/Data/x/keystore-sock"}},
		{"/variable/keystore-sock", []string{"/variable/keystore-sock", "/System/Volumes/Data/variable/keystore-sock"}},
	} {
		if got := socketDirForms(tt.dir); !slices.Equal(got, tt.want) {
			t.Errorf("socketDirForms(%q) = %q, want %q", tt.dir, got, tt.want)
		}
	}
}

func TestProfileDeniesSocket(t *testing.T) {
	allow := "(version 1)\n(deny default)\n(allow file-read* (subpath \"/\"))\n(allow network-outbound)\n"
	for _, tt := range []struct {
		name    string
		profile string
		open    string // "" when the profile denies the socket
	}{
		{"every spelling denied, last", allow + stanzaFor(allForms...), ""},
		{"an ancestor subpath covers it", allow + stanzaFor("/var/lib", "/private/var/lib", "/System/Volumes/Data/private/var/lib"), ""},
		{"an allow of another operation after it", allow + stanzaFor(allForms...) + "(allow process-exec (literal \"/bin/sh\"))\n", ""},
		{"no stanza", allow, "no file-read* deny covers /var/lib/k3sm/keystore-sock"},
		{"another data root", allow + stanzaFor("/Volumes/x/keystore-sock", "/System/Volumes/Data/Volumes/x/keystore-sock"), "/var/lib/k3sm/keystore-sock"},
		{"the /private spelling missing", allow + stanzaFor(allForms[0], allForms[2]), "/private/var/lib/k3sm/keystore-sock"},
		{"the data-volume spelling missing", allow + stanzaFor(allForms[:2]...), "/System/Volumes/Data/private/var/lib/k3sm/keystore-sock"},
		{"a sibling subpath only", allow + stanzaFor("/var/lib/k3sm/keystore-run", "/private/var/lib/k3sm/keystore-run", "/System/Volumes/Data/private/var/lib/k3sm/keystore-run"), "/var/lib/k3sm/keystore-sock"},
		{"no connect deny", allow + strings.SplitAfter(stanzaFor(allForms...), "  )\n")[0], "no network-outbound deny"},
		{"a file-read allow after it", allow + stanzaFor(allForms...) + "(allow file-read-data (subpath \"/var/lib/k3sm\"))\n", "no file-read* deny"},
		{"a file* allow after it", allow + stanzaFor(allForms...) + "(allow file* (subpath \"/var\"))\n", "no file-read* deny"},
		{"a connect allow after it", allow + stanzaFor(allForms...) + "(allow network* (remote unix-socket))\n", "no network-outbound deny"},
		{"an allow default after it", allow + stanzaFor(allForms...) + "(allow default)\n", "no file-read* deny"},
		{"no case-folding regex", allow + stanzaWith(func(string) string { return "" }, allForms...), "no file-read* deny carries the case-folding regex of keystore- names under /var/lib/k3sm"},
		{"a regex that does not fold", allow + stanzaWith(func(root string) string { return "^" + root + "/keystore-" }, allForms...), "case-folding regex"},
		{"a regex without the Kelvin sign", allow + stanzaWith(func(root string) string { return "^" + root + "/[Kk][Ee][Yy](S|s|\u017f)[Tt][Oo][Rr][Ee]-" }, allForms...), "case-folding regex"},
		{"a regex anchored at its end after the prefix", allow + stanzaWith(func(root string) string { return "^" + root + "/" + generatorFold + "$" }, allForms...), "case-folding regex"},
		{"an alternation of the single-letter probes alone", allow + stanzaWith(func(root string) string { return "^" + root + "/(" + strings.Join(prefixFoldings(), "|") + ")" }, allForms...), "case-folding regex"},
		{"a regex matching any name", allow + stanzaWith(func(root string) string { return "^" + root + "/" }, allForms...), "case-folding regex"},
		{"the /private regex missing", allow + stanzaWith(func(root string) string {
			if root == rootForms[1] {
				return ""
			}
			return "^" + root + "/" + generatorFold
		}, allForms...), "under /private/var/lib/k3sm"},
		{"unbalanced", allow + stanzaFor(allForms...) + "(deny", "ends inside a list"},
		{"an unterminated string", "(deny file-read* (subpath \"/var", "ends inside a string"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ProfileDeniesSocket(tt.profile, sock)
			if tt.open == "" {
				if err != nil {
					t.Fatalf("got %v, want the socket denied", err)
				}
				return
			}
			if !errors.Is(err, ErrPodProfileOpen) || !strings.Contains(err.Error(), tt.open) {
				t.Fatalf("got %v, want ErrPodProfileOpen naming %q", err, tt.open)
			}
		})
	}
	if err := ProfileDeniesSocket(allow+stanzaFor(allForms...), "keys.sock"); !errors.Is(err, ErrPodProfileOpen) {
		t.Fatalf("a relative socket path: %v", err)
	}
}
