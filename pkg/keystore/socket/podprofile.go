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
	"path/filepath"
	"slices"
	"strings"
)

// ErrPodProfileOpen is a Pod profile that does not deny the keystore
// socket: some spelling of the socket's directory is missing from its
// file or its connect deny, or an allow after that deny re-opens it.
var ErrPodProfileOpen = errors.New("the Pod profile does not deny the keystore socket")

// dataVolumeAlias is the macOS data volume's mount point: a path under a
// firmlink is also reachable through it.
const dataVolumeAlias = "/System/Volumes/Data"

// firmlinks are the root firmlinks a path under which is also spelled
// /private<path>.
var firmlinks = []string{"/var", "/tmp", "/etc"}

// socketDirForms returns every spelling of dir a Pod profile must deny: dir
// itself; its /private form when it is under a firmlink (/var, /tmp, /etc);
// and the data volume's form of the resolved one, unless that is already
// under the data volume. These are the spellings runtimed's keystore stanza
// is written in (docs/design/keystore.md § "Pod denies").
func socketDirForms(dir string) []string {
	dir = filepath.Clean(dir)
	forms := []string{dir}
	resolved := dir
	for _, fl := range firmlinks {
		if pathUnder(dir, fl) {
			resolved = "/private" + dir
			forms = append(forms, resolved)
			break
		}
	}
	if !pathUnder(resolved, dataVolumeAlias) {
		forms = append(forms, dataVolumeAlias+resolved)
	}
	return forms
}

// pathUnder reports whether p is root or below it, lexically.
func pathUnder(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// podProfileDenies are the operations the profile must deny on the
// socket's directory: every file read and write (so no Pod can stat, plant,
// unlink or replace the socket) and connect(2) to a unix socket.
var podProfileDenies = []struct {
	op string
	// unix is set for the network operation, whose filter is
	// (remote unix-socket <filter>).
	unix bool
}{
	{op: "file-read*"},
	{op: "file-write*"},
	{op: "network-outbound", unix: true},
}

// ProfileDeniesSocket reports whether profile, a rendered Pod profile,
// denies Pods the keystore socket at socketPath: for every spelling of the
// socket's directory (socketDirForms) it needs a deny of file-read*,
// file-write* and unix-socket network-outbound whose filter is a subpath at
// or above that spelling, with no allow of an overlapping operation after
// it (Seatbelt is last-match-wins). It returns nil when the profile denies
// all of them, and an error wrapping ErrPodProfileOpen naming the first
// missing operation and spelling otherwise, or when the profile does not
// parse.
//
// It reads the text the node's generator rendered, so a k3sm linked against
// a generator that does not deny the socket for this data root is caught at
// start, whatever the generator's own tests pin.
func ProfileDeniesSocket(profile, socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("%w: the socket path %q is not absolute", ErrPodProfileOpen, socketPath)
	}
	forms, err := parseSBPL(profile)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPodProfileOpen, err)
	}
	for _, dir := range socketDirForms(filepath.Dir(socketPath)) {
		for _, d := range podProfileDenies {
			if !deniedLast(forms, d.op, d.unix, dir) {
				return fmt.Errorf("%w: no %s deny covers %s with no allow after it", ErrPodProfileOpen, d.op, dir)
			}
		}
	}
	return nil
}

// deniedLast reports whether a top-level deny of op covers dir and no
// top-level allow after the last such deny names an operation overlapping
// op.
func deniedLast(forms []sexp, op string, unix bool, dir string) bool {
	last := -1
	for i, f := range forms {
		head, ops, filters := f.rule()
		if head == "deny" && slices.Contains(ops, op) && slices.ContainsFunc(filters, func(fl sexp) bool { return covers(fl, unix, dir) }) {
			last = i
		}
	}
	if last < 0 {
		return false
	}
	for _, f := range forms[last+1:] {
		head, ops, _ := f.rule()
		if head == "allow" && slices.ContainsFunc(ops, func(a string) bool { return opsOverlap(a, op) }) {
			return false
		}
	}
	return true
}

// covers reports whether filter is (subpath P), or with unix set
// (remote unix-socket (subpath P)), for a P at or above dir.
func covers(filter sexp, unix bool, dir string) bool {
	if unix {
		if len(filter.list) != 3 || filter.list[0].atom != "remote" || filter.list[1].atom != "unix-socket" {
			return false
		}
		filter = filter.list[2]
	}
	if len(filter.list) != 2 || filter.list[0].atom != "subpath" || !filter.list[1].str {
		return false
	}
	return pathUnder(dir, filter.list[1].atom)
}

// opsOverlap reports whether an allow of a can re-open a deny of d: the
// same operation, "default", or one operation a wildcard family of the
// other (file-read-data under file-read*, file* over file-write*).
func opsOverlap(a, d string) bool {
	if a == d || a == "default" {
		return true
	}
	fam := func(s string) (string, bool) { return strings.CutSuffix(s, "*") }
	if af, ok := fam(a); ok && strings.HasPrefix(d, af) {
		return true
	}
	if df, ok := fam(d); ok && strings.HasPrefix(a, df) {
		return true
	}
	return false
}

// sexp is one SBPL form: an atom (a symbol, or a string when str is set,
// its quotes removed) or a list.
type sexp struct {
	atom   string
	str    bool
	list   []sexp
	isList bool
}

// rule splits a top-level (allow|deny op... filter...) into its head, its
// operation symbols and its filter lists. Anything else has an empty head.
func (s sexp) rule() (head string, ops []string, filters []sexp) {
	if !s.isList || len(s.list) == 0 || s.list[0].isList || s.list[0].str {
		return "", nil, nil
	}
	head = s.list[0].atom
	if head != "allow" && head != "deny" {
		return "", nil, nil
	}
	for _, e := range s.list[1:] {
		switch {
		case e.isList:
			filters = append(filters, e)
		case !e.str:
			ops = append(ops, e.atom)
		}
	}
	return head, ops, filters
}

// parseSBPL reads text as a sequence of top-level SBPL forms. It knows
// lists, symbols, "strings" and #"regex" literals (a backslash escapes the
// next character in both) and ; comments; it is a reader for profiles this
// binary rendered, not a validator of SBPL.
func parseSBPL(text string) ([]sexp, error) {
	p := &sbplReader{s: text}
	var forms []sexp
	for {
		p.skip()
		if p.i >= len(p.s) {
			return forms, nil
		}
		f, err := p.form()
		if err != nil {
			return nil, err
		}
		forms = append(forms, f)
	}
}

type sbplReader struct {
	s string
	i int
}

// skip passes whitespace and comments.
func (p *sbplReader) skip() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == ';':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *sbplReader) form() (sexp, error) {
	switch {
	case p.s[p.i] == '(':
		p.i++
		l := sexp{isList: true}
		for {
			p.skip()
			if p.i >= len(p.s) {
				return sexp{}, errors.New("the profile ends inside a list")
			}
			if p.s[p.i] == ')' {
				p.i++
				return l, nil
			}
			e, err := p.form()
			if err != nil {
				return sexp{}, err
			}
			l.list = append(l.list, e)
		}
	case p.s[p.i] == ')':
		return sexp{}, fmt.Errorf("an unbalanced ) at byte %d", p.i)
	case p.s[p.i] == '"' || strings.HasPrefix(p.s[p.i:], `#"`):
		if p.s[p.i] == '#' {
			p.i++
		}
		p.i++
		var b strings.Builder
		for p.i < len(p.s) {
			c := p.s[p.i]
			switch {
			case c == '\\' && p.i+1 < len(p.s):
				b.WriteByte(c)
				b.WriteByte(p.s[p.i+1])
				p.i += 2
			case c == '"':
				p.i++
				return sexp{atom: b.String(), str: true}, nil
			default:
				b.WriteByte(c)
				p.i++
			}
		}
		return sexp{}, errors.New("the profile ends inside a string")
	default:
		start := p.i
		for p.i < len(p.s) && !strings.ContainsRune(" \t\r\n();\"", rune(p.s[p.i])) {
			p.i++
		}
		return sexp{atom: p.s[start:p.i]}, nil
	}
}
