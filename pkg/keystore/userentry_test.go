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

package keystore

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	keyentry "k3sm.io/apis/keystore/entry"
)

// resolverTable installs a uid resolver answering from table, recording
// every name it is asked for.
func resolverTable(t *testing.T, table map[string]uint32) *[]string {
	t.Helper()
	asked := new([]string)
	setSeam(t, &timerSeam, neverFires)
	setSeam(t, &uidResolverSeam, func(name string) (uint32, error) {
		*asked = append(*asked, name)
		uid, ok := table[name]
		if !ok {
			return 0, errors.New("no such account")
		}
		return uid, nil
	})
	return asked
}

// U10: user/<shortname>/<name> resolves through the uid resolver to the
// uid's entry, and the resolution is stated.
func TestShortNameResolvesToUID(t *testing.T) {
	asked := resolverTable(t, map[string]uint32{"alice": 501, "root": 0})
	r, err := ResolveEntry("user/alice/token")
	if err != nil {
		t.Fatal(err)
	}
	if r.Entry != (keyentry.Entry{Scope: keyentry.ScopeUser, UID: 501, Name: "token"}) || r.Entry.String() != "user/501/token" {
		t.Fatalf("user/alice/token resolved to %+v (%s)", r.Entry, r.Entry.String())
	}
	if r.Note != "resolved user/alice to user/501" {
		t.Fatalf("the resolution says %q", r.Note)
	}
	for _, in := range []string{"user/bob/token", "user/root/token", "user/alice/Token", "user/alice/"} {
		if _, err := ResolveEntry(in); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("ResolveEntry(%q): %v, want ErrInvalidName", in, err)
		}
	}
	*asked = nil
	for _, in := range []string{"user/501/token", "system/token"} {
		r, err := ResolveEntry(in)
		if err != nil || r.Note != "" || r.Entry.String() != in {
			t.Fatalf("ResolveEntry(%q): %+v, %v; want it unchanged, with no note", in, r, err)
		}
	}
	if len(*asked) != 0 {
		t.Fatalf("a qualified name asked the resolver for %q", *asked)
	}
}

// U11: the store's resolver takes the grammar from apis/keystore/entry and
// gives every shared vector's verdict, with or without short-name
// resolution in front of it.
func TestEntryGrammarVectorsResolver(t *testing.T) {
	resolverTable(t, nil) // no account resolves
	for _, v := range keyentry.Vectors() {
		e, err := ParseEntry(v.Input)
		if (err == nil) != v.Valid {
			t.Errorf("ParseEntry(%q) = %v, want valid=%v (%s)", v.Input, err, v.Valid, v.Why)
		}
		if err != nil && !errors.Is(err, ErrInvalidName) {
			t.Errorf("ParseEntry(%q): %v does not match ErrInvalidName", v.Input, err)
		}
		if err == nil && e.String() != v.Input {
			t.Errorf("ParseEntry(%q) = %s", v.Input, e.String())
		}
		r, err := ResolveEntry(v.Input)
		if (err == nil) != v.Valid {
			t.Errorf("ResolveEntry(%q) = %v, want valid=%v (%s)", v.Input, err, v.Valid, v.Why)
		}
		if err == nil && (r.Entry.String() != v.Input || r.Note != "") {
			t.Errorf("ResolveEntry(%q) = %+v", v.Input, r)
		}
	}
}

// U11: Phase A's checkName, as a fourth consumer, gives every vector whose
// scope part is valid the vector's verdict on its name part.
func TestEntryGrammarVectorsCheckName(t *testing.T) {
	n := 0
	for _, v := range keyentry.Vectors() {
		name, ok := namePart(v.Input)
		if !ok {
			continue
		}
		n++
		if got := checkName(name) == nil; got != v.Valid {
			t.Errorf("checkName(%q) of %q = %v, want %v (%s)", name, v.Input, got, v.Valid, v.Why)
		}
	}
	if n < 20 {
		t.Fatalf("only %d vectors have a valid scope part", n)
	}
}

// namePart splits a vector whose scope part is valid, system/ or user/<uid>/
// with a uid checkScope accepts, into its name part.
func namePart(s string) (string, bool) {
	if rest, ok := strings.CutPrefix(s, "system/"); ok {
		return rest, true
	}
	rest, ok := strings.CutPrefix(s, userScopePrefix)
	if !ok {
		return "", false
	}
	uid, name, ok := strings.Cut(rest, "/")
	if !ok || checkScope(userScopePrefix+uid) != nil {
		return "", false
	}
	return name, true
}

// U11: user/0 is no scope: root has no user scope.
func TestCheckScopeRefusesUserZero(t *testing.T) {
	if err := checkScope("user/0"); err == nil {
		t.Fatal("checkScope accepted user/0")
	}
	if _, err := deriveKeys(make([]byte, masterSize), "user/0"); err == nil {
		t.Fatal("deriveKeys derived keys for user/0")
	}
	s, _ := newTestStore(t)
	startScopes(t, s)
	if _, err := s.UserScope(0); err == nil {
		t.Fatal("UserScope(0) built a user scope for root")
	}
	if _, err := ParseEntry("user/0/a"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("ParseEntry(user/0/a): %v, want ErrInvalidName", err)
	}
	for _, uid := range []string{"1", "501", "4294967295"} {
		if err := checkScope(userScopePrefix + uid); err != nil {
			t.Fatalf("checkScope(user/%s): %v", uid, err)
		}
	}
}

// U11: an all-digit second segment is always a uid, even when an account of
// that name exists; it never reaches the resolver.
func TestAllDigitSegmentIsAlwaysUID(t *testing.T) {
	asked := resolverTable(t, map[string]uint32{"1000": 2000, "0501": 777})
	r, err := ResolveEntry("user/1000/a")
	if err != nil || r.Entry.UID != 1000 || r.Note != "" {
		t.Fatalf("user/1000/a resolved to %+v, %v; want uid 1000 with no note", r, err)
	}
	if _, err := ResolveEntry("user/0501/a"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("user/0501/a: %v, want ErrInvalidName (a leading zero, never a short name)", err)
	}
	if len(*asked) != 0 {
		t.Fatalf("an all-digit segment asked the resolver for %q", *asked)
	}
}

// U11: pkg/keystore imports no Kubernetes package.
func TestKeystoreIsKubernetesFree(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("find the go tool: %v", err)
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	sawGrammar := false
	for _, d := range deps {
		if strings.HasPrefix(d, "k8s.io/") || strings.HasPrefix(d, "sigs.k8s.io/") || strings.Contains(d, "client-go") {
			t.Errorf("pkg/keystore depends on %s", d)
		}
		sawGrammar = sawGrammar || d == "k3sm.io/apis/keystore/entry"
	}
	if !sawGrammar {
		t.Fatalf("go list -deps did not list the grammar package; got %d deps: %s", len(deps), strconv.Quote(string(out)))
	}
}
