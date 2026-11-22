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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setFloorBytes rewrites s's floor to b in place, keeping its owner: the
// test flag source stands in for SF_APPEND.
func setFloorBytes(t *testing.T, s *FileStore, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dataRoot, userFloorLogName), b, logMode); err != nil {
		t.Fatal(err)
	}
}

// A two-line burial torn at every byte offset: the generation of the torn
// line is refused, whether the tear is attributable (its key is tainted) or
// not (the floor-wide rule refuses a generation it has no line for), and a
// whole first tombstone buries its generation. While the tear is past the
// scope's space, other names keep working: a known generation is served and
// a put of another name is admitted. A tear inside the scope or at its
// space covers every name of the scope. A tear shorter than "user/" and a
// digit is unattributable: a put is refused and a known generation is still
// served.
func TestTornBurialTaintsOnlyItsKey(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	g1, g2 := guid(0x51), guid(0x52)
	l1, err := tombLine("user/1001", "gone", g1)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := tombLine("user/1001", "gone", g2)
	if err != nil {
		t.Fatal(err)
	}
	burial := append(append([]byte{'\n'}, l1...), l2...)
	base := readLog(t, s, userFloorLogName)
	tokenGen := entryGeneration(t, server, "token")
	head := len("user/1001 gone ")
	for cut := 0; cut <= len(burial); cut++ {
		setFloorBytes(t, s, append(append([]byte(nil), base...), burial[:cut]...))
		var torn []byte
		var gen [generationSize]byte
		switch {
		case cut > 1 && cut < 1+len(l1):
			torn, gen = burial[1:cut], g1
		case cut > 1+len(l1) && cut < len(burial):
			torn, gen = burial[1+len(l1):cut], g2
		}
		if cut >= 1+len(l1) {
			if _, err := ff.floor("user/1001", "gone", g1); !errors.Is(err, errFloorBuried) {
				t.Fatalf("cut %d: the whole first tombstone's generation: %v, want errFloorBuried", cut, err)
			}
		}
		if cut == len(burial) {
			if _, err := ff.floor("user/1001", "gone", g2); !errors.Is(err, errFloorBuried) {
				t.Fatalf("cut %d: the whole second tombstone's generation: %v, want errFloorBuried", cut, err)
			}
		}
		if torn == nil {
			if err := s.floorGrantRoom("user/1001", []string{"fresh"}, 0); err != nil {
				t.Fatalf("cut %d: a put over a floor with no damage: %v", cut, err)
			}
			continue
		}
		if _, err := ff.floor("user/1001", "gone", gen); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("cut %d (%q): the torn tombstone's generation: %v, want errFloorDegraded", cut, torn, err)
		}
		// A tear inside the scope or at its space covers every name of it;
		// a shorter one is unattributable.
		wholeScope := len(torn) >= len("user/1") && len(torn) <= len("user/1001 ")
		_, _, cerr := u.Current(ctx, "user/1001/token")
		seq, ferr := ff.floor("user/1001", "token", tokenGen)
		if wholeScope {
			if !errors.Is(cerr, errFloorDegraded) || !errors.Is(ferr, errFloorDegraded) {
				t.Fatalf("cut %d (%q): another name of a scope the tear covers: current %v, floor %v, want errFloorDegraded", cut, torn, cerr, ferr)
			}
		} else {
			if cerr != nil {
				t.Fatalf("cut %d (%q): current of another name's known generation: %v", cut, torn, cerr)
			}
			if ferr != nil || seq == 0 {
				t.Fatalf("cut %d (%q): the floor of another name: %d, %v", cut, torn, seq, ferr)
			}
		}
		err := s.floorGrantRoom("user/1001", []string{"fresh"}, 0)
		switch {
		case len(torn) > len("user/1001 "):
			if err != nil {
				t.Fatalf("cut %d (%q): a put of another name over an attributable tear: %v", cut, torn, err)
			}
			if err := s.floorGrantRoom("user/1001", []string{"gone"}, 0); len(torn) < head+2*generationSize && !errors.Is(err, errFloorDegraded) {
				t.Fatalf("cut %d (%q): a put of the name a tear inside its name or generation taints: %v, want errFloorDegraded", cut, torn, err)
			}
		case !errors.Is(err, errFloorDegraded):
			t.Fatalf("cut %d (%q): a put over a tear that covers the scope or is unattributable: %v, want errFloorDegraded", cut, torn, err)
		}
	}
	// One attributable tear through the whole put path: another name's put
	// succeeds.
	setFloorBytes(t, s, append(append([]byte(nil), base...), burial[:1+len(l1)+head+4]...))
	if _, err := u.Put(ctx, "user/1001/fresh", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put of another name over an attributable tear: %v", err)
	}
	if _, err := ff.floor("user/1001", "gone", g2); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("after the put closed the tear, its generation: %v, want errFloorDegraded", err)
	}
}

// A torn withdraw line taints the delivery record: across a restart a
// copied-back older record, at the floor's last whole line, is refused,
// where an exempt record was served, and the scope's entries still work.
func TestTornWithdrawLineTaintsDeliveryRecord(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	if err := u.addDelivery(ctx, testDelivery(2)); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(scopeDir(server, "1001"), deliveriesName)
	older, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(f *os.File, b []byte) (int, error) {
		n, err := f.Write(b[:len(b)-1]) // the line lands with no newline
		if err != nil {
			return n, err
		}
		return n, errors.New("injected torn floor write")
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil && !errors.Is(err, errCommitted) {
		t.Fatalf("withdraw whose floor line tears: %v", err)
	}
	fl.write = nil
	if err := os.WriteFile(rec, older, 0o600); err != nil {
		t.Fatal(err)
	}
	forgetDeliveriesSeen(s)
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	u2 := userScope(t, s2, 1001)
	if _, err := u2.Delivery(ctx, testDelivery(1).uid); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("lookup of a copied-back record over a torn withdraw line: %v, want errFloorDegraded", err)
	}
	if _, _, err := u2.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current of an entry beside the tainted delivery record: %v", err)
	}
}

// Unattributable garbage keeps the floor-wide rule: a put of any name is
// refused, a generation the floor has no line for is refused, and a known
// generation is served.
func TestUnattributableDamageKeepsFloorWideRefusal(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	for _, garbage := range []string{"\nuser/\n", "\nuser/1001 Bad\n", "\ngarbage line\n", "\nuser/1001 gone zz\n", "\nuser/1001 gone " + string(bytes.Repeat([]byte("a"), 32)) + " rX\n"} {
		base := readLog(t, s, userFloorLogName)
		appendLogBytes(t, s, userFloorLogName, []byte(garbage))
		if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%q: put over unattributable damage: %v, want errFloorDegraded", garbage, err)
		}
		if _, err := ff.floor("user/1001", "gone", guid(0x77)); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%q: an unknown generation over unattributable damage: %v, want errFloorDegraded", garbage, err)
		}
		if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
			t.Fatalf("%q: current of a known generation: %v", garbage, err)
		}
		_ = server
		setFloorBytes(t, s, base)
	}
}

// classifyFloorDamage on every prefix of a valid line for key K taints K
// once the prefix reaches into its scope's digits: as a scope prefix while
// the scope is partial, as a name prefix while the name is, as a name while
// the generation is partial, as K itself once it is whole. A prefix shorter
// than "user/" and one digit is unattributable.
func TestClassifyEveryPrefixTaintsItsKey(t *testing.T) {
	g := guid(0x3C)
	live, err := floorLine("user/1001", deliveriesFloorName, g, 1234567)
	if err != nil {
		t.Fatal(err)
	}
	tomb, err := tombLine("user/1001", "a.b", g)
	if err != nil {
		t.Fatal(err)
	}
	minScope := len("user/1")
	for _, c := range []struct {
		line []byte
		name string
	}{{live, deliveriesFloorName}, {tomb, "a.b"}} {
		scopeEnd := len("user/1001")
		head := scopeEnd + 1 + len(c.name) + 1
		key := floorKey{"user/1001", c.name, g}
		for n := 1; n < len(c.line)-1; n++ {
			p := c.line[:n]
			kind, k := classifyFloorDamage(p)
			switch {
			case n < minScope:
				if kind != taintUnattributable {
					t.Fatalf("%q: %v, want unattributable", p, kind)
				}
			case n <= scopeEnd:
				if kind != taintScopePrefix || k.scope != string(p) {
					t.Fatalf("%q: %v %+v, want a scope-prefix taint", p, kind, k)
				}
			case n < head:
				if kind != taintNamePrefix || k.scope != "user/1001" || k.name != string(p[scopeEnd+1:]) {
					t.Fatalf("%q: %v %+v, want a name-prefix taint", p, kind, k)
				}
			case n < head+2*generationSize:
				if kind != taintName || k.scope != "user/1001" || k.name != c.name {
					t.Fatalf("%q: %v %+v, want a name taint", p, kind, k)
				}
			default:
				if kind != taintGen || k != key {
					t.Fatalf("%q: %v %+v, want a generation taint", p, kind, k)
				}
			}
			if n < minScope {
				continue
			}
			var st logState
			st.taintLine(0, p)
			if !st.tainted(key) {
				t.Fatalf("%q: does not taint %+v", p, key)
			}
			if _, ok := st.unattributedAt(); ok {
				t.Fatalf("%q: counted as unattributable", p)
			}
		}
	}
}

// A partial scope or name that is the prefix of no valid one, or a scope
// prefix shorter than "user/" and one digit, is unattributable.
func TestClassifyInvalidPrefixIsUnattributable(t *testing.T) {
	for _, line := range []string{"user/", "user", "u", "user/0", "user/01", "user/99999999999", "user/1001 -a", "user/1001 a..", "user/1001 A", "user/1001 a_b", "user/1001 ..d"} {
		if kind, _ := classifyFloorDamage([]byte(line)); kind != taintUnattributable {
			t.Fatalf("%q: %v, want unattributable", line, kind)
		}
	}
	for _, line := range []string{"user/2", "user/21474", "user/2147483647", "user/1001 ", "user/1001 a-", "user/1001 a.", "user/1001 .", "user/1001 .del"} {
		if kind, _ := classifyFloorDamage([]byte(line)); kind == taintUnattributable {
			t.Fatalf("%q: unattributable, want a prefix taint", line)
		}
	}
}

// A prefix taint matches every key its prefix covers and no other: a scope
// prefix by the scope's canonical text, a name prefix by the name within
// its scope.
func TestPrefixTaintMatches(t *testing.T) {
	var st logState
	st.taintLine(0, []byte("user/100"))
	st.taintLine(10, []byte("user/2002 go"))
	for _, c := range []struct {
		scope, name string
		want        bool
	}{
		{"user/1001", "x", true}, {"user/100", "x", true}, {"user/10012", deliveriesFloorName, true},
		{"user/1010", "x", false}, {"user/2002", "gone", true}, {"user/2002", "go", true},
		{"user/2002", "token", false}, {"user/20021", "gone", false}, {"user/2002", deliveriesFloorName, false},
	} {
		if got := st.tainted(floorKey{c.scope, c.name, guid(1)}); got != c.want {
			t.Fatalf("%s %s: tainted %v, want %v", c.scope, c.name, got, c.want)
		}
		if got := st.nameTainted(c.scope, c.name); got != c.want {
			t.Fatalf("%s %s: name tainted %v, want %v", c.scope, c.name, got, c.want)
		}
	}
}

// Prefix taints share the taint set's cap: past it, a prefix line is
// unattributable damage.
func TestPrefixTaintCapped(t *testing.T) {
	var st logState
	for i := range maxTaintKeys {
		st.taintLine(int64(i), fmt.Appendf(nil, "user/1001 n%d", i))
	}
	if _, ok := st.unattributedAt(); ok {
		t.Fatal("a prefix taint under the cap counted as unattributable")
	}
	st.taintLine(1000, []byte("user/1001 zz"))
	if at, ok := st.unattributedAt(); !ok || at != 1000 {
		t.Fatalf("a prefix taint past the cap: unattributable %v at %d, want at 1000", ok, at)
	}
	if st.tainted(floorKey{"user/1001", "zz", guid(1)}) {
		t.Fatal("a prefix past the cap tainted its key")
	}
}

// A burial torn at every byte offset, cut 0 to its whole length: every cut
// that reaches into the scope's digits taints the buried name, so current
// of a known generation of it is refused, while a name that does not share
// the cut's prefix keeps working; a cut shorter than that is unattributable
// and the known generation is served.
func TestTornBurialEveryCutRefusesKnownGeneration(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	if _, err := u.Put(ctx, "user/1001/gone", KindOpaque, []byte("v")); err != nil {
		t.Fatal(err)
	}
	gen := entryGeneration(t, server, "gone")
	l1, err := tombLine("user/1001", "gone", gen)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := tombLine("user/1001", "gone", guid(0x52))
	if err != nil {
		t.Fatal(err)
	}
	burial := append(append([]byte{'\n'}, l1...), l2...)
	base := readLog(t, s, userFloorLogName)
	minScope := 1 + len("user/1")
	for cut := 0; cut <= len(burial); cut++ {
		setFloorBytes(t, s, append(append([]byte(nil), base...), burial[:cut]...))
		_, _, err := u.Current(ctx, "user/1001/gone")
		switch {
		case cut >= 1+len(l1):
			var del *userDeletedError
			if !errors.As(err, &del) {
				t.Fatalf("cut %d: current of a buried generation: %v", cut, err)
			}
			continue
		case cut < minScope:
			if err != nil {
				t.Fatalf("cut %d (%q): current of a known generation over an unattributable tear: %v", cut, burial[:cut], err)
			}
			continue
		}
		torn := string(burial[1:cut])
		if !errors.Is(err, errFloorDegraded) {
			t.Fatalf("cut %d (%q): current of a known generation of the tainted name: %v, want errFloorDegraded", cut, torn, err)
		}
		shares := strings.HasPrefix("user/1001 token ", torn) || (len(torn) <= len("user/1001 ") && strings.HasPrefix("user/1001 ", torn))
		_, _, terr := u.Current(ctx, "user/1001/token")
		if shares && !errors.Is(terr, errFloorDegraded) {
			t.Fatalf("cut %d (%q): current of a name sharing the prefix: %v, want errFloorDegraded", cut, torn, terr)
		}
		if !shares && terr != nil {
			t.Fatalf("cut %d (%q): current of a name not sharing the prefix: %v", cut, torn, terr)
		}
		_ = ff
	}
}

// A skipped line that is a partial scope, "user/10" closed by a later
// append, taints every scope it is a prefix of: user/1001's known
// generation is refused.
func TestSkippedScopePrefixTaintsItsScopes(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	appendLogBytes(t, s, userFloorLogName, []byte("\nuser/10\n"))
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current under a scope-prefix taint: %v, want errFloorDegraded", err)
	}
	if err := s.floorGrantRoom("user/2002", []string{"fresh"}, 0); err != nil {
		t.Fatalf("a put in a scope the prefix does not cover: %v", err)
	}
}
