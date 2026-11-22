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
	"os"
	"path/filepath"
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
// whole first tombstone buries its generation. While the tear is
// attributable, other names keep working: a known generation is served and a
// put of another name is admitted. While it is not, a put is refused and a
// known generation is still served.
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
		if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
			t.Fatalf("cut %d (%q): current of another name's known generation: %v", cut, torn, err)
		}
		if seq, err := ff.floor("user/1001", "token", tokenGen); err != nil || seq == 0 {
			t.Fatalf("cut %d (%q): the floor of another name: %d, %v", cut, torn, seq, err)
		}
		err := s.floorGrantRoom("user/1001", []string{"fresh"}, 0)
		if len(torn) >= head {
			if err != nil {
				t.Fatalf("cut %d (%q): a put of another name over an attributable tear: %v", cut, torn, err)
			}
			if err := s.floorGrantRoom("user/1001", []string{"gone"}, 0); len(torn) < head+2*generationSize && !errors.Is(err, errFloorDegraded) {
				t.Fatalf("cut %d (%q): a put of the name a tear inside its generation taints: %v, want errFloorDegraded", cut, torn, err)
			}
		} else if !errors.Is(err, errFloorDegraded) {
			t.Fatalf("cut %d (%q): a put over an unattributable tear: %v, want errFloorDegraded", cut, torn, err)
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
	for _, garbage := range []string{"\nuser/10\n", "\ngarbage line\n", "\nuser/1001 gone zz\n", "\nuser/1001 gone " + string(bytes.Repeat([]byte("a"), 32)) + " rX\n"} {
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
// once the prefix holds K's scope and name and their spaces: as a name
// while the generation is partial, as K itself once it is whole.
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
	for _, c := range []struct {
		line []byte
		name string
	}{{live, deliveriesFloorName}, {tomb, "a.b"}} {
		head := len("user/1001 ") + len(c.name) + 1
		for n := 1; n < len(c.line)-1; n++ {
			kind, k := classifyFloorDamage(c.line[:n])
			switch {
			case n < head:
				if kind != taintUnattributable {
					t.Fatalf("%q: %v, want unattributable", c.line[:n], kind)
				}
			case n < head+2*generationSize:
				if kind != taintName || k.scope != "user/1001" || k.name != c.name {
					t.Fatalf("%q: %v %+v, want a name taint", c.line[:n], kind, k)
				}
			default:
				if kind != taintGen || k != (floorKey{"user/1001", c.name, g}) {
					t.Fatalf("%q: %v %+v, want a generation taint", c.line[:n], kind, k)
				}
			}
		}
	}
}
