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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/apis/keystore/credential"
	"k3sm.io/k3sm/pkg/keystore/typed"
)

// crashAfterVersionWrite runs write with a crash injected once its version
// file is in place, before the pointer flip, and puts that file back, as a
// real crash would leave it: the failed write itself removes it.
func crashAfterVersionWrite(t *testing.T, s *FileStore, server, name string, write func() error) {
	t.Helper()
	var file string
	var orphan []byte
	s.step = func(step string) error {
		n, ok := strings.CutPrefix(step, "sync v")
		if !ok {
			return nil
		}
		file = "v" + n
		b, err := os.ReadFile(entryPath(server, name, file))
		if err != nil {
			t.Errorf("%s at its sync: %v", file, err)
		}
		orphan = b
		return fmt.Errorf("injected crash at %s", step)
	}
	if err := write(); err == nil {
		t.Fatal("the write succeeded through a crash")
	}
	s.step = func(string) error { return nil }
	if orphan == nil {
		t.Fatal("the crash did not fire after a version write")
	}
	writeFile(t, entryPath(server, name, file), string(orphan))
}

// mustOrphan is the orphan Orphan reports for name, the Version Adopt takes.
func mustOrphan(t *testing.T, s *FileStore, name string) Version {
	t.Helper()
	info, err := s.Orphan(context.Background(), name)
	if err != nil {
		t.Fatalf("Orphan %s: %v", name, err)
	}
	return info.Orphan
}

// sealedRefresh opens version of the oauth entry name inside the package
// and returns its refresh token, which no exported read returns.
func sealedRefresh(t *testing.T, s *FileStore, name string, version uint64) string {
	t.Helper()
	var refresh string
	err := s.read(context.Background(), name, func(e *entry, k keys, _ floor) error {
		_, val, err := e.version(k, version)
		defer clear(val)
		if err != nil {
			return err
		}
		env, err := typed.Decode(credential.KindOAuth, val)
		if err != nil {
			return err
		}
		refresh = string(env.RefreshToken)
		return nil
	})
	if err != nil {
		t.Fatalf("open %s version %d: %v", name, version, err)
	}
	return refresh
}

// TestOAuthCrashOrphanAdopted is G9's recovery: an oauth rotation that
// crashes between its version write and its pointer flip leaves the only
// copy of the new pair above the pointer. A read refuses with
// ErrOrphanVersion, a rotation refuses without unlinking it and says not to
// delete it, Orphan shows it beside the current version, and Adopt makes it
// current under the retention rule, after which the new pair reads and the
// next rotation proceeds from it.
func TestOAuthCrashOrphanAdopted(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "k", KindOAuth, oauthEnvelope("a2", "r2"))
	crashAfterVersionWrite(t, s, server, "k", func() error {
		_, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("a3", "r3"))
		return err
	})

	if _, _, err := s.CurrentCredential(ctx, "k"); !errors.Is(err, ErrOrphanVersion) {
		t.Fatalf("CurrentCredential over the orphan: %v, want ErrOrphanVersion", err)
	}
	if _, _, err := s.GetCredential(ctx, "k", 2); !errors.Is(err, ErrOrphanVersion) {
		t.Fatalf("GetCredential over the orphan: %v, want ErrOrphanVersion", err)
	}
	_, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("a4", "r4"))
	if !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrOrphanVersion) {
		t.Fatalf("RotateCredential over the orphan: %v, want ErrCorrupt and ErrOrphanVersion", err)
	}
	for _, want := range []string{
		"inspect with `k3sm keys adopt system/k`",
		"do not delete the file: it may hold the only valid refresh token",
		"a rotation crashed before its pointer flip",
		"copied back",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "remove v3") {
		t.Errorf("the oauth refusal %q says to remove the orphan", err)
	}

	info, err := s.Orphan(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if info.Current.Version != 2 || info.Orphan.Version != 3 || info.Orphan.Kind != KindOAuth || info.Current.Kind != KindOAuth ||
		info.Seq != 2 || len(info.Others) != 0 || info.Orphan.Created.IsZero() {
		t.Fatalf("Orphan = %+v, want version 3 above version 2 at sequence 2", info)
	}

	for _, v := range []uint64{2, 4} {
		if _, err := s.Adopt(ctx, "k", Version{Version: v}); !errors.Is(err, ErrVersionNotFound) {
			t.Fatalf("Adopt version %d: %v, want ErrVersionNotFound", v, err)
		}
	}
	v, err := s.Adopt(ctx, "k", info.Orphan)
	if err != nil || v.Version != 3 || v.Kind != KindOAuth {
		t.Fatalf("Adopt version 3 = %+v, %v", v, err)
	}
	cur, c := mustCredential(t, s, "k")
	if cur != v || string(c.AccessToken) != "a3" {
		t.Fatalf("current after Adopt: %+v %q, want %+v a3", cur, c.AccessToken, v)
	}
	if got := sealedRefresh(t, s, "k", 3); got != "r3" {
		t.Fatalf("the adopted refresh token is %q, want r3", got)
	}
	if got := fmt.Sprint(versionFiles(t, server, "k")); got != "[2 3]" {
		t.Fatalf("versions after Adopt %s, want [2 3]: the current version and one previous", got)
	}
	if f := floorOf(t, server)["k"]; f.Seq != 3 {
		t.Fatalf("floor after Adopt = %+v, want sequence 3", f)
	}
	if _, err := s.Orphan(ctx, "k"); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("Orphan after Adopt: %v, want ErrVersionNotFound", err)
	}
	// RotateIf from the adopted Version proceeds.
	if next, err := s.RotateIf(ctx, "k", KindOAuth, v, oauthEnvelope("a5", "r5")); err != nil || next.Version != 4 {
		t.Fatalf("RotateIf from the adopted version = %+v, %v", next, err)
	}
}

// TestOrphanReportsSealedIssuedAt: Orphan reports, for each side, the
// issuedAt sealed in a token's or an oauth pair's envelope (the access
// token's), read without returning any secret; a kind with no issuedAt
// reports the zero time.
func TestOrphanReportsSealedIssuedAt(t *testing.T) {
	ctx := context.Background()
	orphanAt := typedNow.Add(30 * time.Minute) // before the envelopes expire
	sshEnvelope := func(seed byte) typed.Envelope {
		return typed.Envelope{Credential: typed.Credential{
			Algorithm: typed.SSHAlgorithmEd25519,
			Seed:      []byte(strings.Repeat(string(rune(seed)), 32)),
		}}
	}
	for _, tc := range []struct {
		kind        Kind
		first, next typed.Envelope
		raw         bool // an opaque entry, written with Put and Rotate
		hasIssuedAt bool
	}{
		{kind: KindToken, first: tokenEnvelope("t1"), next: tokenEnvelope("t2"), hasIssuedAt: true},
		{kind: KindOAuth, first: oauthEnvelope("a1", "r1"), next: oauthEnvelope("a2", "r2"), hasIssuedAt: true},
		{kind: KindSSH, first: sshEnvelope('a'), next: sshEnvelope('b')},
		{kind: KindOpaque, raw: true},
	} {
		t.Run(tc.kind.String(), func(t *testing.T) {
			s, server := newTypedStore(t)
			if tc.raw {
				if _, err := s.Put(ctx, "k", tc.kind, []byte("o1")); err != nil {
					t.Fatal(err)
				}
			} else {
				mustPutCredential(t, s, "k", tc.kind, tc.first)
			}
			s.now = func() time.Time { return orphanAt }
			crashAfterVersionWrite(t, s, server, "k", func() error {
				if tc.raw {
					_, err := s.Rotate(ctx, "k", []byte("o2"))
					return err
				}
				_, err := s.RotateCredential(ctx, "k", tc.kind, tc.next)
				return err
			})
			info, err := s.Orphan(ctx, "k")
			if err != nil {
				t.Fatal(err)
			}
			var wantCur, wantOrphan time.Time
			if tc.hasIssuedAt {
				wantCur, wantOrphan = typedNow, orphanAt
			}
			if !info.CurrentIssuedAt.Equal(wantCur) || !info.OrphanIssuedAt.Equal(wantOrphan) ||
				info.CurrentIssuedAt.IsZero() != wantCur.IsZero() || info.OrphanIssuedAt.IsZero() != wantOrphan.IsZero() {
				t.Fatalf("Orphan issuedAt: current %v, orphan %v; want %v, %v", info.CurrentIssuedAt, info.OrphanIssuedAt, wantCur, wantOrphan)
			}
		})
	}
}

// recordingHandler is a slog.Handler that keeps every record it is given.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

// TestAdoptLogs: a successful Adopt emits one Info line naming the entry,
// the old version, the adopted version and its record digest, and never a
// value; a refused Adopt logs nothing.
func TestAdoptLogs(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	rec := &recordingHandler{}
	s.log = slog.New(rec)
	const access1, refresh1 = "MARKER-access-1-c07e", "MARKER-refresh-1-41aa"
	const access2, refresh2 = "MARKER-access-2-9b3d", "MARKER-refresh-2-e612"
	mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope(access1, refresh1))
	crashAfterVersionWrite(t, s, server, "k", func() error {
		_, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope(access2, refresh2))
		return err
	})
	if _, err := s.Adopt(ctx, "k", Version{Version: 2}); !errors.Is(err, ErrVersionStale) {
		t.Fatalf("Adopt without the inspected identity: %v, want ErrVersionStale", err)
	}
	if len(rec.records) != 0 {
		t.Fatalf("a refused Adopt logged %d lines", len(rec.records))
	}
	orphan := mustOrphan(t, s, "k")
	if _, err := s.Adopt(ctx, "k", orphan); err != nil {
		t.Fatal(err)
	}
	if len(rec.records) != 1 {
		t.Fatalf("Adopt logged %d lines, want 1", len(rec.records))
	}
	r := rec.records[0]
	if r.Level != slog.LevelInfo {
		t.Fatalf("Adopt logged at %v, want Info", r.Level)
	}
	got := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		got[a.Key] = a.Value.Resolve().String()
		return true
	})
	want := map[string]string{"entry": "k", "oldVersion": "1", "version": "2", "recordDigest": orphan.RecordDigest()}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Adopt log attrs %v, want %v", got, want)
	}
	line := r.Message + fmt.Sprint(got)
	for _, m := range []string{access1, refresh1, access2, refresh2} {
		if strings.Contains(line, m) {
			t.Fatalf("Adopt logged the value %q: %s", m, line)
		}
	}
}

// TestOrphanRefusalTellsCasesApart is G9's refusal text: a version further
// out than cur+1 cannot be a crash, so the refusal names only the
// copied-back pointer; a non-oauth orphan at cur+1 may be removed or
// adopted.
func TestOrphanRefusalTellsCasesApart(t *testing.T) {
	ctx := context.Background()
	t.Run("opaque crash", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		crashAfterVersionWrite(t, s, server, "k", func() error {
			_, err := s.Rotate(ctx, "k", []byte("two"))
			return err
		})
		_, err := s.Rotate(ctx, "k", []byte("three"))
		if !errors.Is(err, ErrOrphanVersion) || !strings.Contains(err.Error(), "remove v2") ||
			!strings.Contains(err.Error(), "k3sm keys adopt system/k") || strings.Contains(err.Error(), "refresh token") {
			t.Fatalf("opaque refusal %v: want adopt or remove v2, and no refresh-token advice", err)
		}
		// Reads of a non-oauth entry are refused too (review round 4, item 3).
		if _, val, err := s.Current(ctx, "k"); !errors.Is(err, ErrOrphanVersion) || val != nil {
			t.Fatalf("Current over the opaque orphan: %v, want ErrOrphanVersion", err)
		}
		if v, err := s.Adopt(ctx, "k", mustOrphan(t, s, "k")); err != nil || v.Version != 2 {
			t.Fatalf("Adopt the opaque orphan = %+v, %v", v, err)
		}
		mustCurrent(t, s, "k", "two")
	})
	t.Run("beyond the next version", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		saved, err := os.ReadFile(entryPath(server, "k", currentName))
		if err != nil {
			t.Fatal(err)
		}
		mustRotate(t, s, "k", "two")
		mustRotate(t, s, "k", "three")
		writeFile(t, entryPath(server, "k", currentName), string(saved))
		fl := floorOf(t, server)
		f := fl["k"]
		f.Seq = 1
		fl["k"] = f
		writeFloor(t, server, fl)
		// Only v3, further out than a crash reaches, is left above.
		remove(t, entryPath(server, "k", "v2"))
		_, err = s.Rotate(ctx, "k", []byte("four"))
		if !errors.Is(err, ErrOrphanVersion) || !strings.Contains(err.Error(), "a crashed rotation leaves only version 2") ||
			strings.Contains(err.Error(), "`k3sm keys adopt") {
			t.Fatalf("refusal over version 3 above version 1: %v", err)
		}
		if _, err := s.Adopt(ctx, "k", Version{Version: 3}); !errors.Is(err, ErrVersionNotFound) {
			t.Fatalf("Adopt version 3 over version 1: %v, want ErrVersionNotFound", err)
		}
	})
}

// TestAdoptRefuses is Adopt's refusals: no orphan, an orphan that does not
// authenticate, and two orphans (a copied-back pointer, never a crash).
func TestAdoptRefuses(t *testing.T) {
	ctx := context.Background()
	t.Run("none", func(t *testing.T) {
		s, _ := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		if _, err := s.Adopt(ctx, "k", Version{Version: 2}); !errors.Is(err, ErrVersionNotFound) {
			t.Fatalf("Adopt with no orphan: %v, want ErrVersionNotFound", err)
		}
		if _, err := s.Orphan(ctx, "k"); !errors.Is(err, ErrVersionNotFound) {
			t.Fatalf("Orphan with no orphan: %v, want ErrVersionNotFound", err)
		}
	})
	t.Run("does not authenticate", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		mustPut(t, s, "other", KindOpaque, []byte("x"))
		mustRotate(t, s, "other", "y")
		copyFile(t, entryPath(server, "other", "v2"), entryPath(server, "k", "v2"))
		if _, err := s.Adopt(ctx, "k", Version{Version: 2}); !errors.Is(err, ErrVersionNotFound) {
			t.Fatalf("Adopt another entry's version: %v, want ErrVersionNotFound", err)
		}
		mustCurrent(t, s, "k", "one")
	})
	t.Run("two orphans", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		saved, err := os.ReadFile(entryPath(server, "k", currentName))
		if err != nil {
			t.Fatal(err)
		}
		mustRotate(t, s, "k", "two")
		mustRotate(t, s, "k", "three")
		writeFile(t, entryPath(server, "k", currentName), string(saved))
		fl := floorOf(t, server)
		f := fl["k"]
		f.Seq = 1
		fl["k"] = f
		writeFloor(t, server, fl)
		info, err := s.Orphan(ctx, "k")
		if err != nil || info.Orphan.Version != 2 || fmt.Sprint(info.Others) != "[3]" {
			t.Fatalf("Orphan = %+v, %v; want 2 with 3 beyond", info, err)
		}
		if _, err := s.Adopt(ctx, "k", Version{Version: 2}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Adopt with two orphans: %v, want ErrCorrupt", err)
		}
		// A read refuses v3, further out than a crash reaches, by name.
		if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "v3") {
			t.Fatalf("Current with two orphans: %v, want ErrCorrupt naming v3", err)
		}
	})
}

// TestRewrapRefusesOrphan is G12's orphan case: Rewrap re-seals only the
// committed range, so an authenticated version above the pointer would stay
// under the retired master and be unlinked by the next rotation. The plan
// refuses it, naming the entry and the version, and changes nothing; Adopt
// then works and Rewrap proceeds.
func TestRewrapRefusesOrphan(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope("a1", "r1"))
	crashAfterVersionWrite(t, s, server, "k", func() error {
		_, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("a2", "r2"))
		return err
	})
	master := readMasterFile(t, server)
	err := s.Rewrap(ctx, rewrapKey(1))
	if !errors.Is(err, ErrOrphanVersion) || !strings.Contains(err.Error(), `entry "k"`) || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("Rewrap over an orphan: %v, want ErrOrphanVersion naming k and version 2", err)
	}
	if got := readMasterFile(t, server); string(got) != string(master) {
		t.Fatal("the refused Rewrap changed the master")
	}
	if v, err := s.Adopt(ctx, "k", mustOrphan(t, s, "k")); err != nil || v.Version != 2 {
		t.Fatalf("Adopt after the refused Rewrap = %+v, %v", v, err)
	}
	if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
		t.Fatalf("Rewrap after Adopt: %v", err)
	}
	if got := sealedRefresh(t, s, "k", 2); got != "r2" {
		t.Fatalf("refresh token after Rewrap %q, want r2", got)
	}
}

// writeFloor writes fl as the floor file: what a floor that lagged its
// pointer leaves.
func writeFloor(t *testing.T, server string, fl floor) {
	t.Helper()
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, floorPath(server), string(b))
}

// readMasterFile returns the master file's bytes.
func readMasterFile(t *testing.T, server string) []byte {
	t.Helper()
	b, err := os.ReadFile(masterPath(server, masterName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
