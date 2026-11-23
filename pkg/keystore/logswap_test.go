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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// crashAttrs is a file-attribute writer that fails its n-th call (from 0),
// standing in for a crash before that step, and applies each fchmod for
// real (the test owns every file), so a closed gate stays closed.
type crashAttrs struct {
	n, at  int
	before func(call string)
}

func (c *crashAttrs) step(call string) error {
	defer func() { c.at++ }()
	if c.before != nil {
		c.before(call)
	}
	if c.at == c.n {
		return errors.New("crash")
	}
	return nil
}

func (c *crashAttrs) Fchown(int, int, int) error { return c.step("fchown") }

func (c *crashAttrs) Fchmod(fd int, mode uint32) error {
	if err := c.step(fmt.Sprintf("fchmod %o", mode)); err != nil {
		return err
	}
	return unix.Fchmod(fd, mode)
}

func (c *crashAttrs) Fchflags(_, flags int) error { return c.step(fmt.Sprintf("fchflags %#x", flags)) }

// TestSwapRerunFromEachCrashPoint: a verb that stops at each attribute call
// of the swap (owner, mode, gate close, old flag clear, new flag, gate open)
// is finished by a rerun: the log judges, the gate is open, the marker is
// gone, and nothing the old log held is lost (the floor's key, rotate's
// line in .1).
func TestSwapRerunFromEachCrashPoint(t *testing.T) {
	for _, v := range maintVerbs {
		for n := 0; n < 6; n++ {
			t.Run(fmt.Sprintf("%s/crash before call %d", v.name, n), func(t *testing.T) {
				s, _, _ := fileLogScope(t)
				if v.log == auditLogName {
					appendLogBytes(t, s, auditLogName, []byte("old line\n"))
				}
				if err := v.run(s, &crashAttrs{n: n}); err == nil {
					t.Fatal("the crashed run reported success")
				}
				if err := v.run(s, &crashAttrs{n: -1}); err != nil {
					t.Fatalf("the rerun: %v, want it to finish", err)
				}
				assertNoMaintenanceLeft(t, s)
				if err := s.CheckLogFlags(context.Background()); err != nil {
					t.Fatalf("the check after the rerun: %v", err)
				}
				fi, err := os.Stat(filepath.Join(s.dataRoot, logsDirName))
				if err != nil || fi.Mode().Perm() != logsDirMode {
					t.Fatalf("%s after the rerun: %v, %v, want the gate open", logsDirName, fi, err)
				}
				if v.log == userFloorLogName {
					if recs := floorRecs(t, s); len(recs) == 0 {
						t.Fatal("the rebuilt floor lost the scope's key")
					}
					return
				}
				all := ""
				for k := 1; k <= auditArchives; k++ {
					b, _ := os.ReadFile(filepath.Join(s.dataRoot, logsDirName, auditArchiveName(k)))
					all += string(b)
				}
				if !strings.Contains(all, "old line\n") {
					t.Fatalf("the archives lost the old log's line: %q", all)
				}
			})
		}
	}
}

// TestSwapKeepsTailAppendedBeforeGate: lines appended to the old log after
// step 2 read it and before the gate closed are re-read at step 5 and
// kept: merged into the new floor, or appended to the new archive.
func TestSwapKeepsTailAppendedBeforeGate(t *testing.T) {
	t.Run("floor --rebuild", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		gen := entryGeneration(t, server, "token")
		line, err := floorLine("user/1001", "token", gen, 41)
		if err != nil {
			t.Fatal(err)
		}
		rec := &crashAttrs{n: -1, before: func(call string) {
			if call == "fchmod 700" {
				appendLogBytes(t, s, userFloorLogName, line)
			}
		}}
		if _, err := s.RebuildFloor(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range floorRecs(t, s) {
			if r.key.scope == "user/1001" && r.key.name == "token" && r.seq == 41 {
				found = true
			}
		}
		if !found {
			t.Fatal("the line appended before the gate closed was lost")
		}
	})
	t.Run("audit --rotate", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		rec := &crashAttrs{n: -1, before: func(call string) {
			if call == "fchmod 700" {
				appendLogBytes(t, s, auditLogName, []byte("tail line\n"))
			}
		}}
		if _, err := s.RotateAudit(context.Background(), rec, false); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(s.dataRoot, logsDirName, auditArchiveName(1)))
		if err != nil || !strings.HasSuffix(string(b), "tail line\n") {
			t.Fatalf(".1 holds %q, %v; want the tail line at its end", b, err)
		}
	})
}

// TestLogsGateClosedRefusesServer: a server that finds keystore-logs/ at
// the gate's 0700 refuses, naming the verbs to rerun.
func TestLogsGateClosedRefusesServer(t *testing.T) {
	s, _, _ := fileLogScope(t)
	if err := os.Chmod(filepath.Join(s.dataRoot, logsDirName), logsGateMode); err != nil {
		t.Fatal(err)
	}
	err := s.CheckLogFlags(context.Background())
	if !errors.Is(err, errLogUntrusted) || !strings.Contains(err.Error(), "floor --rebuild") || !strings.Contains(err.Error(), "audit --rotate") {
		t.Fatalf("the check behind a closed gate: %v, want a refusal naming the verbs", err)
	}
}

// TestLogAtOldLocationRefused: a log at the top of the data root is
// refused, naming the step to run.
func TestLogAtOldLocationRefused(t *testing.T) {
	s, _, _ := fileLogScope(t)
	if err := os.Rename(filepath.Join(s.dataRoot, logsDirName, auditLogName), filepath.Join(s.dataRoot, auditLogName)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLogFlags(context.Background()); !errors.Is(err, errLogUntrusted) || !strings.Contains(err.Error(), "sudo k3sm install") {
		t.Fatalf("the check over a log at the old location: %v", err)
	}
	if _, err := s.RotateAudit(context.Background(), &crashAttrs{n: -1}, false); !errors.Is(err, errRotateRefused) {
		t.Fatalf("rotate over a log at the old location: %v, want refused", err)
	}
}
