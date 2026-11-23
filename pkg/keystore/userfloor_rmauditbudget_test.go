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
	"strings"
	"testing"
	"time"
)

// A burial whose revocation budget left over is just below the burial plus
// its audit line, in the floor and in the audit log, either is refused
// before anything is written or lands with its audit line: never a burial
// without its audit line.
func TestRmBurialNeverLosesItsAuditLine(t *testing.T) {
	for _, tightAudit := range []bool{false, true} {
		t.Run(fmt.Sprintf("tight audit %v", tightAudit), func(t *testing.T) {
			s, _, u := fileLogScope(t)
			// The longest name, so the burial is the worst case, 1,891
			// bytes, and the budget left over, under 2,276, is the window
			// where the floor holds the burial and less than an audit line.
			name := strings.Repeat("n", maxNameLen)
			userPut(t, u, "user/1001/"+name, "a value")
			var gens []byte
			for i := range maxBurialTombstones - 1 {
				line, err := floorLine("user/1001", name, guid(byte(0x40+i)), 1)
				if err != nil {
					t.Fatal(err)
				}
				gens = append(gens, line...)
			}
			appendLogBytes(t, s, userFloorLogName, gens)
			s.logSoftCap = int64(max(len(readLog(t, s, userFloorLogName)), len(readLog(t, s, auditLogName))))
			s.logHardCap = s.logSoftCap
			s.logRevokeBudget = minLogRevokeBudget
			// The burial: maxBurialTombstones tombstones and its newline.
			tomb, err := tombLine("user/1001", name, guid(0x40))
			if err != nil {
				t.Fatal(err)
			}
			burial := int64(maxBurialTombstones*len(tomb) + 1)
			// Spend the floor's budget down to the burial plus less than an
			// audit line, with lines of uid 1001 past the hard cap.
			var pad []byte
			for i := 0; int64(len(pad)) < minLogRevokeBudget-burial-int64(maxRmAuditLineBytes)/2; i++ {
				line, err := floorLine("user/1001", fmt.Sprintf("pad%d", i), guid(0x11), 1)
				if err != nil {
					t.Fatal(err)
				}
				pad = append(pad, line...)
			}
			appendLogBytes(t, s, userFloorLogName, pad)
			if tightAudit {
				var a []byte
				for int64(len(a)) < int64(len(pad)) {
					line, err := marshalAuditLine(auditLine{op: "put", scope: "user/1001", name: "pad", result: "ok"}, time.Unix(1_800_000_000, 0))
					if err != nil {
						t.Fatal(err)
					}
					a = append(a, line...)
				}
				appendLogBytes(t, s, auditLogName, a)
			}
			floorBefore, auditBefore := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
			err = u.Delete(context.Background(), "user/1001/"+name)
			floorAfter, auditAfter := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
			buried := bytes.Contains(floorAfter[len(floorBefore):], []byte(" rm "))
			audited := false
			for _, l := range bytes.Split(auditAfter[len(auditBefore):], []byte{'\n'}) {
				if r, err := parseAuditLine(l); err == nil && r.Op == "rm" && (r.Result == auditResultOK || r.Result == auditResultCommitted) {
					audited = true
				}
			}
			switch {
			case err != nil && !errors.Is(err, errCommitted):
				// A refusal is audited as one; nothing was buried.
				if buried || audited {
					t.Fatalf("the refused rm (%v) wrote: tombstones %v, a committed audit line %v", err, buried, audited)
				}
			case !buried || !audited:
				t.Fatalf("rm (%v): buried %v, audited %v; want both", err, buried, audited)
			}
			if err != nil && !errors.Is(err, errCommitted) {
				t.Fatalf("rm with the worst-case burial inside the budget: %v, want it buried and audited", err)
			}
		})
	}
}
