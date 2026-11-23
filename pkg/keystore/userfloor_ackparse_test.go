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
	"testing"

	"golang.org/x/sys/unix"
)

// parseFloorAck reads fixed fields of canonical decimal: a negative, a
// sign, a leading zero, a nanosecond past a second, a field too few or too
// many, and a missing newline are each refused.
func TestParseFloorAckFixedFields(t *testing.T) {
	good := floorAck{ino: 7, birth: unix.Timespec{Sec: 1700000000, Nsec: 5}, watermark: 99}
	if a, err := parseFloorAck(good.encode()); err != nil || a != good {
		t.Fatalf("parseFloorAck of its own encoding: %+v, %v", a, err)
	}
	for _, in := range []string{
		floorAckTag + " 7 -1 5 99\n",
		floorAckTag + " 7 1700000000 -5 99\n",
		floorAckTag + " 7 1700000000 5 -99\n",
		floorAckTag + " -7 1700000000 5 99\n",
		floorAckTag + " +7 1700000000 5 99\n",
		floorAckTag + " 07 1700000000 5 99\n",
		floorAckTag + " 7 1700000000 1000000000 99\n",
		floorAckTag + " 7 1700000000 5\n",
		floorAckTag + " 7 1700000000 5 99 1\n",
		floorAckTag + " 7 1700000000 5 99",
		floorAckTag + " 7  1700000000 5 99\n",
		floorAckTag + " 18446744073709551616 1700000000 5 99\n",
		floorAckTag + " 7 9223372036854775808 5 99\n",
		"k3sm-user-floor-ack v2 7 1700000000 5 99\n",
	} {
		if _, err := parseFloorAck([]byte(in)); err == nil {
			t.Errorf("parseFloorAck(%q) accepted", in)
		}
	}
}

// FuzzParseFloorAck: whatever parses encodes back to the same bytes, with
// no negative field.
func FuzzParseFloorAck(f *testing.F) {
	f.Add(floorAck{ino: 7, birth: unix.Timespec{Sec: 1700000000, Nsec: 5}, watermark: 99}.encode())
	f.Add([]byte(floorAckTag + " 7 -1 5 99\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := parseFloorAck(b)
		if err != nil {
			return
		}
		if a.birth.Sec < 0 || a.birth.Nsec < 0 || a.birth.Nsec >= 1e9 || a.watermark < 0 {
			t.Fatalf("accepted %q with a negative or out-of-range field: %+v", b, a)
		}
		if !bytes.Equal(a.encode(), b) {
			t.Fatalf("accepted %q, which encodes as %q", b, a.encode())
		}
	})
}
