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
	"maps"
	"math"
	"math/rand/v2"
	"testing"
)

// checkEncodeRoundTrip encodes d, and fails t unless the output fits
// maxPreFrameDroppedSize, parses, and keeps every class's total.
func checkEncodeRoundTrip(t *testing.T, d preFrameDropped) preFrameDropped {
	t.Helper()
	b := encodePreFrameDropped(d)
	if len(b) > maxPreFrameDroppedSize {
		t.Fatalf("encoded %d bytes, over %d", len(b), maxPreFrameDroppedSize)
	}
	got, err := parsePreFrameDropped(b)
	if err != nil {
		t.Fatalf("the reader refuses what the writer wrote: %v", err)
	}
	want := d.totals()
	maps.DeleteFunc(want, func(_ preFrameClass, n uint64) bool { return n == 0 }) // a zero count is no line
	if have := got.totals(); !maps.Equal(want, have) {
		t.Fatalf("per-class totals after the round trip: %v, want %v", have, want)
	}
	return got
}

// TestPreFrameDroppedEncodeFits: a file naming every uid at the uid cap
// under every class, with the longest uids and counts, would be far over
// the size bound line by line; the writer folds what does not fit into the
// others lines, so its own reader still reads it and persistence stays on.
func TestPreFrameDroppedEncodeFits(t *testing.T) {
	d := newPreFrameDropped()
	for i := range preFrameDroppedUIDs + 8 {
		u := uint32(math.MaxUint32 - i)
		for _, c := range preFrameClasses {
			d.uids[preFrameKey{c, u}] = math.MaxUint64 / 4
		}
	}
	for _, c := range preFrameClasses {
		d.others[c] = math.MaxUint64 / 4
	}
	got := checkEncodeRoundTrip(t, d)
	if len(got.uids) == 0 {
		t.Fatal("the writer named no uid at all")
	}
	for _, c := range preFrameClasses {
		if got.others[c] == 0 {
			t.Fatalf("class %s has no others line, want the folded counts in it", c)
		}
	}
}

// TestPreFrameDroppedRoundTrip: for random counts (few or many uids, each
// under one or several classes, short or long numbers, saturated totals)
// parse(encode(x)) succeeds and keeps every class's total.
func TestPreFrameDroppedRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 500 {
		d := newPreFrameDropped()
		nuids := r.IntN(3 * preFrameDroppedUIDs)
		for range nuids {
			u := r.Uint32()
			if r.IntN(2) == 0 {
				u = uint32(r.IntN(2000))
			}
			for _, c := range preFrameClasses[:1+r.IntN(len(preFrameClasses))] {
				n := r.Uint64() >> r.IntN(64)
				if r.IntN(50) == 0 {
					n = math.MaxUint64
				}
				d.uids[preFrameKey{c, u}] = n
			}
		}
		for _, c := range preFrameClasses {
			if r.IntN(3) == 0 {
				d.others[c] = r.Uint64() >> r.IntN(64)
			}
		}
		t.Run("", func(t *testing.T) {
			checkEncodeRoundTrip(t, d)
		})
	}
}
