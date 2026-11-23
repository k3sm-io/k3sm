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

import "testing"

// The floor's limits in tests. A test that would otherwise write a floor of
// megabytes, or plant more than maxDirNames files, lowers the limit it
// reaches to one of these and checks the same boundary there.
// TestFloorProductionLimits runs those tests at the production limits.
const (
	// smallDirNames is the sync's directory bound a test lowers
	// floorDirNamesBound to.
	smallDirNames = 256
	// smallFloorSize is the floor size a test lowers floorSizeLimit to.
	smallFloorSize = 16 << 10
	// smallTombstoneSize is the tombstone budget a test lowers
	// tombstoneSizeLimit to: a quarter of smallFloorSize, as maxTombstoneSize
	// is of maxFloorSize.
	smallTombstoneSize = 4 << 10
	// smallBuriedPerName is the per-name cap a test lowers buriedPerNameLimit
	// to.
	smallBuriedPerName = 4
)

// setFloorLimits sets the floor's size limits for the rest of t: the floor
// size, the entry count that size holds, and the tombstone budget. t must
// not run in parallel with a test that reads them.
func setFloorLimits(t *testing.T, size, tombstones int) {
	t.Helper()
	setSeam(t, &floorSizeLimit, size)
	setSeam(t, &floorEntriesLimit, size/minFloorEntrySize)
	setSeam(t, &tombstoneSizeLimit, tombstones)
}

// setSmallFloorLimits is setFloorLimits at smallFloorSize and
// smallTombstoneSize.
func setSmallFloorLimits(t *testing.T) {
	t.Helper()
	setFloorLimits(t, smallFloorSize, smallTombstoneSize)
}

// TestFloorLimitsDefault: with no test lowering them, a store reads the
// floor's limits at their production constants, so a lowered limit in one
// test never stands in for production.
func TestFloorLimitsDefault(t *testing.T) {
	newTestStore(t)
	for name, got := range map[string][2]int{
		"floorSizeLimit":     {floorSizeLimit, maxFloorSize},
		"floorEntriesLimit":  {floorEntriesLimit, maxFloorEntries},
		"tombstoneSizeLimit": {tombstoneSizeLimit, maxTombstoneSize},
		"buriedPerNameLimit": {buriedPerNameLimit, maxBuriedPerName},
		"floorDirNamesBound": {floorDirNamesBound, maxDirNames},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %d, want the production %d", name, got[0], got[1])
		}
	}
	if maxFloorEntries != maxFloorSize/minFloorEntrySize {
		t.Errorf("maxFloorEntries = %d, want maxFloorSize/minFloorEntrySize %d", maxFloorEntries, maxFloorSize/minFloorEntrySize)
	}
}
