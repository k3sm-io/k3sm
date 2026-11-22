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
