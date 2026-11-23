//go:build !race

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

// TestFloorProductionLimits runs the tests that lower the floor's limits at
// the production limits instead: TestDeleteBuriesPastPlantedNames plants
// maxDirNames+1 names, and TestTombstoneNeverRefusesPut and
// TestPruneLogsAtWarn fill a floor of maxFloorSize and bury up to
// maxBuriedPerName generations of one name. It is built without the race
// detector only: under it, planting 131,073 files and filling a 4 MiB floor
// take minutes, and the race detector has nothing more to find at the
// production limits than at the lowered ones, which those tests check under
// it. The planted names also skip under -short, as they did before.
func TestFloorProductionLimits(t *testing.T) {
	t.Run("planted names past maxDirNames", func(t *testing.T) {
		if testing.Short() {
			t.Skip("plants over maxDirNames files")
		}
		if floorDirNamesBound != maxDirNames {
			t.Fatalf("floorDirNamesBound = %d, want maxDirNames %d", floorDirNamesBound, maxDirNames)
		}
		deleteBuriesPastPlantedNames(t)
	})
	t.Run("tombstones never refuse a Put at maxFloorSize", func(t *testing.T) {
		if floorSizeLimit != maxFloorSize || tombstoneSizeLimit != maxTombstoneSize {
			t.Fatalf("floor limits = %d, %d; want %d, %d", floorSizeLimit, tombstoneSizeLimit, maxFloorSize, maxTombstoneSize)
		}
		tombstoneNeverRefusesPut(t)
	})
	t.Run("prune logs at maxBuriedPerName and maxFloorSize", func(t *testing.T) {
		if buriedPerNameLimit != maxBuriedPerName || floorSizeLimit != maxFloorSize {
			t.Fatalf("limits = %d, %d; want %d, %d", buriedPerNameLimit, floorSizeLimit, maxBuriedPerName, maxFloorSize)
		}
		pruneLogsAtWarn(t)
	})
}
