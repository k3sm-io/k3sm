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
	"testing"
)

// A torn tombstone, read while torn, then completed by a foreign writer
// whose bytes carry no leading newline into a live line that parses: the
// torn fragment's classification is frozen at its offset, so the merged
// line is damage that keeps the key tainted, and the generation the floor
// knows is still refused.
func TestForeignCompletionOfTornTailStaysTainted(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	gen := entryGeneration(t, server, "token")
	k := floorKey{"user/1001", "token", gen}
	live, err := floorLine(k.scope, k.name, k.gen, 1)
	if err != nil {
		t.Fatal(err)
	}
	cut := len("user/1001 token ") + 2*generationSize + 1 // "... <gen> "
	appendLogBytes(t, s, userFloorLogName, append([]byte{'\n'}, live[:cut]...))
	if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("the known generation over a torn tombstone: %v, want errFloorDegraded", err)
	}
	appendLogBytes(t, s, userFloorLogName, live[cut:])
	if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("the known generation once a foreign append completed the tear: %v, want errFloorDegraded", err)
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current once a foreign append completed the tear: %v, want errFloorDegraded", err)
	}
	// The server's next append closes nothing more: the merged line stays
	// damage, read again from the start too.
	closer, err := floorLine("user/1002", "other", guid(0x11), 1)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, append([]byte{'\n'}, closer...))
	if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("the known generation after the next append: %v, want errFloorDegraded", err)
	}
}

// A torn tail grown by a foreign append that is still torn keeps the
// classification of the bytes first read: a fragment that tainted a key
// does not become one that taints another.
func TestForeignGrowthOfTornTailKeepsTaint(t *testing.T) {
	s, server, _ := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	gen := entryGeneration(t, server, "token")
	k := floorKey{"user/1001", "token", gen}
	appendLogBytes(t, s, userFloorLogName, []byte("\nuser/1001 tok"))
	if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("the known generation under a torn name prefix: %v, want errFloorDegraded", err)
	}
	appendLogBytes(t, s, userFloorLogName, []byte("x "))
	if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("the known generation once a foreign append grew the tear: %v, want errFloorDegraded", err)
	}
}
