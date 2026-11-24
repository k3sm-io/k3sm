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
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// A stored Ed25519 version that authenticates and fails checkStored is
// damage: ErrCorrupt. It also matches InvalidValue, the refusal a put of
// the same value gets, so the socket's table must judge ErrCorrupt first.
func TestStoredEd25519FailingCheckIsCorrupt(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	if _, err := s.Put(ctx, "ed", KindEd25519, bytes.Repeat([]byte{7}, ed25519.SeedSize)); err != nil {
		t.Fatal(err)
	}
	sealVersion(t, s, server, "ed", 1, KindEd25519, []byte("SECRET!"))
	_, _, err := s.Current(ctx, "ed")
	if !errors.Is(err, ErrCorrupt) || !InvalidValue(err) {
		t.Fatalf("reading an Ed25519 version that fails its check: %v, want ErrCorrupt (and InvalidValue)", err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), " 7 ") {
		t.Fatalf("the error %q carries the value or its length", err)
	}
}
