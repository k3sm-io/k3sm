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
	"time"

	"k3sm.io/k3sm/pkg/keystore/typed"
)

// TestExpiryCheckedOnSealedSeconds is review round 4, item 4: an expiry is
// compared with the issue time as the envelope seals both, in whole
// seconds, so an expiry less than a second after the clock (sealed equal
// to the issue time) is refused, for a token and for an oauth access token.
func TestExpiryCheckedOnSealedSeconds(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	tok := tokenEnvelope("t1")
	tok.Credential.ExpiresAt = typedNow.Add(500 * time.Millisecond)
	if _, err := s.PutCredential(ctx, "tok", KindToken, tok); !errors.Is(err, typed.ErrInvalidCredential) {
		t.Fatalf("PutCredential of a token expiring within its issue second: %v, want ErrInvalidCredential", err)
	}
	pair := oauthEnvelope("a1", "r1")
	pair.Credential.AccessExpiresAt = typedNow.Add(500 * time.Millisecond)
	if _, err := s.PutCredential(ctx, "pair", KindOAuth, pair); !errors.Is(err, typed.ErrInvalidCredential) {
		t.Fatalf("PutCredential of an access token expiring within its issue second: %v, want ErrInvalidCredential", err)
	}
	pair.Credential.AccessExpiresAt = typedNow.Add(-time.Minute)
	if _, err := s.PutCredential(ctx, "pair", KindOAuth, pair); !errors.Is(err, typed.ErrInvalidCredential) {
		t.Fatalf("PutCredential of an access token expired before its issue time: %v, want ErrInvalidCredential", err)
	}
	pair.Credential.AccessExpiresAt = typedNow.Add(time.Second)
	if _, err := s.PutCredential(ctx, "pair", KindOAuth, pair); err != nil {
		t.Fatalf("PutCredential of an access token expiring a second after its issue: %v", err)
	}
}
