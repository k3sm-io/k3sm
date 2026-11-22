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

// Package typed is the pure half of the keystore's typed credentials: the
// typed envelope codec, the Credential value a store hands its consumers, and
// the SSH key helpers. docs/design/keystore.md § "Typed credentials" is its
// specification.
//
// The kind names, the projection field table, the item type, the
// refresh-owner grammar and the closed name sets are not here: they are the
// public names in k3sm.io/apis/keystore/credential, which this package uses.
//
// # The envelope
//
// Kinds token, ssh and oauth seal an envelope rather than raw bytes: a 1-byte
// envelope version (EnvelopeVersion), then fields, each a 1-byte tag, a 2-byte
// big-endian length and the value. Tags are strictly ascending, so a field
// appears at most once and in one order; every required tag of the kind is
// present and no other tag is; every value is within its bound. So each
// Envelope has exactly one encoding, and Decode(Encode(e)) is e. Anything
// else Decode refuses as ErrCorrupt, except an envelope version this build
// does not know, which is ErrKindUnsupported.
//
// # The refresh token
//
// Credential has no field for an oauth refresh token. Envelope carries it
// beside a Credential; a store returns only the Credential to every consumer
// but the refresher, so a renderer or a socket handler never holds the
// refresh token's bytes.
//
// The package holds no state and no seams: randomness comes in as an
// io.Reader from the caller. It imports no Kubernetes package and nothing of
// pkg/keystore.
package typed
