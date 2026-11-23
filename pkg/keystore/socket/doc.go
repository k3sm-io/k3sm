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

// Package socket is the wire layer of the keystore's non-root socket,
// protocol k3sm-keys/1 (docs/design/keystore.md, "Protocol k3sm-keys/1").
//
// A frame is a 4-byte big-endian length, then the frame body: a 1-byte type,
// a 4-byte big-endian header length and that many bytes of JSON header, and
// optionally a 4-byte big-endian value length and that many bytes of binary
// value. The frame length counts the body only, never its own 4 bytes, and
// must equal the body exactly: the value is present iff bytes remain after
// the header, and then its length must account for every one of them. The
// frame cap is MaxFrame and the header cap MaxHeader; every length is checked
// against its cap and against what remains of the frame before anything is
// allocated. Frames are strict (a frame that breaks a rule is a
// *ProtocolError, which closes the connection); headers are tolerant
// (unknown JSON fields are ignored).
//
// The client sends TypeHello first and TypeRequest after it; the server
// answers with TypeHello, TypeReply or TypeError. A request header names its
// operation in "op"; an error header carries its code in "code".
//
// This package holds the frames, the HELLO exchange, the error codes, the
// per-connection loop with its request and idle bounds, and the Listener:
// peer admission at accept (eligible uid, not sandboxed, read through
// injected sources), the connection caps and the rate-limited refusal
// lines. It has no store: every operation is answered unknown-op.
package socket
