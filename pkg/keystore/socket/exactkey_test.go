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

package socket

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The dispatcher reads op by its exact name, as decodeRequest reads every
// field: an op spelled in another case, given twice in any case, missing,
// empty, null or not a string closes the connection, and no operation runs.
// An exact op beside an unknown field still dispatches.
func TestDispatchOpExactKey(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		ran          string // the op that runs; "" when the connection closes
	}{
		{"exact", `{"op":"rm"}`, "rm"},
		{"exact beside an unknown field", `{"op":"list","entry":"x","later":1}`, "list"},
		{"upper case", `{"OP":"rm"}`, ""},
		{"title case", `{"Op":"rm"}`, ""},
		{"duplicated, another case", `{"op":"list","Op":"rm"}`, ""},
		{"duplicated, another case first", `{"Op":"rm","op":"list"}`, ""},
		{"duplicated exactly", `{"op":"list","op":"rm"}`, ""},
		{"missing", `{"entry":"user/501/a"}`, ""},
		{"empty", `{"op":""}`, ""},
		{"null", `{"op":null}`, ""},
		{"a number", `{"op":1}`, ""},
		{"an array", `{"op":["rm"]}`, ""},
		{"an object", `{"op":{"op":"rm"}}`, ""},
		{"not an object", `["op","rm"]`, ""},
		{"data after the object", `{"op":"rm"}{"op":"list"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var (
					mu  sync.Mutex
					ran []string
				)
				record := func(name string) HandlerOption {
					return withOp(name, func(context.Context, Request) (Reply, error) {
						mu.Lock()
						defer mu.Unlock()
						ran = append(ran, name)
						return Reply{}, nil
					})
				}
				h, err := NewHandler(time.Now, record("rm"), record("list"))
				if err != nil {
					t.Fatal(err)
				}
				s := serveWith(t, h)
				s.hello(t)
				s.send(t, TypeRequest, tc.header, nil)
				if tc.ran != "" {
					f, _ := s.recvFrame(t)
					if f.Type != TypeReply {
						t.Fatalf("%s answered %#02x %s, want a reply", tc.header, byte(f.Type), f.Header)
					}
					if err := s.finish(); err != nil {
						t.Fatalf("Serve = %v", err)
					}
				} else {
					var pe *ProtocolError
					if err := s.wait(); !errors.As(err, &pe) {
						t.Fatalf("%s: Serve = %v, want a protocol error", tc.header, err)
					}
					s.closed(t)
					_ = s.finish()
				}
				mu.Lock()
				defer mu.Unlock()
				if want := []string{tc.ran}; tc.ran == "" && len(ran) != 0 || tc.ran != "" && (len(ran) != 1 || ran[0] != want[0]) {
					t.Fatalf("%s ran %q, want %q", tc.header, ran, tc.ran)
				}
			})
		})
	}
}

// HELLO reads proto, min and max by their exact names: a known field
// spelled in another case, given twice or of the wrong type closes the
// connection with nothing written; unknown fields are ignored.
func TestHelloProtoExactKey(t *testing.T) {
	for _, tc := range []struct {
		name, hello string
		ok          bool
	}{
		{"exact", helloV1, true},
		{"exact beside an unknown field", `{"proto":"k3sm-keys","min":1,"max":1,"protocol":"x"}`, true},
		{"proto in title case", `{"Proto":"k3sm-keys","min":1,"max":1}`, false},
		{"proto in upper case", `{"PROTO":"k3sm-keys","min":1,"max":1}`, false},
		{"proto duplicated, another case", `{"proto":"k3sm-keys","Proto":"other","min":1,"max":1}`, false},
		{"proto duplicated exactly", `{"proto":"other","proto":"k3sm-keys","min":1,"max":1}`, false},
		{"proto missing", `{"min":1,"max":1}`, false},
		{"proto not a string", `{"proto":7,"min":1,"max":1}`, false},
		{"min in another case", `{"proto":"k3sm-keys","Min":1,"max":1}`, false},
		{"max duplicated", `{"proto":"k3sm-keys","min":1,"max":9,"max":1}`, false},
		{"max not a number", `{"proto":"k3sm-keys","min":1,"max":"1"}`, false},
		{"not an object", `"k3sm-keys"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := serve(t, time.Now)
				s.send(t, TypeHello, tc.hello, nil)
				if tc.ok {
					var reply HelloReply
					s.recv(t, TypeHello, &reply)
					if reply.Proto != Proto || reply.Version != 1 {
						t.Fatalf("HELLO reply %+v", reply)
					}
					if err := s.finish(); err != nil {
						t.Fatalf("Serve = %v", err)
					}
					return
				}
				var pe *ProtocolError
				if err := s.wait(); !errors.As(err, &pe) {
					t.Fatalf("%s: Serve = %v, want a protocol error", tc.hello, err)
				}
				s.closed(t)
				_ = s.finish()
			})
		})
	}
}
