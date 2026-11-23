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
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// helloed starts Serve and completes the HELLO exchange.
func helloed(t *testing.T) *session {
	t.Helper()
	s := serve(t, time.Now)
	s.send(t, TypeHello, helloV1, nil)
	var reply HelloReply
	s.recv(t, TypeHello, &reply)
	return s
}

// request is a well-formed request frame's encoding.
func request(t *testing.T) []byte {
	t.Helper()
	b, err := AppendFrame(nil, Frame{Type: TypeRequest, Header: []byte(`{"op":"x"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cutAt checks that Serve ended on a deadline at want after its start and
// closed the connection.
func (s *session) cutAt(t *testing.T, want time.Duration) {
	t.Helper()
	err := s.wait()
	if got := time.Since(s.start); got != want {
		t.Errorf("Serve returned after %v, want %v", got, want)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Serve = %v, want a deadline", err)
	}
	s.closed(t)
	_ = s.finish()
}

func (s *session) write(t *testing.T, b []byte) {
	t.Helper()
	if _, err := s.client.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestRequestTimeout(t *testing.T) {
	rq := request(t)
	t.Run("a request still arriving at 10 s is cut", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := helloed(t)
			advance(5 * time.Second)
			s.write(t, rq[:1])
			advance(9 * time.Second)
			s.write(t, rq[1:len(rq)-1])
			s.cutAt(t, 5*time.Second+RequestBound)
		})
	})
	t.Run("a reply not taken by 10 s is cut", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := helloed(t)
			advance(3 * time.Second)
			s.write(t, rq)
			s.cutAt(t, 3*time.Second+RequestBound)
		})
	})
	t.Run("a request done within 10 s of its first byte is answered", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := helloed(t)
			advance(IdleBound - time.Second)
			s.write(t, rq[:1])
			advance(RequestBound - time.Second) // past the idle bound
			s.write(t, rq[1:])
			if c := s.recvCode(t); c != CodeUnknownOp {
				t.Fatalf("code = %q", c)
			}
			if err := s.finish(); err != nil {
				t.Fatalf("Serve = %v", err)
			}
		})
	})
}

func TestIdleTimeoutAfterHelloAndBetweenRequests(t *testing.T) {
	rq := request(t)
	t.Run("after HELLO", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := helloed(t)
			s.cutAt(t, IdleBound)
		})
	})
	t.Run("between requests", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := helloed(t)
			advance(20 * time.Second)
			s.write(t, rq)
			if c := s.recvCode(t); c != CodeUnknownOp {
				t.Fatalf("code = %q", c)
			}
			s.cutAt(t, 20*time.Second+IdleBound)
		})
	})
	t.Run("each request restarts the idle wait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := helloed(t)
			for range 3 {
				advance(IdleBound - time.Second)
				s.write(t, rq)
				if c := s.recvCode(t); c != CodeUnknownOp {
					t.Fatalf("code = %q", c)
				}
			}
			s.cutAt(t, 3*(IdleBound-time.Second)+IdleBound)
		})
	})
}
