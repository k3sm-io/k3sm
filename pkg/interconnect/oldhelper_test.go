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

package interconnect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// helloFixtureDir holds the netd Hello replies the M17 lab ladder also reads.
const helloFixtureDir = "../../hack/lab/testdata/m17-interconnect"

// readHelloFixture returns a fixture's bytes with the trailing newline trimmed.
func readHelloFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(helloFixtureDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// fakeHelper is a netd on a real unix socket that answers every frame of its one
// connection with reply, and records the verb of each frame it read.
type fakeHelper struct {
	path  string
	ln    net.Listener
	reply []byte
	done  chan struct{}

	mu    sync.Mutex
	verbs []wire.Verb
}

func startFakeHelper(t *testing.T, reply []byte) *fakeHelper {
	t.Helper()
	// A short directory: a unix socket path is bounded at 104 bytes on darwin.
	dir, err := os.MkdirTemp("", "ohh")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	h := &fakeHelper{path: filepath.Join(dir, "netd.sock"), reply: reply, done: make(chan struct{})}
	h.ln, err = net.Listen("unix", h.path)
	if err != nil {
		t.Fatalf("listen %s: %v", h.path, err)
	}
	t.Cleanup(func() { _ = h.ln.Close() })
	go h.serve()
	return h
}

func (h *fakeHelper) serve() {
	defer close(h.done)
	conn, err := h.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		raw, err := wire.ReadFrame(conn, wire.DefaultMaxRequestBytes)
		if err != nil {
			return
		}
		var req wire.Request
		_ = json.Unmarshal(raw, &req)
		h.mu.Lock()
		h.verbs = append(h.verbs, req.Verb)
		h.mu.Unlock()
		if err := wire.WriteFrame(conn, h.reply); err != nil {
			return
		}
	}
}

// seen waits for the connection to end and returns the verbs the helper read.
func (h *fakeHelper) seen(t *testing.T) []wire.Verb {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake helper's connection did not end")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]wire.Verb(nil), h.verbs...)
}

// ensureAgainst runs the wire client's interconnect call against a fake helper
// that answers with reply, and returns the verbs the helper read and the call's error.
func ensureAgainst(t *testing.T, reply []byte) ([]wire.Verb, error) {
	t.Helper()
	h := startFakeHelper(t, reply)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := wire.NewClient(h.path).EnsureInterconnectAlias(ctx, 0)
	return h.seen(t), err
}

// TestOldHelperHelloReplyIsHelperTooOld pins what a helper older than the
// interconnect verbs answers to a Hello, and what the current client makes of it:
// the reply the lab ladder used to obtain by downgrading a live node, held here as
// a fixture so no downgrade is needed to keep it true.
func TestOldHelperHelloReplyIsHelperTooOld(t *testing.T) {
	old := readHelloFixture(t, "hello-minor1.json")

	t.Run("decodes as version 1.1, not ok, unknown verb", func(t *testing.T) {
		var resp wire.Response
		if err := json.Unmarshal(old, &resp); err != nil {
			t.Fatalf("decode %s: %v", old, err)
		}
		want := wire.Response{Version: wire.Version{Major: 1, Minor: 1}, OK: false, Error: `unknown verb "Hello"`}
		if resp.Version != want.Version || resp.OK != want.OK || resp.Error != want.Error || resp.Reason != "" {
			t.Errorf("decoded %+v, want %+v", resp, want)
		}
	})

	t.Run("marshals back to the fixture bytes", func(t *testing.T) {
		resp := wire.Response{Version: wire.Version{Major: 1, Minor: 1}, Error: `unknown verb "Hello"`}
		got, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(got, old) {
			t.Errorf("marshalled %s, want the fixture %s", got, old)
		}
	})

	t.Run("version 1.1 does not support the interconnect", func(t *testing.T) {
		if (wire.Version{Major: 1, Minor: 1}).SupportsInterconnect() {
			t.Error("Version 1.1 reports SupportsInterconnect, want false")
		}
	})

	t.Run("the client returns ErrHelperTooOld and sends no verb after Hello", func(t *testing.T) {
		verbs, err := ensureAgainst(t, old)
		if !errors.Is(err, wire.ErrHelperTooOld) {
			t.Errorf("EnsureInterconnectAlias error = %v, want ErrHelperTooOld", err)
		}
		if len(verbs) != 1 || verbs[0] != wire.VerbHello {
			t.Errorf("the helper read %v, want only %s", verbs, wire.VerbHello)
		}
	})

	t.Run("control: a minor-2 reply is not too old", func(t *testing.T) {
		verbs, err := ensureAgainst(t, readHelloFixture(t, "hello-minor2.json"))
		if errors.Is(err, wire.ErrHelperTooOld) {
			t.Errorf("EnsureInterconnectAlias error = %v against a minor-2 helper, want no ErrHelperTooOld", err)
		}
		if len(verbs) != 2 || verbs[0] != wire.VerbHello || verbs[1] != wire.VerbEnsureInterconnectAlias {
			t.Errorf("the helper read %v, want %s then %s", verbs, wire.VerbHello, wire.VerbEnsureInterconnectAlias)
		}
	})

	t.Run("control: an undecodable reply is a plain error", func(t *testing.T) {
		verbs, err := ensureAgainst(t, []byte("not a netd reply"))
		if err == nil || errors.Is(err, wire.ErrHelperTooOld) {
			t.Errorf("EnsureInterconnectAlias error = %v against an undecodable reply, want a plain error", err)
		}
		if len(verbs) != 1 || verbs[0] != wire.VerbHello {
			t.Errorf("the helper read %v, want only %s", verbs, wire.VerbHello)
		}
	})
}
