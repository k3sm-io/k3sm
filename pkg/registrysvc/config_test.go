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

package registrysvc

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// TestRenderConfigShape pins the document handed to the zot child, field by
// field. It matters more than an ordinary marshalling test for two reasons: zot's
// loader is STRICT (an unknown key is a boot failure), so every key here is load
// bearing; and the accessControl block below IS the security posture — anonymous
// read, authenticated write, nothing granted by merely being authenticated.
func TestRenderConfigShape(t *testing.T) {
	body, err := renderConfig("/var/lib/k3sm/server", "127.0.0.1", 6450)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	var got zotConfig
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("the rendered config is not valid JSON: %v", err)
	}

	t.Run("storage", func(t *testing.T) {
		if want := "/var/lib/k3sm/server/registry"; got.Storage.RootDirectory != want {
			t.Errorf("rootDirectory = %q, want %q", got.Storage.RootDirectory, want)
		}
		if !got.Storage.Dedupe {
			t.Error("dedupe is off; identical layers across pushes would each be stored whole")
		}
		if !got.Storage.GC {
			t.Error("gc is off; an ingest registry that never collects grows without bound")
		}
		if got.Storage.GCDelay != gcDelay || got.Storage.GCInterval != gcInterval {
			t.Errorf("gc cadence = (%q,%q), want (%q,%q)", got.Storage.GCDelay, got.Storage.GCInterval, gcDelay, gcInterval)
		}
	})

	t.Run("http", func(t *testing.T) {
		if got.HTTP.Address != "127.0.0.1" {
			t.Errorf("address = %q, want the loopback bind", got.HTTP.Address)
		}
		// zot's schema types the port as a STRING and refuses the file on a type
		// mismatch, so this is a boot-or-not assertion, not a formatting one.
		if got.HTTP.Port != "6450" {
			t.Errorf("port = %q, want the string \"6450\"", got.HTTP.Port)
		}
		if want := []string{dockerCompat}; !reflect.DeepEqual(got.HTTP.Compat, want) {
			t.Errorf("compat = %v, want %v — without it a Docker Schema-2 manifest is refused MANIFEST_INVALID", got.HTTP.Compat, want)
		}
		if want := "/var/lib/k3sm/server/registry/htpasswd"; got.HTTP.Auth.HTPasswd.Path != want {
			t.Errorf("htpasswd path = %q, want %q", got.HTTP.Auth.HTPasswd.Path, want)
		}
		if got.HTTP.Auth.FailDelay != authFailDelay {
			t.Errorf("failDelay = %d, want %d", got.HTTP.Auth.FailDelay, authFailDelay)
		}
	})

	t.Run("access control is anonymous-read and authenticated-write", func(t *testing.T) {
		group, ok := got.HTTP.AccessControl.Repositories[allRepositories]
		if !ok {
			t.Fatalf("no policy for %q; repositories = %v", allRepositories, got.HTTP.AccessControl.Repositories)
		}
		if want := []string{"read"}; !reflect.DeepEqual(group.AnonymousPolicy, want) {
			t.Errorf("anonymousPolicy = %v, want %v — the node's runtime pulls with no credential", group.AnonymousPolicy, want)
		}
		if len(group.DefaultPolicy) != 0 {
			t.Errorf("defaultPolicy = %v, want empty — being authenticated must grant nothing by itself", group.DefaultPolicy)
		}
		if len(group.Policies) != 1 {
			t.Fatalf("policies = %v, want exactly one", group.Policies)
		}
		if want := []string{pushUser}; !reflect.DeepEqual(group.Policies[0].Users, want) {
			t.Errorf("policy users = %v, want %v", group.Policies[0].Users, want)
		}
		if want := []string{"read", "create", "update", "delete"}; !reflect.DeepEqual(group.Policies[0].Actions, want) {
			t.Errorf("policy actions = %v, want %v", group.Policies[0].Actions, want)
		}
	})
}

// TestRenderConfigRefusesNonLoopback pins that the bind discipline is enforced at
// the RENDER too, not only at New. The rendered file is what the child actually
// binds, so a second path that could produce a wildcard bind would defeat the
// constructor's refusal entirely.
func TestRenderConfigRefusesNonLoopback(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::", "10.0.0.4", "localhost", ""} {
		t.Run(bind, func(t *testing.T) {
			if _, err := renderConfig(t.TempDir(), bind, 6450); !errors.Is(err, ErrNonLoopbackBind) {
				t.Fatalf("renderConfig(%q) err = %v, want ErrNonLoopbackBind", bind, err)
			}
		})
	}
}

// TestRenderConfigIsDeterministic pins that two renders of the same inputs
// produce identical bytes. The config is rewritten on every boot; a map iteration
// leaking into the output would rewrite the file with equivalent-but-different
// content each time, which turns "did the config change?" into an unanswerable
// question during an incident.
func TestRenderConfigIsDeterministic(t *testing.T) {
	a, err := renderConfig("/w", "127.0.0.1", 6450)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	b, err := renderConfig("/w", "127.0.0.1", 6450)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("two renders of the same inputs differ:\n%s\n---\n%s", a, b)
	}
}
