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

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore/socket"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/runtimed/pkg/keystorepaths"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The Pod profile the linked runtimed renders for the server's posture
// denies the keystore socket the server serves, for the default data root
// and for custom ones: this is the test that turns red when k3sm is built
// against a runtimed whose Pod profile lacks the keystore deny, or whose
// deny misses a data root the server can be given.
func TestServerPodProfileDeniesKeystoreSocket(t *testing.T) {
	for _, tt := range []struct {
		name    string
		workDir string
		podRoot string // "" derives the work dir's parent, as preflightServer does
		socket  string
	}{
		{"the default data root", install.DefaultDataRoot + "/server", "", "/var/lib/k3sm/keystore-sock/keys.sock"},
		{"a custom data root", "/Volumes/k3sm-data/server", "", "/Volumes/k3sm-data/keystore-sock/keys.sock"},
		{"a custom data root under /private", "/private/var/k3sm/server", "", "/private/var/k3sm/keystore-sock/keys.sock"},
		{"a pod root apart from the data root", "/Volumes/k3sm-data/server", "/opt/k3sm-pods", "/Volumes/k3sm-data/keystore-sock/keys.sock"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := serverOptions{workDir: tt.workDir, podRoot: tt.podRoot, logs: containerLogOptions{dir: podlogs.DefaultPodLogsDir}}
			if opts.podRoot == "" {
				opts.podRoot = keystoreLayout(opts.workDir).DataRoot
			}
			sock := keystoreSocketPath(opts.workDir)
			if sock != tt.socket || sock != keystorepaths.SocketPath(serverPodPosture(opts).DataRoot) {
				t.Fatalf("the server serves %s; want %s, under the posture's data root", sock, tt.socket)
			}
			profile, err := keystorePodProfile(serverPodPosture(opts))
			if err != nil {
				t.Fatal(err)
			}
			if err := socket.ProfileDeniesSocket(profile, sock); err != nil {
				t.Fatalf("the linked runtimed's Pod profile does not deny %s: %v", sock, err)
			}
			if err := podProfileCheck(func() (string, error) { return profile, nil }, sock)(); err != nil {
				t.Fatalf("the start check: %v", err)
			}
		})
	}
}

// serverPodPosture is the one derivation the node's runtime and the socket's
// check share: the data root is the socket's, the state dir is the work
// dir, and the pod root is the one the node is given.
func TestServerPodPostureIsTheSockets(t *testing.T) {
	opts := serverOptions{workDir: "/Volumes/d/server", podRoot: "/opt/pods", logs: containerLogOptions{dir: "/Volumes/d/logs"}}
	p := serverPodPosture(opts)
	if p.DataRoot != keystoreLayout(opts.workDir).DataRoot || p.StateDir != opts.workDir || p.WorkDir != opts.podRoot || p.PodLogsDir != opts.logs.dir {
		t.Fatalf("posture %+v does not follow the options %+v", p, opts)
	}
}

// A Pod profile rendered for a posture whose data root is not the socket's
// leaves the socket open, and the user scope goes off with OffPodProfile:
// one Warn naming the remedy, no start check, nothing retried. A render
// that fails is the same off state. The fixture's own profile, rendered for
// the socket's data root, passes.
func TestKeystorePodProfileMismatchTurnsScopeOff(t *testing.T) {
	other := sandbox.Posture{
		WorkDir:    "/Volumes/other",
		DataRoot:   "/Volumes/other",
		StateDir:   "/Volumes/other/server",
		PodLogsDir: podlogs.DefaultPodLogsDir,
	}
	for _, tt := range []struct {
		name   string
		render func() (string, error)
		detail string
	}{
		{"another data root", func() (string, error) { return keystorePodProfile(other) }, "keystore-sock"},
		{"a render that fails", func() (string, error) { return "", errors.New("fake: the generator refused the posture") }, "the generator refused"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newWiringFixture(t)
			f.deps.podProfile = tt.render
			logs := &bytes.Buffer{}
			f.deps.log = slog.New(slog.NewTextHandler(logs, nil))
			var euids int
			f.deps.euid = func() int { euids++; return 277 }
			synctest.Test(t, func(t *testing.T) {
				ks, err := newKeystoreSocket(f.deps)
				if err != nil {
					t.Fatal(err)
				}
				stop := runKeystoreSocket(context.Background(), ks)
				synctest.Wait()
				st := ks.sup.State()
				stop()
				if st.Phase != socket.PhaseOff || st.Reason != socket.OffPodProfile || !strings.Contains(st.Detail, tt.detail) {
					t.Fatalf("state = %+v, want off with %q naming %q", st, socket.OffPodProfile, tt.detail)
				}
				if euids != 0 {
					t.Fatalf("%d start checks ran; the profile is checked before any", euids)
				}
				if n := strings.Count(logs.String(), "level=WARN"); n != 1 || !strings.Contains(logs.String(), socket.PodProfileRemedy) {
					t.Fatalf("%d Warn lines, want one naming %q:\n%s", n, socket.PodProfileRemedy, logs.String())
				}
			})
		})
	}
	t.Run("the socket's own data root", func(t *testing.T) {
		f := newWiringFixture(t)
		cfg, closeAll, err := keystoreSocketConfig(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll()
		if err := cfg.PodProfile(); err != nil {
			t.Fatalf("the profile for the socket's data root: %v", err)
		}
	})
	t.Run("no profile source", func(t *testing.T) {
		f := newWiringFixture(t)
		f.deps.podProfile = nil
		if _, _, err := keystoreSocketConfig(f.deps); err == nil || !strings.Contains(err.Error(), "Pod profile") {
			t.Fatalf("got %v, want the config refused", err)
		}
	})
}
