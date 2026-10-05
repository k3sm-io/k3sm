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

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// theServerToken is a server-class token over testCluster()'s CA, so a
// --server-join install reaches the join preflight's cluster comparison the way
// a live one does.
var theServerToken = "K10" + testCluster().pin + "::server:s3rv3r-s3cr3t"

// seedMember puts a member's data in dir: a non-empty etcd data dir.
func seedMember(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "member"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// recordedArgs returns the arguments the fake's server-arguments record holds.
func recordedArgs(t *testing.T, f *fakeSystem, cfg Config) []string {
	t.Helper()
	rec, ok := f.serverArgs[cfg.withDefaults().ServerArgsRecord]
	if !ok {
		t.Fatal("install wrote no server-arguments record")
	}
	return rec.Args
}

// TestInstallEmbeddedEtcdServer drives the whole Install over the fake for the
// two HA requests and the reinstalls that follow them: what the daemon is
// rendered with, what the record carries forward, where a joining server's
// token is staged, and which role changes are refused.
func TestInstallEmbeddedEtcdServer(t *testing.T) {
	ctx := context.Background()

	t.Run("--cluster-init renders and records, and a plain reinstall carries it", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		first := cfg
		first.ClusterInit, first.NodeIP, first.MeshIP = true, "192.0.2.10", "100.64.0.1"
		if err := Install(ctx, f, first); err != nil {
			t.Fatalf("Install --cluster-init: %v", err)
		}
		want := []string{"--mesh-ip", "100.64.0.1", "--cluster-init", "--etcd-peer-ip", "192.0.2.10"}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("server plist carries %q, want %q", got, want)
		}
		if got := recordedArgs(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("record carries %q, want %q", got, want)
		}
		// Re-running the same request does not duplicate a flag.
		if err := Install(ctx, f, first); err != nil {
			t.Fatalf("repeat Install --cluster-init: %v", err)
		}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("after a repeated request the plist carries %q, want %q", got, want)
		}
		// A reinstall with no flags of its own, after an uninstall removed the
		// plist, carries the HA role from the record.
		if err := Uninstall(ctx, f, cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if err := Install(ctx, f, cfg); err != nil {
			t.Fatalf("plain reinstall: %v", err)
		}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("after uninstall then a plain install the plist carries %q, want %q", got, want)
		}
	})

	t.Run("an HA request strips a carried --node-ip and renders the peer address as --etcd-peer-ip", func(t *testing.T) {
		// Before the peer address had a flag of its own, an HA server's LAN
		// address was carried as --node-ip. Left on the argv it is the node's
		// advertised address, aliased on lo0 at every start; the request must
		// drop it, not carry it beside the --etcd-peer-ip it renders.
		f := &fakeSystem{}
		cfg := testConfig(t)
		configureServerArgs(f, cfg, "--mesh-ip", "100.64.0.1", "--cluster-init", "--node-ip", "192.0.2.10")
		req := cfg
		req.ClusterInit, req.NodeIP = true, "192.0.2.10"
		if err := Install(ctx, f, req); err != nil {
			t.Fatalf("Install --cluster-init over a pre-split record: %v", err)
		}
		want := []string{"--mesh-ip", "100.64.0.1", "--cluster-init", "--etcd-peer-ip", "192.0.2.10"}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("server plist carries %q, want %q", got, want)
		}
	})

	t.Run("a plain reinstall over pre-split HA arguments refuses and names the migration", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			carried []string
			want    []string // substrings of the refusal
		}{
			{
				name:    "cluster-init",
				carried: []string{"--mesh-ip", "100.64.0.1", "--cluster-init", "--node-ip", "192.0.2.10"},
				want:    []string{"--cluster-init --node-ip 192.0.2.10", "sudo k3sm install --cluster-init --node-ip 192.0.2.10", "--etcd-peer-ip"},
			},
			{
				name:    "server-join",
				carried: []string{"--server-join", "--server", "192.0.2.10", "--node-ip=192.0.2.20"},
				want:    []string{"sudo k3sm install --server-join --server 192.0.2.10 --token-file", "--node-ip 192.0.2.20", "--etcd-peer-ip"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeSystem{}
				cfg := testConfig(t)
				configureServerArgs(f, cfg, tc.carried...)
				err := Install(ctx, f, cfg)
				if !errors.Is(err, ErrPreSplitEtcdArgs) {
					t.Fatalf("Install = %v, want ErrPreSplitEtcdArgs", err)
				}
				for _, w := range tc.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("the refusal does not name %q: %v", w, err)
					}
				}
				if m := mutatingCalls(f.calls); len(m) > 0 {
					t.Errorf("the refusal came after the install changed the machine: %v", m)
				}
			})
		}
	})

	t.Run("current-grammar HA arguments carry forward on a plain reinstall", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		want := []string{"--mesh-ip", "100.64.0.1", "--cluster-init", "--etcd-peer-ip", "192.0.2.10"}
		configureServerArgs(f, cfg, want...)
		if err := Install(ctx, f, cfg); err != nil {
			t.Fatalf("plain reinstall: %v", err)
		}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("server plist carries %q, want %q", got, want)
		}
	})

	t.Run("--server-join stages the server token and points the daemon at it", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(operatorTokenFile, []byte(theServerToken+"\n"))
		cfg := testConfig(t)
		join := cfg
		join.ServerJoin, join.JoinServer, join.TokenFile, join.NodeIP = true, "192.0.2.10", operatorTokenFile, "192.0.2.20"
		if err := Install(ctx, f, join); err != nil {
			t.Fatalf("Install --server-join: %v", err)
		}
		want := []string{"--server-join", "--server", "192.0.2.10", "--etcd-peer-ip", "192.0.2.20"}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("server plist carries %q, want %q", got, want)
		}
		if got := recordedArgs(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("record carries %q, want %q", got, want)
		}
		staged := cfg.withDefaults().serverJoinTokenPath()
		if got := strings.TrimSpace(string(f.files[staged])); got != theServerToken {
			t.Errorf("staged join token = %q, want the operator's server token", got)
		}
		plist := string(f.files[cfg.withDefaults().plistPath(ServerLabel)])
		if !strings.Contains(plist, "<string>"+staged+"</string>") {
			t.Errorf("the server plist does not point --token-file at the staged join token %s", staged)
		}
		for _, leak := range []string{theServerToken, operatorTokenFile} {
			if strings.Contains(plist, leak) {
				t.Errorf("the server plist carries %q; the daemon is told where its token is, never what it is", leak)
			}
		}
		// A plain reinstall keeps the daemon on the staged join token, which is
		// still there: the operator's own file may be gone by then.
		delete(f.files, operatorTokenFile)
		if err := Install(ctx, f, cfg); err != nil {
			t.Fatalf("plain reinstall of a joined server: %v", err)
		}
		plist = string(f.files[cfg.withDefaults().plistPath(ServerLabel)])
		if !strings.Contains(plist, "<string>"+staged+"</string>") {
			t.Error("a plain reinstall of a joined server stopped pointing --token-file at its join token")
		}
	})

	t.Run("--server-join refuses a worker token before anything is written", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(operatorTokenFile, []byte(theJoinToken+"\n"))
		cfg := testConfig(t)
		cfg.ServerJoin, cfg.JoinServer, cfg.TokenFile, cfg.NodeIP = true, "192.0.2.10", operatorTokenFile, "192.0.2.20"
		err := Install(ctx, f, cfg)
		if err == nil || !strings.Contains(err.Error(), "not a k3sm server token") {
			t.Fatalf("Install with a worker token = %v, want a refusal naming the server token", err)
		}
		if _, ok := f.files[cfg.withDefaults().plistPath(ServerLabel)]; ok {
			t.Error("a refused install wrote the server plist")
		}
	})

	t.Run("--server-join over a carried --cluster-init with member data is refused", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(operatorTokenFile, []byte(theServerToken+"\n"))
		cfg := testConfig(t)
		init := cfg
		init.ClusterInit, init.NodeIP = true, "192.0.2.10"
		if err := Install(ctx, f, init); err != nil {
			t.Fatalf("Install --cluster-init: %v", err)
		}
		etcdDir := executor.EtcdDataDir(cfg.withDefaults().serverWorkDir())
		seedMember(t, etcdDir)
		before := serverArgsOf(t, f, cfg)
		join := cfg
		join.ServerJoin, join.JoinServer, join.TokenFile, join.NodeIP = true, "192.0.2.11", operatorTokenFile, "192.0.2.10"
		err := Install(ctx, f, join)
		if !errors.Is(err, ErrEtcdRoleSwitch) {
			t.Fatalf("Install --server-join over a formed member = %v, want ErrEtcdRoleSwitch", err)
		}
		for _, want := range []string{"--cluster-init", etcdDir, "launchctl bootout"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q must name %q", err, want)
			}
		}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, before) {
			t.Errorf("a refused install changed the plist to %q", got)
		}

		// The symmetric request is refused the same way.
		f2 := &fakeSystem{}
		f2.putFile(operatorTokenFile, []byte(theServerToken+"\n"))
		cfg2 := testConfig(t)
		join2 := cfg2
		join2.ServerJoin, join2.JoinServer, join2.TokenFile, join2.NodeIP = true, "192.0.2.10", operatorTokenFile, "192.0.2.20"
		if err := Install(ctx, f2, join2); err != nil {
			t.Fatalf("Install --server-join: %v", err)
		}
		seedMember(t, executor.EtcdDataDir(cfg2.withDefaults().serverWorkDir()))
		init2 := cfg2
		init2.ClusterInit, init2.NodeIP = true, "192.0.2.20"
		if err := Install(ctx, f2, init2); !errors.Is(err, ErrEtcdRoleSwitch) {
			t.Fatalf("Install --cluster-init over a joined member = %v, want ErrEtcdRoleSwitch", err)
		}
	})

	t.Run("with the member data removed, --server-join replaces the carried --cluster-init", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(operatorTokenFile, []byte(theServerToken+"\n"))
		cfg := testConfig(t)
		init := cfg
		init.ClusterInit, init.NodeIP, init.MeshIP = true, "192.0.2.10", "100.64.0.1"
		if err := Install(ctx, f, init); err != nil {
			t.Fatalf("Install --cluster-init: %v", err)
		}
		join := cfg
		join.ServerJoin, join.JoinServer, join.TokenFile, join.NodeIP = true, "192.0.2.11", operatorTokenFile, "192.0.2.10"
		if err := Install(ctx, f, join); err != nil {
			t.Fatalf("Install --server-join with no member data: %v", err)
		}
		want := []string{"--mesh-ip", "100.64.0.1", "--server-join", "--server", "192.0.2.11", "--etcd-peer-ip", "192.0.2.10"}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("server plist carries %q, want %q", got, want)
		}
		if got := recordedArgs(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("record carries %q, want %q", got, want)
		}
	})

	t.Run("an empty etcd dir holds no member and does not block the role change", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(operatorTokenFile, []byte(theServerToken+"\n"))
		cfg := testConfig(t)
		init := cfg
		init.ClusterInit, init.NodeIP = true, "192.0.2.10"
		if err := Install(ctx, f, init); err != nil {
			t.Fatalf("Install --cluster-init: %v", err)
		}
		if err := os.MkdirAll(executor.EtcdDataDir(cfg.withDefaults().serverWorkDir()), 0o700); err != nil {
			t.Fatal(err)
		}
		join := cfg
		join.ServerJoin, join.JoinServer, join.TokenFile, join.NodeIP = true, "192.0.2.11", operatorTokenFile, "192.0.2.10"
		if err := Install(ctx, f, join); err != nil {
			t.Fatalf("Install --server-join over an empty etcd dir: %v", err)
		}
	})

	t.Run("the staged join token lives until uninstall or a role change", func(t *testing.T) {
		joined := func(t *testing.T) (*fakeSystem, Config, string) {
			t.Helper()
			f := &fakeSystem{}
			f.putFile(operatorTokenFile, []byte(theServerToken+"\n"))
			cfg := testConfig(t)
			join := cfg
			join.ServerJoin, join.JoinServer, join.TokenFile, join.NodeIP = true, "192.0.2.10", operatorTokenFile, "192.0.2.20"
			if err := Install(ctx, f, join); err != nil {
				t.Fatalf("Install --server-join: %v", err)
			}
			staged := cfg.withDefaults().serverJoinTokenPath()
			if _, ok := f.files[staged]; !ok {
				t.Fatal("a --server-join install staged no join token")
			}
			return f, cfg, staged
		}

		t.Run("a plain reinstall keeps it", func(t *testing.T) {
			f, cfg, staged := joined(t)
			if err := Install(ctx, f, cfg); err != nil {
				t.Fatalf("plain reinstall: %v", err)
			}
			if _, ok := f.files[staged]; !ok {
				t.Error("a plain reinstall of a joined server removed the join token its daemon reads at every start")
			}
		})

		t.Run("uninstall removes it", func(t *testing.T) {
			f, cfg, staged := joined(t)
			if err := Uninstall(ctx, f, cfg); err != nil {
				t.Fatalf("Uninstall: %v", err)
			}
			if _, ok := f.files[staged]; ok {
				t.Error("uninstall left the server-class join token behind")
			}
		})

		t.Run("a node role change removes it, whichever role the uninstall names", func(t *testing.T) {
			// A role change is an uninstall then an install of the other role.
			// The uninstall reads the server plist off the disk and tears that
			// role down too, so the token goes even from an agent-role Config.
			f, cfg, staged := joined(t)
			asAgent := cfg
			asAgent.Role = RoleAgent
			if err := Uninstall(ctx, f, asAgent); err != nil {
				t.Fatalf("Uninstall: %v", err)
			}
			if _, ok := f.files[staged]; ok {
				t.Error("the server join token survived the uninstall that precedes a role change")
			}
		})

		t.Run("an etcd role change to --cluster-init removes it", func(t *testing.T) {
			f, cfg, staged := joined(t)
			init := cfg
			init.ClusterInit, init.NodeIP = true, "192.0.2.20"
			if err := Install(ctx, f, init); err != nil {
				t.Fatalf("Install --cluster-init over a joined server with no member data: %v", err)
			}
			if _, ok := f.files[staged]; ok {
				t.Error("the server join token survived the change to --cluster-init")
			}
			plist := string(f.files[cfg.withDefaults().plistPath(ServerLabel)])
			if strings.Contains(plist, staged) {
				t.Error("the --cluster-init server is still pointed at the join token")
			}
		})
	})

	t.Run("boolFlagSet reads a bool the way the flag package does", func(t *testing.T) {
		for _, tc := range []struct {
			arg  string
			want bool
		}{
			{"--cluster-init", true}, {"-cluster-init", true}, {"--cluster-init=true", true},
			{"--cluster-init=1", true}, {"--cluster-init=T", true}, {"--cluster-init=false", false},
			{"--cluster-init=0", false}, {"--cluster-init=bogus", false}, {"--server-join", false},
		} {
			if got := boolFlagSet([]string{tc.arg}, clusterInitFlag); got != tc.want {
				t.Errorf("boolFlagSet(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		}
	})

	t.Run("a hand-built Config is held to the same contract", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			edit func(*Config)
			want string
		}{
			{"both roles", func(c *Config) { c.ClusterInit, c.ServerJoin, c.NodeIP = true, true, "192.0.2.10" }, "mutually exclusive"},
			{"join without a server", func(c *Config) { c.ServerJoin, c.TokenFile, c.NodeIP = true, operatorTokenFile, "192.0.2.10" }, "needs --server"},
			{"join without a token", func(c *Config) { c.ServerJoin, c.JoinServer, c.NodeIP = true, "192.0.2.11", "192.0.2.10" }, "needs --token-file"},
			{"loopback node IP", func(c *Config) { c.ClusterInit, c.NodeIP = true, "127.0.0.1" }, "loopback"},
			{"an agent asking for a role", func(c *Config) { c.Role, c.JoinServer, c.ClusterInit = RoleAgent, "192.0.2.11", true }, "--agent"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeSystem{}
				cfg := testConfig(t)
				tc.edit(&cfg)
				err := Install(ctx, f, cfg)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Install = %v, want a refusal naming %q", err, tc.want)
				}
				if len(f.files) != 0 {
					t.Errorf("a refused install wrote %d files", len(f.files))
				}
			})
		}
	})
}
