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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// nodesErrKube is a serving apiserver whose node list fails.
type nodesErrKube struct {
	fakeKube
	err error
}

func (k nodesErrKube) Nodes(context.Context) ([]corev1.Node, error) { return nil, k.err }

// plistFiles is the one install.System method install.AgentJoinServer calls,
// over an in-memory file set. The embedded nil System makes any other call
// panic, which fails the test as loudly as an assertion would.
type plistFiles struct {
	install.System
	files map[string][]byte
}

func (p plistFiles) ReadFile(path string) ([]byte, error) {
	b, ok := p.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

// workerNode is a Ready node reporting kubelet version v.
func workerNode(name, v string) corev1.Node {
	n := readyNode(name)
	n.Status.NodeInfo.KubeletVersion = v
	return n
}

// joinCanaries are argv values the installer renders onto the agent plist
// beside --server. None of them may reach the report.
const (
	joinCanaryDataRoot = "/Volumes/tokenfile-canary"
	joinCanaryNodeIP   = "192.0.2.77"
	joinCanaryExtra    = "--node-label=argv-canary"
)

// agentPlistSystem renders the agent LaunchDaemon exactly as `k3sm install
// --agent --server <host>` would, with a token file, a node IP and an extra
// operator argument on the argv, and serves it at the default plist path.
func agentPlistSystem(host string) plistFiles {
	cfg := install.Config{
		Role:           install.RoleAgent,
		JoinServer:     host,
		NodeIP:         joinCanaryNodeIP,
		DataRoot:       joinCanaryDataRoot,
		TokenFile:      "/var/root/join-token",
		ExtraAgentArgs: []string{joinCanaryExtra},
	}
	path := filepath.Join(install.DefaultLaunchDaemonDir, install.AgentLabel+".plist")
	return plistFiles{files: map[string][]byte{path: install.AgentPlist(cfg)}}
}

// TestStatusReportsWorkerVersionsAndJoinTarget pins the two fields an update
// client reads: on a server, every other node and its kubelet-reported version
// (absent when unknown, empty when there are none); on an agent, the bootstrap
// endpoint it joined, taken from the --server value alone.
func TestStatusReportsWorkerVersionsAndJoinTarget(t *testing.T) {
	t.Parallel()

	serverWith := func(t *testing.T, kube Kube) Collector {
		return contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", kube, nil)
	}

	t.Run("server with two workers lists both, sorted, without itself", func(t *testing.T) {
		t.Parallel()
		kube := healthyKube()
		b := workerNode("node-b", "v1.36.2+k3sm.0.1.6")
		a := workerNode("node-a", "v1.36.2+k3sm.0.1.7")
		a.Labels = map[string]string{controlPlaneNodeLabel: ""}
		// A label the node itself may write never stands in for the version.
		b.Labels = map[string]string{"k3sm.io/version": "v9.9.9"}
		kube.nodes = append(kube.nodes, b, a)
		rep := serverWith(t, kube).Collect(context.Background())
		want := []Worker{
			{Name: "node-a", Role: dataroot.RoleServer, Version: "v1.36.2+k3sm.0.1.7"},
			{Name: "node-b", Role: dataroot.RoleAgent, Version: "v1.36.2+k3sm.0.1.6"},
		}
		if rep.Workers == nil || !reflect.DeepEqual(*rep.Workers, want) {
			t.Fatalf("workers = %+v, want %+v", deref(rep.Workers), want)
		}
		if rep.JoinTarget != "" {
			t.Errorf("a server reports joinTarget %q", rep.JoinTarget)
		}
	})

	t.Run("no workers is an empty list, encoded as []", func(t *testing.T) {
		t.Parallel()
		rep := serverWith(t, healthyKube()).Collect(context.Background())
		if rep.Workers == nil || len(*rep.Workers) != 0 {
			t.Fatalf("workers = %v, want an empty, present list", rep.Workers)
		}
		raw := marshal(t, rep)
		if !strings.Contains(raw, `"workers":[]`) {
			t.Errorf("JSON does not carry an empty workers list: %s", raw)
		}
	})

	for name, kube := range map[string]Kube{
		"the node read fails":           nodesErrKube{fakeKube: healthyKube(), err: errors.New("forbidden")},
		"the apiserver does not answer": downKube(),
	} {
		t.Run(name+": workers is absent, never empty", func(t *testing.T) {
			t.Parallel()
			rep := serverWith(t, kube).Collect(context.Background())
			if rep.Workers != nil {
				t.Fatalf("workers = %+v, want absent", *rep.Workers)
			}
			if raw := marshal(t, rep); strings.Contains(raw, `"workers"`) {
				t.Errorf("JSON carries workers: %s", raw)
			}
		})
	}

	t.Run("no credential: workers is absent", func(t *testing.T) {
		t.Parallel()
		c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", nil, errors.New("no k3sm context in ~/.kube/config"))
		if rep := c.Collect(context.Background()); rep.Workers != nil {
			t.Fatalf("workers = %+v, want absent", *rep.Workers)
		}
	})

	t.Run("own node not identifiable: workers is absent", func(t *testing.T) {
		t.Parallel()
		kube := healthyKube()
		kube.nodes = []corev1.Node{workerNode("node-a", "v1"), workerNode("node-b", "v1")}
		if rep := serverWith(t, kube).Collect(context.Background()); rep.Workers != nil {
			t.Fatalf("workers = %+v, want absent when this server cannot be told apart", *rep.Workers)
		}
	})

	agent := func(t *testing.T, join func() (string, error)) Collector {
		c := contractAgent(t, func(_ *testing.T, _ Paths, fsys fakeFS) fakeFS { return fsys })
		c.Kube = healthyKube()
		c.KubeErr = nil
		c.AgentJoinServer = join
		return c
	}

	t.Run("agent reports the join target from the installed --server only", func(t *testing.T) {
		t.Parallel()
		sys := agentPlistSystem("192.0.2.10")
		rep := agent(t, func() (string, error) { return install.AgentJoinServer(sys, install.Config{}) }).Collect(context.Background())
		if rep.JoinTarget != "192.0.2.10:9345" {
			t.Fatalf("joinTarget = %q, want 192.0.2.10:9345", rep.JoinTarget)
		}
		if rep.Workers != nil {
			t.Errorf("an agent reports workers %+v", *rep.Workers)
		}
		raw := marshal(t, rep)
		var plist string
		for _, b := range sys.files {
			plist = string(b)
		}
		// The staged token path lives under the data root, so the data-root
		// canary is the token-file value.
		for _, canary := range []string{joinCanaryDataRoot, joinCanaryNodeIP, "argv-canary"} {
			if !strings.Contains(plist, canary) {
				t.Fatalf("the rendered agent plist does not carry %q, so its absence below proves nothing:\n%s", canary, plist)
			}
			if strings.Contains(raw, canary) {
				t.Errorf("the report leaks %q from the agent argv: %s", canary, raw)
			}
		}
	})

	t.Run("agent joinTarget brackets an IPv6 host", func(t *testing.T) {
		t.Parallel()
		sys := agentPlistSystem("2001:db8::10")
		rep := agent(t, func() (string, error) { return install.AgentJoinServer(sys, install.Config{}) }).Collect(context.Background())
		if rep.JoinTarget != "[2001:db8::10]:9345" {
			t.Fatalf("joinTarget = %q", rep.JoinTarget)
		}
	})

	for name, join := range map[string]func() (string, error){
		"no agent plist": func() (string, error) {
			return install.AgentJoinServer(plistFiles{files: map[string][]byte{}}, install.Config{})
		},
		"unreadable":                         func() (string, error) { return "", os.ErrPermission },
		"a host that already carries a port": func() (string, error) { return "192.0.2.10:6443", nil },
		"not a bare host":                    func() (string, error) { return "https://192.0.2.10", nil },
	} {
		t.Run("agent joinTarget is absent: "+name, func(t *testing.T) {
			t.Parallel()
			rep := agent(t, join).Collect(context.Background())
			if rep.JoinTarget != "" {
				t.Fatalf("joinTarget = %q, want absent", rep.JoinTarget)
			}
			if raw := marshal(t, rep); strings.Contains(raw, `"joinTarget"`) {
				t.Errorf("JSON carries joinTarget: %s", raw)
			}
		})
	}

	t.Run("a server never consults the join seam", func(t *testing.T) {
		t.Parallel()
		c := serverWith(t, healthyKube())
		c.AgentJoinServer = func() (string, error) { t.Error("join seam called on a server"); return "192.0.2.10", nil }
		if rep := c.Collect(context.Background()); rep.JoinTarget != "" {
			t.Fatalf("joinTarget = %q on a server", rep.JoinTarget)
		}
	})
}

func deref(w *[]Worker) any {
	if w == nil {
		return nil
	}
	return *w
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
