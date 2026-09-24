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

package executor

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestControllersFlagScoping asserts the KCM controller scoping: the flag is
// "*" (all on-by-default controllers) minus the node-side controllers that
// assume Linux kubelets/cloud providers, and the endpointslice-controller (which
// M1.4's Service proxy reconciles off) is NOT among the disabled set, so it stays
// on.
func TestControllersFlagScoping(t *testing.T) {
	flag := controllersFlag()
	tokens := strings.Split(flag, ",")

	if tokens[0] != "*" {
		t.Errorf("controllers flag must start with * (enable on-by-default), got %q", tokens[0])
	}
	disabled := map[string]bool{}
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			disabled[strings.TrimPrefix(tok, "-")] = true
		}
	}

	if disabled["endpointslice-controller"] {
		t.Error("endpointslice-controller must NOT be disabled (M1.4 Service proxy needs it)")
	}
	for _, dropped := range []string{
		"persistentvolume-attach-detach-controller",
		"cloud-node-lifecycle-controller",
		"node-route-controller",
		"service-lb-controller",
		"node-ipam-controller",
	} {
		if !disabled[dropped] {
			t.Errorf("node-side controller %q must be DISABLED, not found in %q", dropped, flag)
		}
	}
}

// TestPersistentVolumeControllersKept asserts the controllers the M3.2 local-path
// provisioner + StatefulSet binding depend on stay ENABLED in the scoped KCM
// --controllers set: the in-tree persistentvolume-binder (binds the PVC to the
// PV the provisioner creates), the statefulset controller (creates the
// per-replica PVCs + pods), and pvc/pv-protection (the in-use finalizers). The
// external-provisioner pattern + the scheduler VolumeBinding plugin rely on the
// in-tree binder, so a future tightening of kcmDisabledControllers that drops one
// would silently break binding — this is the tripwire.
func TestPersistentVolumeControllersKept(t *testing.T) {
	flag := controllersFlag()
	tokens := strings.Split(flag, ",")
	if tokens[0] != "*" {
		t.Fatalf("controllers flag must start with * (enable on-by-default), got %q", tokens[0])
	}
	disabled := map[string]bool{}
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			disabled[strings.TrimPrefix(tok, "-")] = true
		}
	}
	for _, keep := range []string{
		"persistentvolume-binder-controller",
		"statefulset-controller",
		"pvc-protection-controller",
		"pv-protection-controller",
	} {
		if disabled[keep] {
			t.Errorf("controller %q must stay ENABLED (M3.2 provisioner + StatefulSet binding needs it), found disabled in %q", keep, flag)
		}
	}
}

// kcmControllersGolden is the controller registry captured from the pinned
// kube-controller-manager binary (see the file's header for the capture command).
const kcmControllersGolden = "testdata/kcm-controllers-v1.36.2.txt"

// TestNodeFailureControllersKept is the B366 tripwire for the controllers that
// rescue a Pod from a failed node: node-lifecycle-controller (marks the node
// NotReady and taints it), taint-eviction-controller (evicts Pods off the
// NoExecute taint; its own registry entry at this minor), and
// pod-garbage-collector-controller (force-deletes Pods bound to a gone or
// out-of-service node). k3sm keeps them by the "*" wildcard, so a future
// tightening of kcmDisabledControllers that drops one would silently strand Pods
// on a dead node.
//
// The token names are pinned against the controller registry of Kubernetes
// v1.36.2, captured from the pinned binary with `kube-controller-manager --help`
// ("All controllers" and "Disabled-by-default controllers") into
// testdata/kcm-controllers-v1.36.2.txt. Asserting membership there is what keeps
// the absent-from-the-minus-set check from passing vacuously on a misspelled or
// renamed token, and asserting the token is not disabled-by-default is what makes
// "kept by the wildcard" true.
//
// NodeOutOfServiceVolumeDetach needs no pin here: its enforcement lives in the
// attach-detach controller, which k3sm deliberately disables (see
// kcmDisabledControllers); the end-to-end post-heal reaper flow is covered by its
// own item, not by this argv-level test.
func TestNodeFailureControllersKept(t *testing.T) {
	vals := flagValues(controllerManagerArgs(Config{}.withDefaults()), "--controllers")
	if len(vals) != 1 {
		t.Fatalf("--controllers must appear exactly once in the controller-manager argv (the last value wins), got %d: %q", len(vals), vals)
	}
	flag := vals[0]
	tokens := strings.Split(flag, ",")
	if tokens[0] != "*" {
		t.Fatalf("--controllers must start with * (enable on-by-default), got %q", flag)
	}
	disabled := map[string]bool{}
	for _, tok := range tokens[1:] {
		name, ok := strings.CutPrefix(tok, "-")
		if !ok {
			t.Fatalf("--controllers token %q after * is not a -<name> disable; rendered %q", tok, flag)
		}
		disabled[name] = true
	}

	raw, err := os.ReadFile(kcmControllersGolden)
	if err != nil {
		t.Fatalf("read controller registry golden: %v", err)
	}
	var header strings.Builder
	registry := map[string]bool{} // name -> on by default
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			header.WriteString(line + "\n")
		default:
			fields := strings.Fields(line)
			registry[fields[0]] = !(len(fields) > 1 && fields[1] == "disabled-by-default")
		}
	}
	for _, want := range []string{"`kube-controller-manager --help`", "v1.36.2"} {
		if !strings.Contains(header.String(), want) {
			t.Fatalf("%s header must name the capture provenance %q, got:\n%s", kcmControllersGolden, want, header.String())
		}
	}

	for _, tc := range []struct {
		name, why string
	}{
		{"node-lifecycle-controller", "it marks a failed node NotReady and applies the NoExecute taint"},
		{"taint-eviction-controller", "it evicts Pods off a NoExecute-tainted node"},
		{"pod-garbage-collector-controller", "it force-deletes Pods bound to a gone or out-of-service node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			onByDefault, known := registry[tc.name]
			if !known {
				t.Fatalf("controller %q is not in the v1.36.2 registry %s: the token is misspelled or renamed, so the kept check below would pass vacuously", tc.name, kcmControllersGolden)
			}
			if !onByDefault {
				t.Fatalf("controller %q is disabled-by-default at v1.36.2, so the * wildcard does not keep it", tc.name)
			}
			if disabled[tc.name] {
				t.Errorf("controller %q must stay ENABLED (%s), found disabled in --controllers %q", tc.name, tc.why, flag)
			}
		})
	}
}

// TestShutdownOrderKineLast verifies kine is stopped LAST (so no component loses
// its datastore mid-shutdown) and the apiserver drains before the controllers.
func TestShutdownOrderKineLast(t *testing.T) {
	// Start order as bringUp appends them.
	comps := []*component{
		{name: "kine"},
		{name: "kube-apiserver"},
		{name: "kube-scheduler"},
		{name: "kube-controller-manager"},
	}
	order := shutdownOrder(comps)
	if len(order) != 4 {
		t.Fatalf("want 4 components, got %d", len(order))
	}
	if order[len(order)-1].name != "kine" {
		t.Errorf("kine must be stopped LAST, got %q", order[len(order)-1].name)
	}
	if order[0].name != "kube-apiserver" {
		t.Errorf("apiserver must drain FIRST, got %q", order[0].name)
	}
}

// TestConfigDefaults checks the pinned defaults are applied (port 6444 not 6443).
func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.APIServerPort != 6444 {
		t.Errorf("APIServerPort = %d, want 6444 (Docker Desktop squats 6443)", c.APIServerPort)
	}
	if c.KinePort != DefaultKinePort {
		t.Errorf("KinePort = %d, want %d", c.KinePort, DefaultKinePort)
	}
	if c.KubeVersion != DefaultKubeVersion {
		t.Errorf("KubeVersion = %q, want %q", c.KubeVersion, DefaultKubeVersion)
	}
	if c.KineVersion != DefaultKineVersion {
		t.Errorf("KineVersion = %q, want %q", c.KineVersion, DefaultKineVersion)
	}
	if c.Logger == nil {
		t.Error("Logger must default to a non-nil discard logger")
	}
}

// TestEmbeddedNotImplemented confirms the Embedded strategy is a stub that
// reports the deferred-milestone sentinel (from-source in-process embedding).
func TestEmbeddedNotImplemented(t *testing.T) {
	e := NewEmbedded(Config{})
	if err := e.Start(context.Background()); err != ErrEmbeddedNotImplemented {
		t.Errorf("Embedded.Start err = %v, want ErrEmbeddedNotImplemented", err)
	}
	if e.Ready(context.Background()) {
		t.Error("Embedded.Ready should be false (nothing starts)")
	}
}

// TestSupervisedPathsLayout checks the workdir layout helpers produce the
// expected on-disk structure (the kubeconfig and kine DB live where the gate
// scripts expect them).
func TestSupervisedPathsLayout(t *testing.T) {
	wd := "/var/lib/k3sm/server"
	if got := kubeconfigPath(wd); !strings.HasSuffix(got, "/k3sm.kubeconfig") {
		t.Errorf("kubeconfig path = %q", got)
	}
	if got := binDir(wd); got != wd+"/bin" {
		t.Errorf("bin dir = %q", got)
	}
	if got := apiServerURL(Config{APIServerPort: 6444}); got != "https://127.0.0.1:6444" {
		t.Errorf("apiserver url = %q", got)
	}
}
