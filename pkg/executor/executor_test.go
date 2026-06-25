package executor

import (
	"context"
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
	if got := apiServerURL(6444); got != "https://127.0.0.1:6444" {
		t.Errorf("apiserver url = %q", got)
	}
}
