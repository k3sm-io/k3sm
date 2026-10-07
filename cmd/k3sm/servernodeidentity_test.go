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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	stdmaps "maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

// TestServerNodeClientIsSystemNodeIdentity pins the server node's client identity:
// from an admin config carrying every kind of credential client-go knows, the
// result carries ONLY a freshly minted CN=system:node:<name>, O=system:nodes cert
// chaining to the signing CA, keeps the apiserver address and server trust, paces
// itself like any node, and leaves the CA hierarchy untouched. A hierarchy that
// cannot sign is an error, never a fallback to the admin identity.
func TestServerNodeClientIsSystemNodeIdentity(t *testing.T) {
	wd := t.TempDir()
	h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	clusterPin, signingPin := h.Cluster.PinHash(), h.Signing.PinHash()
	diskCluster, diskSigning, err := certs.LoadCAPins(wd)
	if err != nil {
		t.Fatalf("LoadCAPins: %v", err)
	}

	admin := func() *rest.Config {
		return &rest.Config{
			Host:            "https://127.0.0.1:6444",
			BearerToken:     "admin-static-token",
			BearerTokenFile: filepath.Join(wd, "admin.token"),
			Username:        "admin",
			Password:        "admin-password",
			ExecProvider:    &clientcmdapi.ExecConfig{Command: "/usr/bin/false", APIVersion: "client.authentication.k8s.io/v1"},
			AuthProvider:    &clientcmdapi.AuthProviderConfig{Name: "oidc"},
			Impersonate:     rest.ImpersonationConfig{UserName: "system:admin", Groups: []string{"system:masters"}},
			TLSClientConfig: rest.TLSClientConfig{
				ServerName: "kubernetes",
				CAData:     h.Cluster.CertPEM,
				CertFile:   filepath.Join(wd, "admin.crt"),
				KeyFile:    filepath.Join(wd, "admin.key"),
				CertData:   []byte("admin-cert"),
				KeyData:    []byte("admin-key"),
			},
		}
	}
	src := admin()
	const node = "k3sm-server-node"
	cfg, err := serverNodeRESTConfig(src, h, node)
	if err != nil {
		t.Fatalf("serverNodeRESTConfig: %v", err)
	}

	t.Run("carries only the minted node identity", func(t *testing.T) {
		if cfg.BearerToken != "" || cfg.BearerTokenFile != "" {
			t.Errorf("bearer token %q / token file %q survived; the admin token must not ride along", cfg.BearerToken, cfg.BearerTokenFile)
		}
		if cfg.Username != "" || cfg.Password != "" {
			t.Errorf("basic auth survived (%q)", cfg.Username)
		}
		if cfg.ExecProvider != nil || cfg.AuthProvider != nil {
			t.Error("an exec or auth provider survived")
		}
		if cfg.Impersonate.UserName != "" || len(cfg.Impersonate.Groups) != 0 {
			t.Errorf("impersonation survived: %+v", cfg.Impersonate)
		}
		if cfg.CertFile != "" || cfg.KeyFile != "" {
			t.Errorf("admin cert/key files survived: %q %q", cfg.CertFile, cfg.KeyFile)
		}
		if _, err := tls.X509KeyPair(cfg.CertData, cfg.KeyData); err != nil {
			t.Fatalf("the minted cert and key are not a pair: %v", err)
		}
	})

	t.Run("CN=system:node:<name> O=system:nodes, signed by the signing CA", func(t *testing.T) {
		block, _ := pem.Decode(cfg.CertData)
		if block == nil {
			t.Fatal("no PEM certificate in CertData")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		if got, want := leaf.Subject.CommonName, "system:node:"+node; got != want {
			t.Errorf("CN = %q, want %q (the CN must equal the registered node name)", got, want)
		}
		if !slices.Equal(leaf.Subject.Organization, []string{"system:nodes"}) {
			t.Errorf("O = %v, want [system:nodes]", leaf.Subject.Organization)
		}
		signing := x509.NewCertPool()
		signing.AddCert(h.Signing.Cert)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: signing, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("the leaf does not verify as a client cert against the signing CA: %v", err)
		}
		cluster := x509.NewCertPool()
		cluster.AddCert(h.Cluster.Cert)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: cluster, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			t.Error("the leaf verifies against the CLUSTER CA; client identities come from the signing CA only")
		}
		if life := leaf.NotAfter.Sub(leaf.NotBefore); life > executor.ComponentCertValidity+2*time.Hour || life < executor.ComponentCertValidity-2*time.Hour {
			t.Errorf("lifetime %s, want about %s (the per-boot component leaves' validity)", life, executor.ComponentCertValidity)
		}
	})

	t.Run("keeps the apiserver address and server trust; node budget", func(t *testing.T) {
		if cfg.Host != src.Host || cfg.ServerName != src.ServerName || string(cfg.CAData) != string(src.CAData) {
			t.Errorf("server half not kept: host=%q serverName=%q", cfg.Host, cfg.ServerName)
		}
		if cfg.Timeout != nodeAPIRequestTimeout || cfg.QPS != 50 || cfg.Burst != 100 || cfg.RateLimiter != nil {
			t.Errorf("budget = timeout %s qps %v burst %d limiter %v, want the node's %s/50/100/nil", cfg.Timeout, cfg.QPS, cfg.Burst, cfg.RateLimiter, nodeAPIRequestTimeout)
		}
		if src.BearerToken != "admin-static-token" || string(src.CertData) != "admin-cert" {
			t.Error("the admin config was mutated; the node config must be a copy")
		}
	})

	t.Run("the CA hierarchy is untouched", func(t *testing.T) {
		if h.Cluster.PinHash() != clusterPin || h.Signing.PinHash() != signingPin {
			t.Error("a CA pin moved in memory across the mint")
		}
		gotCluster, gotSigning, err := certs.LoadCAPins(wd)
		if err != nil {
			t.Fatalf("LoadCAPins after: %v", err)
		}
		if gotCluster != diskCluster || gotSigning != diskSigning || gotCluster != clusterPin || gotSigning != signingPin {
			t.Error("a CA pin moved on disk across the mint; the mint must re-use the hierarchy, never re-create it")
		}
	})

	t.Run("fails closed without a usable signing CA", func(t *testing.T) {
		noKey := &certs.Hierarchy{Cluster: h.Cluster, Signing: &certs.CA{Cert: h.Signing.Cert, CertPEM: h.Signing.CertPEM}}
		noCert := &certs.Hierarchy{Cluster: h.Cluster, Signing: &certs.CA{Key: h.Signing.Key, KeyPEM: h.Signing.KeyPEM}}
		for name, tc := range map[string]struct {
			admin *rest.Config
			h     *certs.Hierarchy
			node  string
		}{
			"nil hierarchy":           {admin(), nil, node},
			"no signing CA":           {admin(), &certs.Hierarchy{Cluster: h.Cluster}, node},
			"signing CA without key":  {admin(), noKey, node},
			"signing CA without cert": {admin(), noCert, node},
			"nil admin config":        {nil, h, node},
			"empty node name":         {admin(), h, ""},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := serverNodeRESTConfig(tc.admin, tc.h, tc.node)
				if err == nil {
					t.Fatalf("want an error, got a config (bearer %q)", got.BearerToken)
				}
				if got != nil {
					t.Error("a config was returned alongside the error")
				}
			})
		}
	})
}

// TestStartNodeUsesRestConfigExclusively pins the seam the server node's identity
// flows through: nodeClientConfig hands back an in-memory config as given and then
// never reads a kubeconfig, refuses both-set and neither-set, and runServer's node
// options carry the config serverNodeRESTConfig minted and no kubeconfig path.
func TestStartNodeUsesRestConfigExclusively(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.kubeconfig")
	mem := &rest.Config{Host: "https://127.0.0.1:6444"}

	t.Run("restConfig is used as given", func(t *testing.T) {
		got, err := nodeClientConfig(nodeOptions{restConfig: mem})
		if err != nil {
			t.Fatalf("nodeClientConfig: %v", err)
		}
		if got != mem {
			t.Error("nodeClientConfig did not return the in-memory config it was given")
		}
	})
	t.Run("both set is an error, and the kubeconfig is never opened", func(t *testing.T) {
		_, err := nodeClientConfig(nodeOptions{restConfig: mem, kubeconfig: missing})
		if !errors.Is(err, errNodeClientAmbiguous) {
			t.Fatalf("err = %v, want errNodeClientAmbiguous", err)
		}
		if strings.Contains(err.Error(), "load kubeconfig") {
			t.Errorf("the kubeconfig path was opened: %v", err)
		}
	})
	t.Run("neither set is an error", func(t *testing.T) {
		if _, err := nodeClientConfig(nodeOptions{}); !errors.Is(err, errNodeClientMissing) {
			t.Fatalf("err = %v, want errNodeClientMissing", err)
		}
	})
	t.Run("a kubeconfig path is loaded (the agent and k3sm node path)", func(t *testing.T) {
		_, err := nodeClientConfig(nodeOptions{kubeconfig: missing})
		if err == nil || !strings.Contains(err.Error(), "load kubeconfig") {
			t.Fatalf("err = %v, want a load kubeconfig error for a nonexistent path", err)
		}
	})

	t.Run("runServer wires the minted config and no kubeconfig", func(t *testing.T) {
		assertServerNodeOptionsWiring(t, runServerTrace(t))
	})
}

// assertServerNodeOptionsWiring checks, in runServer's trace, that the nodeOptions
// literal handed to startNode sets restConfig to a variable assigned from
// serverNodeRESTConfig(…, opts.nodeName), sets nodeName from the same opts.nodeName
// (the CN equals the registered name), and that no nodeOptions literal and no
// assignment in runServer sets a kubeconfig. It fails when no literal is found, so
// a refactor cannot turn it vacuous.
func assertServerNodeOptionsWiring(t *testing.T, tr *serverTrace) {
	t.Helper()
	isOptsNodeName := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "nodeName" {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		return ok && x.Name == "opts"
	}

	literals := 0
	var nodeOptsVar, restVar string
	var restLit *ast.CompositeLit
	mintedFrom := map[string]*ast.CallExpr{}
	var startNodeArg string
	tr.inspect(func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if id, ok := n.Type.(*ast.Ident); !ok || id.Name != "nodeOptions" {
				return true
			}
			literals++
			for _, elt := range n.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "kubeconfig":
					t.Errorf("a nodeOptions literal in runServer sets kubeconfig; the server node must run on its minted identity only")
				case "restConfig":
					if restLit != nil {
						t.Errorf("more than one nodeOptions literal in runServer sets restConfig")
					}
					restLit = n
					if id, ok := kv.Value.(*ast.Ident); ok {
						restVar = id.Name
					} else {
						t.Errorf("restConfig is not set from a variable assigned by serverNodeRESTConfig")
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && (sel.Sel.Name == "kubeconfig" || sel.Sel.Name == "restConfig") {
					t.Errorf("runServer assigns .%s after the literal; the node options' client must be set in one place", sel.Sel.Name)
				}
			}
			if len(n.Rhs) == 1 {
				if call, ok := n.Rhs[0].(*ast.CallExpr); ok {
					if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "serverNodeRESTConfig" {
						if id, ok := n.Lhs[0].(*ast.Ident); ok {
							mintedFrom[id.Name] = call
						}
					}
				}
				if lit, ok := n.Rhs[0].(*ast.CompositeLit); ok {
					if id, ok := lit.Type.(*ast.Ident); ok && id.Name == "nodeOptions" {
						for _, elt := range lit.Elts {
							if kv, ok := elt.(*ast.KeyValueExpr); ok {
								if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "restConfig" {
									if lhs, ok := n.Lhs[0].(*ast.Ident); ok {
										nodeOptsVar = lhs.Name
									}
								}
							}
						}
					}
				}
			}
		case *ast.CallExpr:
			if fn, ok := n.Fun.(*ast.Ident); ok && fn.Name == "startNode" && len(n.Args) == 2 {
				if id, ok := n.Args[1].(*ast.Ident); ok {
					startNodeArg = id.Name
				}
			}
		}
		return true
	})

	if literals == 0 {
		t.Fatal("runServer contains no nodeOptions literal; this check would be vacuous")
	}
	if restLit == nil {
		t.Fatal("no nodeOptions literal in runServer sets restConfig")
	}
	call, ok := mintedFrom[restVar]
	if !ok {
		t.Fatalf("restConfig is set from %q, which runServer does not assign from serverNodeRESTConfig", restVar)
	}
	if len(call.Args) != 3 || !isOptsNodeName(call.Args[2]) {
		t.Error("serverNodeRESTConfig is not called with opts.nodeName as the node name")
	}
	nameOK := false
	for _, elt := range restLit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "nodeName" && isOptsNodeName(kv.Value) {
				nameOK = true
			}
		}
	}
	if !nameOK {
		t.Error("the node options' nodeName is not opts.nodeName, so the minted CN and the registered node name could differ")
	}
	if nodeOptsVar == "" || startNodeArg == "" {
		t.Fatalf("startNode is called with %q and the minted literal is assigned to %q; the dataflow between them is unassertable", startNodeArg, nodeOptsVar)
	}
	if err := nodeOptsReachStartNode(tr, restLit, nodeOptsVar, startNodeArg); err != nil {
		t.Errorf("startNode is not handed the nodeOptions literal that carries the minted identity: %v", err)
	}
}

// nodeOptsReachStartNode follows the minted nodeOptions literal to startNode by
// DATAFLOW, not by a shared variable name. The literal is assigned to litVar in
// some function F. If F is runServer itself, startNode must be called with litVar.
// Otherwise F must be a helper runServer calls directly: litVar is assigned once in
// F and is the first result of every successful (`…, nil`) return in F, and
// runServer assigns argVar exactly once, as the first result of a call to F, and
// passes argVar to startNode.
func nodeOptsReachStartNode(tr *serverTrace, lit *ast.CompositeLit, litVar, argVar string) error {
	var fn *ast.FuncDecl
	for _, f := range tr.funcs {
		if f.Body.Pos() <= lit.Pos() && lit.End() <= f.Body.End() {
			fn = f
		}
	}
	if fn == nil {
		return fmt.Errorf("the literal at %s sits in no server*.go function", tr.where(lit))
	}
	if fn == tr.decl {
		if litVar != argVar {
			return fmt.Errorf("runServer builds %q but calls startNode with %q", litVar, argVar)
		}
		return nil
	}
	// assignsOutsideClosures lists the assignments to name in body, closures excluded.
	assigns := func(body *ast.BlockStmt, name string) []*ast.AssignStmt {
		var out []*ast.AssignStmt
		ast.Inspect(body, func(n ast.Node) bool {
			if _, isLit := n.(*ast.FuncLit); isLit {
				return false
			}
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
						out = append(out, as)
					}
				}
			}
			return true
		})
		return out
	}
	if n := len(assigns(fn.Body, litVar)); n != 1 {
		return fmt.Errorf("%s assigns %q %d times, want exactly once (the minted literal)", fn.Name.Name, litVar, n)
	}
	successes := 0
	var bad error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		if last, ok := ret.Results[len(ret.Results)-1].(*ast.Ident); !ok || last.Name != "nil" {
			return true
		}
		successes++
		if id, ok := ret.Results[0].(*ast.Ident); !ok || id.Name != litVar {
			bad = fmt.Errorf("%s's successful return at %s does not return %q, the minted literal", fn.Name.Name, tr.where(ret), litVar)
		}
		return true
	})
	if bad != nil {
		return bad
	}
	if successes == 0 {
		return fmt.Errorf("%s has no successful return of %q", fn.Name.Name, litVar)
	}
	argAssigns := assigns(tr.decl.Body, argVar)
	if len(argAssigns) != 1 {
		return fmt.Errorf("runServer assigns %q %d times, want exactly once (from %s)", argVar, len(argAssigns), fn.Name.Name)
	}
	as := argAssigns[0]
	if id, ok := as.Lhs[0].(*ast.Ident); !ok || id.Name != argVar || len(as.Rhs) != 1 {
		return fmt.Errorf("runServer's %q is not the first result of a single call at %s", argVar, tr.where(as))
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return fmt.Errorf("runServer's %q at %s is not a call result", argVar, tr.where(as))
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != fn.Name.Name {
		return fmt.Errorf("runServer's %q at %s is not the result of %s, which builds the minted literal", argVar, tr.where(as), fn.Name.Name)
	}
	return nil
}

// TestStripStaleNodeRoleLabel pins the upgrade repair: a kubernetes.io/role label
// the node recorded in its Virtual Kubelet last-applied annotation is removed from
// both the annotation and the live labels, through the admin client, while every
// other label (an operator's control-plane label included) and annotation field
// survives; an operator's live-only role label, a Node with nothing stale, and a
// Node that does not exist yet are all left alone.
func TestStripStaleNodeRoleLabel(t *testing.T) {
	const name = "k3sm-server-node"
	lastApplied := func(labels map[string]string) string {
		b, err := json.Marshal(map[string]any{"name": name, "labels": labels, "annotations": map[string]string{"keep": "me"}})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	node := func(live map[string]string, ann string) *corev1.Node {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: live, Annotations: map[string]string{"other": "x"}}}
		if ann != "" {
			n.Annotations[vkLastAppliedObjectMetaAnnotation] = ann
		}
		return n
	}
	for _, tc := range []struct {
		name        string
		objs        []runtime.Object
		wantChanged bool
		wantLive    map[string]string
		wantApplied map[string]string // nil: annotation must be unchanged
	}{
		{
			name: "stale in both: stripped from both, the rest kept",
			objs: []runtime.Object{node(
				map[string]string{staleNodeRoleLabel: "agent", "node-role.kubernetes.io/control-plane": "", "kubernetes.io/os": "darwin"},
				lastApplied(map[string]string{staleNodeRoleLabel: "agent", "kubernetes.io/os": "darwin"}))},
			wantChanged: true,
			wantLive:    map[string]string{"node-role.kubernetes.io/control-plane": "", "kubernetes.io/os": "darwin"},
			wantApplied: map[string]string{"kubernetes.io/os": "darwin"},
		},
		{
			name:        "operator's live-only role label: untouched",
			objs:        []runtime.Object{node(map[string]string{staleNodeRoleLabel: "edge"}, lastApplied(map[string]string{"kubernetes.io/os": "darwin"}))},
			wantChanged: false,
			wantLive:    map[string]string{staleNodeRoleLabel: "edge"},
		},
		{
			name:        "nothing stale: no write",
			objs:        []runtime.Object{node(map[string]string{"kubernetes.io/os": "darwin"}, lastApplied(map[string]string{"kubernetes.io/os": "darwin"}))},
			wantChanged: false,
			wantLive:    map[string]string{"kubernetes.io/os": "darwin"},
		},
		{
			name:        "no node yet (first boot): no error, no write",
			wantChanged: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(tc.objs...)
			changed, err := stripStaleNodeRoleLabel(context.Background(), cs.CoreV1().Nodes(), name)
			if err != nil {
				t.Fatalf("stripStaleNodeRoleLabel: %v", err)
			}
			if changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			updates := 0
			for _, a := range cs.Actions() {
				if a.GetVerb() == "update" {
					updates++
				}
			}
			if want := map[bool]int{true: 1, false: 0}[tc.wantChanged]; updates != want {
				t.Errorf("%d updates, want %d", updates, want)
			}
			if len(tc.objs) == 0 {
				return
			}
			n, err := cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !stdmaps.Equal(n.Labels, tc.wantLive) {
				t.Errorf("live labels = %v, want %v", n.Labels, tc.wantLive)
			}
			if n.Annotations["other"] != "x" {
				t.Error("an unrelated annotation was lost")
			}
			var meta struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			}
			if err := json.Unmarshal([]byte(n.Annotations[vkLastAppliedObjectMetaAnnotation]), &meta); err != nil {
				t.Fatalf("parse annotation: %v", err)
			}
			if tc.wantApplied != nil && !stdmaps.Equal(meta.Labels, tc.wantApplied) {
				t.Errorf("last-applied labels = %v, want %v", meta.Labels, tc.wantApplied)
			}
			if meta.Annotations["keep"] != "me" {
				t.Error("a field inside the last-applied annotation was lost")
			}
		})
	}
}
