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
	"crypto/tls"
	"go/ast"
	"slices"
	"testing"

	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/nodecred"
)

// TestServerNetserveRunsAsNetserveIdentity pins, in runServer's source, the
// identities the server's datapath runs under. Its watchers (the Service proxy,
// the DNS zone, the NetworkPolicy watcher) run as this node's netserve identity,
// which pkg/rbac's k3sm:netserve role grants exactly their cluster-wide reads;
// only the kube-dns Service create rides the admin client. So the netserve.Config
// literal must:
//   - set EnforceNetworkPolicy: true and leave PodScopeNode unset;
//   - set Client from a variable assigned exactly once, as the first result of
//     serverNetserveClient (the in-memory netserve mint);
//   - set DNSServiceClient from a variable assigned exactly once, as the second
//     result of kubeclient.FromPath(exec.Kubeconfig()) (the admin kubeconfig).
//
// A Client swapped back to the admin identity would pass every functional test
// and silently hold system:masters again; a DNSServiceClient on the netserve
// identity would be refused its create on every start.
func TestServerNetserveRunsAsNetserveIdentity(t *testing.T) {
	tr := runServerTrace(t)

	var lit *ast.CompositeLit
	tr.inspect(func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "netserve", "New") || len(call.Args) != 1 {
			return true
		}
		cl, ok := call.Args[0].(*ast.CompositeLit)
		if !ok || !isSelector(cl.Type, "netserve", "Config") {
			t.Errorf("netserve.New in runServer is not called with a netserve.Config literal")
			return true
		}
		if lit != nil {
			t.Errorf("runServer calls netserve.New more than once")
		}
		lit = cl
		return true
	})
	if lit == nil {
		t.Fatal("runServer contains no netserve.New(netserve.Config{...}) call; this check would be vacuous")
	}

	var clientVar, dnsVar string
	enforce := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Client", "DNSServiceClient":
			id, ok := kv.Value.(*ast.Ident)
			if !ok {
				t.Fatalf("netserve.Config.%s is not a plain variable", key.Name)
			}
			if key.Name == "Client" {
				clientVar = id.Name
			} else {
				dnsVar = id.Name
			}
		case "EnforceNetworkPolicy":
			id, ok := kv.Value.(*ast.Ident)
			enforce = ok && id.Name == "true"
		case "PodScopeNode":
			t.Error("the server's netserve.Config sets PodScopeNode; the netserve identity watches every pod")
		}
	}
	if !enforce {
		t.Error("the server's netserve.Config does not set EnforceNetworkPolicy: true; NetworkPolicy would not be enforced on the server's pods")
	}
	if clientVar == "" || dnsVar == "" {
		t.Fatalf("the server's netserve.Config sets Client %q and DNSServiceClient %q; both are required", clientVar, dnsVar)
	}
	if clientVar == dnsVar {
		t.Fatalf("Client and DNSServiceClient are the same variable %q; the datapath must not run as the admin identity", clientVar)
	}

	// origin reports how many times name is assigned in runServer's trace and
	// whether one assignment takes result index idx of a call matching match.
	origin := func(name string, idx int, match func(*ast.CallExpr) bool) (int, bool) {
		assigns, from := 0, false
		tr.inspect(func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range as.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != name {
					continue
				}
				assigns++
				if i != idx || len(as.Rhs) != 1 {
					continue
				}
				if call, ok := as.Rhs[0].(*ast.CallExpr); ok && match(call) {
					from = true
				}
			}
			return true
		})
		return assigns, from
	}

	assigns, fromNetserve := origin(clientVar, 0, func(call *ast.CallExpr) bool {
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == "serverNetserveClient"
	})
	if assigns != 1 || !fromNetserve {
		t.Errorf("%s, the server datapath's Client, is assigned %d times and from serverNetserveClient=%v; want exactly once, from the netserve mint", clientVar, assigns, fromNetserve)
	}
	assigns, fromAdmin := origin(dnsVar, 1, func(call *ast.CallExpr) bool {
		if !isSelector(call.Fun, "kubeclient", "FromPath") || len(call.Args) != 1 {
			return false
		}
		arg, ok := call.Args[0].(*ast.CallExpr)
		return ok && isSelector(arg.Fun, "exec", "Kubeconfig") && len(arg.Args) == 0
	})
	if assigns != 1 || !fromAdmin {
		t.Errorf("%s, the server datapath's DNSServiceClient, is assigned %d times and from the admin kubeconfig=%v; want exactly once, as the second result of kubeclient.FromPath(exec.Kubeconfig())", dnsVar, assigns, fromAdmin)
	}
}

// TestServerNetserveClientIsNetserveIdentity pins the server datapath's minted
// identity: from an admin config carrying a bearer token and a client pair, the
// result carries ONLY a CN=k3sm:netserve:<node>, O=k3sm:netservers client cert
// from the signing CA, keeps the apiserver address and its trust, and fails
// closed without a usable signing CA.
func TestServerNetserveClientIsNetserveIdentity(t *testing.T) {
	wd := t.TempDir()
	h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	admin := func() *rest.Config {
		return &rest.Config{
			Host:        "https://127.0.0.1:6444",
			BearerToken: "admin-static-token",
			Impersonate: rest.ImpersonationConfig{UserName: "system:admin", Groups: []string{"system:masters"}},
			TLSClientConfig: rest.TLSClientConfig{
				ServerName: "kubernetes",
				CAData:     h.Cluster.CertPEM,
				CertData:   []byte("admin-cert"),
				KeyData:    []byte("admin-key"),
			},
		}
	}
	const node = "k3sm-server-node"
	cfg, err := serverNetserveRESTConfig(admin(), h, node)
	if err != nil {
		t.Fatalf("serverNetserveRESTConfig: %v", err)
	}
	if cfg.BearerToken != "" || cfg.Impersonate.UserName != "" || len(cfg.Impersonate.Groups) != 0 {
		t.Errorf("an admin credential survived: bearer %q, impersonate %+v", cfg.BearerToken, cfg.Impersonate)
	}
	if cfg.Host != "https://127.0.0.1:6444" || cfg.ServerName != "kubernetes" || string(cfg.CAData) != string(h.Cluster.CertPEM) {
		t.Errorf("server half not kept: host=%q serverName=%q", cfg.Host, cfg.ServerName)
	}
	if err := bootstrap.CheckNetserveKeyPair(cfg.CertData, cfg.KeyData, node); err != nil {
		t.Fatalf("the minted pair is not this node's netserve identity: %v", err)
	}
	pair, err := tls.X509KeyPair(cfg.CertData, cfg.KeyData)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	leaf, err := nodecred.DecodeCertPEM(cfg.CertData)
	if err != nil || len(pair.Certificate) == 0 {
		t.Fatalf("decode leaf: %v", err)
	}
	if leaf.Subject.CommonName != certs.NetserveUserPrefix+node || !slices.Equal(leaf.Subject.Organization, []string{certs.NetserveGroup}) {
		t.Errorf("subject = CN %q O %v, want CN %q O [%s]", leaf.Subject.CommonName, leaf.Subject.Organization, certs.NetserveUserPrefix+node, certs.NetserveGroup)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("the netserve leaf is not signed by the signing CA: %v", err)
	}

	for name, tc := range map[string]struct {
		admin *rest.Config
		h     *certs.Hierarchy
		node  string
	}{
		"nil hierarchy":    {admin(), nil, node},
		"no signing CA":    {admin(), &certs.Hierarchy{Cluster: h.Cluster}, node},
		"nil admin config": {nil, h, node},
		"empty node name":  {admin(), h, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := serverNetserveRESTConfig(tc.admin, tc.h, tc.node); err == nil || got != nil {
				t.Fatalf("want an error and no config, got %v / %v", got, err)
			}
		})
	}
}

// isSelector reports whether e is the qualified selector pkg.name.
func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg
}
