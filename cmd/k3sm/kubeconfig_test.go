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
	"strings"
	"testing"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// k3smSrc mirrors the admin kubeconfig the executor writes: one cluster
// ("k3sm", loopback, insecure-skip), one user ("admin", bearer token), one
// context ("k3sm").
func k3smSrc() *clientcmdapi.Config {
	c := clientcmdapi.NewConfig()
	c.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://127.0.0.1:6444", InsecureSkipTLSVerify: true}
	c.AuthInfos["admin"] = &clientcmdapi.AuthInfo{Token: "k3sm-deadbeef"}
	c.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "admin"}
	c.CurrentContext = "k3sm"
	return c
}

func TestMergeKubeconfig(t *testing.T) {
	tests := []struct {
		name        string
		dst         func() *clientcmdapi.Config
		mergeName   string
		setCurrent  bool
		wantCurrent string
		wantCtxKeys []string
	}{
		{
			name:        "into empty config",
			dst:         clientcmdapi.NewConfig,
			mergeName:   "k3sm",
			setCurrent:  true,
			wantCurrent: "k3sm",
			wantCtxKeys: []string{"k3sm"},
		},
		{
			name: "preserves existing entries; setCurrent=false leaves current",
			dst: func() *clientcmdapi.Config {
				c := clientcmdapi.NewConfig()
				c.Clusters["prod"] = &clientcmdapi.Cluster{Server: "https://prod:6443"}
				c.AuthInfos["prod"] = &clientcmdapi.AuthInfo{Token: "p"}
				c.Contexts["prod"] = &clientcmdapi.Context{Cluster: "prod", AuthInfo: "prod"}
				c.CurrentContext = "prod"
				return c
			},
			mergeName:   "k3sm",
			setCurrent:  false,
			wantCurrent: "prod",
			wantCtxKeys: []string{"prod", "k3sm"},
		},
		{
			name: "custom name avoids collision with an existing k3sm context",
			dst: func() *clientcmdapi.Config {
				c := clientcmdapi.NewConfig()
				c.Clusters["other"] = &clientcmdapi.Cluster{Server: "https://other"}
				c.AuthInfos["other"] = &clientcmdapi.AuthInfo{}
				c.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "other", AuthInfo: "other"}
				return c
			},
			mergeName:   "k3sm-dev",
			setCurrent:  true,
			wantCurrent: "k3sm-dev",
			wantCtxKeys: []string{"k3sm", "k3sm-dev"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeKubeconfig(tt.dst(), k3smSrc(), tt.mergeName, tt.setCurrent)
			if err != nil {
				t.Fatalf("mergeKubeconfig: %v", err)
			}
			if got.CurrentContext != tt.wantCurrent {
				t.Errorf("current-context = %q, want %q", got.CurrentContext, tt.wantCurrent)
			}
			for _, k := range tt.wantCtxKeys {
				if _, ok := got.Contexts[k]; !ok {
					t.Errorf("missing context %q", k)
				}
			}
			c := got.Contexts[tt.mergeName]
			if c == nil {
				t.Fatalf("merged context %q absent", tt.mergeName)
			}
			if c.Cluster != tt.mergeName || c.AuthInfo != tt.mergeName {
				t.Errorf("merged context refs = (%q,%q), want (%q,%q)", c.Cluster, c.AuthInfo, tt.mergeName, tt.mergeName)
			}
			if _, ok := got.Clusters[tt.mergeName]; !ok {
				t.Errorf("merged cluster %q absent", tt.mergeName)
			}
			if _, ok := got.AuthInfos[tt.mergeName]; !ok {
				t.Errorf("merged authinfo %q absent", tt.mergeName)
			}
		})
	}
}

func TestRetargetRefusesInsecureOffLoopback(t *testing.T) {
	if err := retarget(k3smSrc(), "https://mac.local:6444", ""); err == nil {
		t.Fatal("expected refusal for a non-loopback server with no CA")
	}
}

func TestRetargetLoopbackKeepsInsecure(t *testing.T) {
	src := k3smSrc()
	if err := retarget(src, "https://127.0.0.1:7000", ""); err != nil {
		t.Fatalf("loopback retarget should succeed: %v", err)
	}
	if got := soleCluster(src).Server; got != "https://127.0.0.1:7000" {
		t.Errorf("server = %q, want retargeted", got)
	}
}

func TestIsLoopbackServer(t *testing.T) {
	for s, want := range map[string]bool{
		"https://127.0.0.1:6444": true,
		"https://localhost:6444": true,
		"https://[::1]:6444":     true,
		"https://mac.local:6444": false,
		"https://10.0.0.5:6444":  false,
	} {
		if got := isLoopbackServer(s); got != want {
			t.Errorf("isLoopbackServer(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestExtractContext(t *testing.T) {
	// A user's own kubeconfig: the merged k3sm entries plus an unrelated cluster.
	userCfg := func() *clientcmdapi.Config {
		c := clientcmdapi.NewConfig()
		c.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://127.0.0.1:6444", InsecureSkipTLSVerify: true}
		c.AuthInfos["k3sm"] = &clientcmdapi.AuthInfo{Token: "k3sm-deadbeef"}
		c.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "k3sm"}
		c.Clusters["prod"] = &clientcmdapi.Cluster{Server: "https://prod:6443"}
		c.AuthInfos["prod"] = &clientcmdapi.AuthInfo{Token: "p"}
		c.Contexts["prod"] = &clientcmdapi.Context{Cluster: "prod", AuthInfo: "prod"}
		c.CurrentContext = "prod"
		return c
	}

	t.Run("takes only the named context and what it references", func(t *testing.T) {
		got, err := extractContext(userCfg(), "k3sm")
		if err != nil {
			t.Fatalf("extractContext: %v", err)
		}
		if got.CurrentContext != "k3sm" {
			t.Errorf("current-context = %q, want %q", got.CurrentContext, "k3sm")
		}
		if len(got.Contexts) != 1 || len(got.Clusters) != 1 || len(got.AuthInfos) != 1 {
			t.Fatalf("extracted %d contexts / %d clusters / %d users, want 1 of each",
				len(got.Contexts), len(got.Clusters), len(got.AuthInfos))
		}
		if cl := got.Clusters["k3sm"]; cl == nil || cl.Server != "https://127.0.0.1:6444" {
			t.Errorf("cluster = %+v, want the k3sm loopback server", cl)
		}
		if u := got.AuthInfos["k3sm"]; u == nil || u.Token != "k3sm-deadbeef" {
			t.Errorf("user = %+v, want the k3sm token", u)
		}
		// It must be a copy: mutating the result cannot touch the caller's config.
		src := userCfg()
		out, err := extractContext(src, "k3sm")
		if err != nil {
			t.Fatalf("extractContext: %v", err)
		}
		out.Clusters["k3sm"].Server = "https://elsewhere"
		if src.Clusters["k3sm"].Server != "https://127.0.0.1:6444" {
			t.Error("extractContext aliased the source cluster instead of copying it")
		}
	})

	for _, tt := range []struct {
		name    string
		cfg     func() *clientcmdapi.Config
		lookup  string
		wantErr string
	}{
		{
			name:    "context absent",
			cfg:     userCfg,
			lookup:  "k3sm-dev",
			wantErr: `no context "k3sm-dev" in your kubeconfig`,
		},
		{
			name: "cluster the context names is missing",
			cfg: func() *clientcmdapi.Config {
				c := userCfg()
				delete(c.Clusters, "k3sm")
				return c
			},
			lookup:  "k3sm",
			wantErr: `names cluster "k3sm"`,
		},
		{
			name: "user the context names is missing",
			cfg: func() *clientcmdapi.Config {
				c := userCfg()
				delete(c.AuthInfos, "k3sm")
				return c
			},
			lookup:  "k3sm",
			wantErr: `names user "k3sm"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractContext(tt.cfg(), tt.lookup)
			if err == nil {
				t.Fatalf("extractContext = %+v, want an error containing %q", got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
