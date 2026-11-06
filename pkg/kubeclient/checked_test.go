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

package kubeclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// writeCheckedFixture writes a kubeconfig whose current context names the
// cluster and user entries given as indented YAML bodies, plus any extra users,
// and returns its path.
func writeCheckedFixture(t *testing.T, cluster, user, extraUsers string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: https://127.0.0.1:6443
%s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: admin
current-context: k3sm
users:
- name: admin
  user:
%s
%s`, cluster, user, extraUsers)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// inlineUser is a user entry holding only an inline token.
const inlineUser = "    token: inline-token"

// fixturePair returns a PEM self-signed certificate and its key. The client
// builder parses both, so a placeholder would not get as far as the assertion.
func fixturePair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fixture"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<32, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// inlineCluster returns a cluster entry holding caPEM inline.
func inlineCluster(caPEM []byte) string {
	return "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(caPEM)
}

// TestFromCheckedPathRefusesExec is the gate: a kubeconfig whose user names an
// exec entry is refused, and the program it names never runs. FromPath on the
// same file is the control: it yields an exec provider, so the fixture is a live
// entry and the refusal is what stops it being used.
func TestFromCheckedPathRefusesExec(t *testing.T) {
	dir := t.TempDir()
	ran := filepath.Join(dir, "ran")
	helper := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n: > '"+ran+"'\n"), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	caPEM, _ := fixturePair(t)
	path := writeCheckedFixture(t, inlineCluster(caPEM), fmt.Sprintf(`    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
      command: %s`, helper), "")

	unchecked, _, err := FromPath(path)
	if err != nil {
		t.Fatalf("FromPath: %v", err)
	}
	if unchecked.ExecProvider == nil {
		t.Fatal("the fixture resolved to no exec provider, so the refusal below would prove nothing")
	}

	cfg, cs, err := FromCheckedPath(path)
	if !errors.Is(err, ErrCredentialsNotInline) {
		t.Fatalf("err = %v, want ErrCredentialsNotInline", err)
	}
	if cfg != nil || cs != nil {
		t.Error("a refusal must come with a nil config and a nil clientset")
	}
	if !strings.Contains(err.Error(), `user "admin" sets exec`) {
		t.Errorf("err = %q, want it to name the entry and the field", err)
	}
	if _, statErr := os.Stat(ran); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the exec entry ran: stat %s = %v", ran, statErr)
	}
}

func TestFromCheckedPathRefusesEveryFieldNotInline(t *testing.T) {
	const fixturePath = "/fixture/not-in-the-message"
	caPEM, _ := fixturePair(t)
	cluster := inlineCluster(caPEM)
	tests := []struct {
		name          string
		cluster, user string
		want          string
	}{
		{"auth provider", cluster, "    auth-provider:\n      name: fixture", `user "admin" sets auth-provider`},
		{"token file", cluster, "    tokenFile: " + fixturePath, `user "admin" sets tokenFile`},
		{"client certificate", cluster, "    client-certificate: " + fixturePath, `user "admin" sets client-certificate`},
		{"client key", cluster, "    client-key: " + fixturePath, `user "admin" sets client-key`},
		{"impersonated user", cluster, "    as: fixture", `user "admin" sets as`},
		{"impersonated uid", cluster, "    as-uid: fixture", `user "admin" sets as-uid`},
		{"impersonated groups", cluster, "    as-groups: [fixture]", `user "admin" sets as-groups`},
		{"impersonated extra", cluster, "    as-user-extra: {fixture: [fixture]}", `user "admin" sets as-user-extra`},
		{"certificate authority path", "    certificate-authority: " + fixturePath, inlineUser, `cluster "k3sm" sets certificate-authority`},
		{"path beside inline data", cluster, "    client-certificate-data: Y2VydA==\n    client-certificate: " + fixturePath, `user "admin" sets client-certificate`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := FromCheckedPath(writeCheckedFixture(t, tt.cluster, tt.user, ""))
			if !errors.Is(err, ErrCredentialsNotInline) {
				t.Fatalf("err = %v, want ErrCredentialsNotInline", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), fixturePath) {
				t.Errorf("err = %q carries a field's value", err)
			}
		})
	}
}

// TestFromCheckedPathChecksEntriesTheContextDoesNotName pins that the whole file
// is checked, and that the message is stable across loads of one file.
func TestFromCheckedPathChecksEntriesTheContextDoesNotName(t *testing.T) {
	caPEM, _ := fixturePair(t)
	path := writeCheckedFixture(t, inlineCluster(caPEM), inlineUser, `- name: zeta
  user:
    tokenFile: /fixture/token
- name: alpha
  user:
    client-key: /fixture/key
`)
	const want = `user "alpha" sets client-key; user "zeta" sets tokenFile: ` + "only inline credentials are accepted"
	for range 20 {
		_, _, err := FromCheckedPath(path)
		if !errors.Is(err, ErrCredentialsNotInline) {
			t.Fatalf("err = %v, want ErrCredentialsNotInline", err)
		}
		if err.Error() != want {
			t.Fatalf("err = %q, want %q", err, want)
		}
	}
}

// TestFromCheckedPathAcceptsInlineCredentials covers each shape k3sm has written,
// including the older single-node one with no CA and a skip-verify cluster.
func TestFromCheckedPathAcceptsInlineCredentials(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	caPEM, _ := fixturePair(t)
	certPEM, keyPEM := fixturePair(t)
	tests := []struct {
		name          string
		cluster, user string
		wantToken     string
		wantCert      []byte
		wantCA        []byte
	}{
		{"token and CA data", inlineCluster(caPEM), inlineUser, "inline-token", nil, caPEM},
		{"token and skip verify", "    insecure-skip-tls-verify: true", inlineUser, "inline-token", nil, nil},
		{
			"client keypair and CA data", inlineCluster(caPEM),
			"    client-certificate-data: " + b64(certPEM) + "\n    client-key-data: " + b64(keyPEM),
			"", certPEM, caPEM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, cs, err := FromCheckedPath(writeCheckedFixture(t, tt.cluster, tt.user, ""))
			if err != nil {
				t.Fatalf("FromCheckedPath: %v", err)
			}
			if cs == nil {
				t.Error("clientset is nil with no error")
			}
			if cfg.Host != "https://127.0.0.1:6443" {
				t.Errorf("Host = %q, want the file's server", cfg.Host)
			}
			if cfg.BearerToken != tt.wantToken {
				t.Errorf("BearerToken = %q, want %q", cfg.BearerToken, tt.wantToken)
			}
			if !bytes.Equal(cfg.CertData, tt.wantCert) {
				t.Errorf("CertData = %q, want %q", cfg.CertData, tt.wantCert)
			}
			if !bytes.Equal(cfg.CAData, tt.wantCA) {
				t.Errorf("CAData = %q, want %q", cfg.CAData, tt.wantCA)
			}
		})
	}
}

// TestRestConfigFromUsesTheCheckedObject pins that the config comes from what was
// checked: an edit to the object shows, and the file being gone does not matter.
func TestRestConfigFromUsesTheCheckedObject(t *testing.T) {
	caPEM, _ := fixturePair(t)
	path := writeCheckedFixture(t, inlineCluster(caPEM), inlineUser, "")
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove kubeconfig: %v", err)
	}
	raw.AuthInfos["admin"].Token = "from-the-object"
	cfg, err := restConfigFrom(raw)
	if err != nil {
		t.Fatalf("restConfigFrom: %v", err)
	}
	if cfg.BearerToken != "from-the-object" {
		t.Errorf("BearerToken = %q, want the checked object's", cfg.BearerToken)
	}
}

func TestFromCheckedPathReturnsTheLoaderError(t *testing.T) {
	t.Run("absent file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.kubeconfig")
		_, _, err := FromCheckedPath(path)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("err = %v, want the loader's own fs.ErrNotExist", err)
		}
		if errors.Is(err, ErrCredentialsNotInline) {
			t.Errorf("err = %v, an absent file is not a refusal", err)
		}
	})

	t.Run("unparseable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(path, []byte("{{ this is not a kubeconfig\n"), 0o600); err != nil {
			t.Fatalf("write kubeconfig: %v", err)
		}
		_, _, err := FromCheckedPath(path)
		if err == nil {
			t.Fatal("expected an error for an unparseable kubeconfig")
		}
		if errors.Is(err, ErrCredentialsNotInline) {
			t.Errorf("err = %v, an unparseable file is not a refusal", err)
		}
	})

	t.Run("empty path does not search the environment", func(t *testing.T) {
		t.Setenv("KUBECONFIG", writeKubeconfig(t, "https://198.51.100.1:6443"))
		if cfg, _, err := FromCheckedPath(""); err == nil {
			t.Fatalf("FromCheckedPath(\"\") resolved to %q; it must not consult the environment", cfg.Host)
		}
	})
}

// TestPinCAReplacesEveryOtherTrustSetting starts from each trust setting a
// kubeconfig can carry and pins that only the given CA remains.
func TestPinCAReplacesEveryOtherTrustSetting(t *testing.T) {
	pinned, _ := fixturePair(t)
	other, _ := fixturePair(t)
	tests := []struct {
		name string
		tls  rest.TLSClientConfig
	}{
		{name: "an inline CA", tls: rest.TLSClientConfig{CAData: other}},
		{name: "a CA file", tls: rest.TLSClientConfig{CAFile: "/elsewhere/ca.crt"}},
		{name: "insecure-skip-tls-verify", tls: rest.TLSClientConfig{Insecure: true}},
		{name: "tls-server-name", tls: rest.TLSClientConfig{CAData: other, ServerName: "elsewhere.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &rest.Config{Host: "https://192.0.2.1:6443", TLSClientConfig: tt.tls}
			if err := PinCA(cfg, pinned); err != nil {
				t.Fatalf("PinCA: %v", err)
			}
			if !bytes.Equal(cfg.CAData, pinned) {
				t.Error("the config's CA is not the pinned one")
			}
			if cfg.CAFile != "" || cfg.Insecure || cfg.ServerName != APIServerName() {
				t.Errorf("trust left behind: %+v", cfg.TLSClientConfig)
			}
			if cfg.Host != "https://192.0.2.1:6443" {
				t.Errorf("host = %q, want it untouched", cfg.Host)
			}
			if _, err := rest.TLSConfigFor(cfg); err != nil {
				t.Errorf("the pinned config does not build a TLS config: %v", err)
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte("not pem")} {
		cfg := &rest.Config{TLSClientConfig: rest.TLSClientConfig{CAData: other}}
		if err := PinCA(cfg, bad); !errors.Is(err, ErrCAUnusable) {
			t.Errorf("PinCA(%q) = %v, want ErrCAUnusable", bad, err)
		}
		if !bytes.Equal(cfg.CAData, other) {
			t.Errorf("PinCA(%q) changed the config it refused", bad)
		}
	}
}

// TestFromCheckedPathWithCA pins what a caller holding the CA gets from the file:
// the address and the client credential, never the trust.
func TestFromCheckedPathWithCA(t *testing.T) {
	fileCA, _ := fixturePair(t)
	pinned, _ := fixturePair(t)
	clientCert, clientKey := fixturePair(t)
	user := fmt.Sprintf("    client-certificate-data: %s\n    client-key-data: %s",
		base64.StdEncoding.EncodeToString(clientCert), base64.StdEncoding.EncodeToString(clientKey))

	t.Run("the given CA replaces the file's", func(t *testing.T) {
		cfg, cs, err := FromCheckedPathWithCA(writeCheckedFixture(t, inlineCluster(fileCA), user, ""), pinned)
		if err != nil {
			t.Fatalf("FromCheckedPathWithCA: %v", err)
		}
		if cs == nil || !bytes.Equal(cfg.CAData, pinned) {
			t.Errorf("clientset = %v, CA is the pinned one = %t", cs, bytes.Equal(cfg.CAData, pinned))
		}
		if cfg.Host != "https://127.0.0.1:6443" || !bytes.Equal(cfg.CertData, clientCert) {
			t.Errorf("host %q and the client certificate must come from the file", cfg.Host)
		}
	})
	t.Run("insecure-skip-tls-verify in the file does not apply", func(t *testing.T) {
		cfg, _, err := FromCheckedPathWithCA(writeCheckedFixture(t, "    insecure-skip-tls-verify: true", user, ""), pinned)
		if err != nil {
			t.Fatalf("FromCheckedPathWithCA: %v", err)
		}
		if cfg.Insecure || !bytes.Equal(cfg.CAData, pinned) {
			t.Errorf("insecure = %t, want the pinned CA only", cfg.Insecure)
		}
	})
	t.Run("the inline check still applies", func(t *testing.T) {
		path := writeCheckedFixture(t, inlineCluster(fileCA), "    tokenFile: /elsewhere/token", "")
		if _, _, err := FromCheckedPathWithCA(path, pinned); !errors.Is(err, ErrCredentialsNotInline) {
			t.Errorf("err = %v, want ErrCredentialsNotInline", err)
		}
	})
	t.Run("an unusable CA is refused", func(t *testing.T) {
		_, cs, err := FromCheckedPathWithCA(writeCheckedFixture(t, inlineCluster(fileCA), user, ""), []byte("not pem"))
		if !errors.Is(err, ErrCAUnusable) || cs != nil {
			t.Errorf("err = %v, clientset = %v, want ErrCAUnusable and none", err, cs)
		}
	})
}
