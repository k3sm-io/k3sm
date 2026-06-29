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

package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/mount"
)

// TestKubeResolverMaterialize is the M2.1-a1 proof that the provider's
// mount.Resolver resolves a fake ConfigMap/Secret into mount content: the resolver
// returns the apiserver objects' data, and runtimed's materializer writes them as
// files under the pod data volume (the end-to-end seam, no apiserver, no root).
func TestKubeResolverMaterialize(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "app-config"},
			Data:       map[string]string{"app.conf": "key=value"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "app-secret"},
			Data:       map[string][]byte{"token": []byte("s3cr3t")},
		},
	)
	r := newKubeResolver(cs)

	cm, err := r.ConfigMap(ctx, "prod", "app-config")
	if err != nil {
		t.Fatalf("ConfigMap: %v", err)
	}
	if string(cm["app.conf"]) != "key=value" {
		t.Errorf("configMap data = %q, want key=value", cm["app.conf"])
	}
	sec, err := r.Secret(ctx, "prod", "app-secret")
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if string(sec["token"]) != "s3cr3t" {
		t.Errorf("secret data = %q, want s3cr3t", sec["token"])
	}

	dataVol := t.TempDir()
	box := &runtimev1.PodBox{
		Namespace: "prod",
		Volumes: []*runtimev1.Volume{
			{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-config"}},
			{Name: "scrt", Secret: &runtimev1.SecretVolumeSource{SecretName: "app-secret"}},
		},
		Containers: []*runtimev1.Container{{
			Name: "c0",
			VolumeMounts: []*runtimev1.VolumeMount{
				{Name: "cfg", MountPath: "/etc/config"},
				{Name: "scrt", MountPath: "/etc/secret", ReadOnly: true},
			},
		}},
	}
	layout, err := mount.Materialize(ctx, box, dataVol, "10.0.0.7", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if len(layout.Mounts) != 2 {
		t.Fatalf("layout mounts = %d, want 2", len(layout.Mounts))
	}
	got, err := os.ReadFile(filepath.Join(dataVol, "etc/config", "app.conf"))
	if err != nil {
		t.Fatalf("read materialized configMap file: %v", err)
	}
	if string(got) != "key=value" {
		t.Errorf("materialized configMap file = %q, want key=value", got)
	}
	// The secret must be flagged a credential (the SBPL read-only sub-scope).
	if len(layout.CredentialPaths()) != 1 {
		t.Errorf("credential paths = %v, want the secret mount", layout.CredentialPaths())
	}
}

// TestKubeResolverOptionalMissing confirms a missing ConfigMap is reported as
// os.ErrNotExist so an optional source can be skipped (the materializer/env
// resolver test this with errors.Is).
func TestKubeResolverOptionalMissing(t *testing.T) {
	r := newKubeResolver(fake.NewSimpleClientset())
	_, err := r.ConfigMap(context.Background(), "prod", "absent")
	if !os.IsNotExist(err) {
		t.Fatalf("missing configMap err = %v, want os.ErrNotExist", err)
	}
}

// TestResolvePodBoxEnv is the M2.1 proof that the provider flattens env into
// LITERAL values (runtimed reads only EnvVar.value): envFrom expansion,
// configMap/secretKeyRef, downward-API fieldRef, with explicit env overriding
// envFrom and value_from/env_from cleared afterwards.
func TestResolvePodBoxEnv(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "env-config"}, Data: map[string]string{"LOG_LEVEL": "debug", "REGION": "us"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "env-secret"}, Data: map[string][]byte{"API_KEY": []byte("xyz")}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "single"}, Data: map[string]string{"only": "one"}},
	)
	box := &runtimev1.PodBox{
		Namespace: "prod", Name: "api", PodId: "uid-api", PodIp: "10.0.0.7",
		Containers: []*runtimev1.Container{{
			Name: "c0",
			EnvFrom: []*runtimev1.EnvFromSource{
				{ConfigMapRef: &runtimev1.ConfigMapEnvSource{Name: "env-config"}},
				{Prefix: "SEC_", SecretRef: &runtimev1.SecretEnvSource{Name: "env-secret"}},
			},
			Env: []*runtimev1.EnvVar{
				{Name: "NODE", ValueFrom: &runtimev1.EnvVarSource{FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
				{Name: "POD", ValueFrom: &runtimev1.EnvVarSource{FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
				{Name: "IP", ValueFrom: &runtimev1.EnvVarSource{FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
				{Name: "K", ValueFrom: &runtimev1.EnvVarSource{ConfigMapKeyRef: &runtimev1.ConfigMapKeySelector{Name: "single", Key: "only"}}},
				{Name: "S", ValueFrom: &runtimev1.EnvVarSource{SecretKeyRef: &runtimev1.SecretKeySelector{Name: "env-secret", Key: "API_KEY"}}},
				{Name: "LIT", Value: "literal"},
				{Name: "LOG_LEVEL", Value: "override"}, // explicit env wins over envFrom
			},
		}},
	}
	if err := resolvePodBoxEnv(ctx, box, "node-7", "192.168.1.10", newKubeResolver(cs)); err != nil {
		t.Fatalf("resolvePodBoxEnv: %v", err)
	}

	c := box.GetContainers()[0]
	env := map[string]string{}
	for _, e := range c.GetEnv() {
		if e.GetValueFrom() != nil {
			t.Errorf("env %q still carries value_from after resolution", e.GetName())
		}
		env[e.GetName()] = e.GetValue()
	}
	if c.GetEnvFrom() != nil {
		t.Error("env_from must be cleared after resolution")
	}
	want := map[string]string{
		"LOG_LEVEL":   "override", // env overrides the envFrom configMap value
		"REGION":      "us",       // envFrom configMap
		"SEC_API_KEY": "xyz",      // envFrom secret, prefixed
		"NODE":        "node-7",   // downward spec.nodeName (provider-supplied)
		"POD":         "api",      // downward metadata.name
		"IP":          "10.0.0.7", // downward status.podIP
		"K":           "one",      // configMapKeyRef
		"S":           "xyz",      // secretKeyRef
		"LIT":         "literal",  // literal
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%q] = %q, want %q", k, env[k], v)
		}
	}
}

// TestResolvePodBoxEnvOptional confirms an optional missing source is skipped and a
// required missing one fails closed.
func TestResolvePodBoxEnvOptional(t *testing.T) {
	ctx := context.Background()
	r := newKubeResolver(fake.NewSimpleClientset())

	optBox := &runtimev1.PodBox{
		Namespace: "prod",
		Containers: []*runtimev1.Container{{
			Name: "c0",
			Env: []*runtimev1.EnvVar{
				{Name: "OPT", ValueFrom: &runtimev1.EnvVarSource{ConfigMapKeyRef: &runtimev1.ConfigMapKeySelector{Name: "absent", Key: "k", Optional: true}}},
			},
		}},
	}
	if err := resolvePodBoxEnv(ctx, optBox, "n", "ip", r); err != nil {
		t.Fatalf("optional missing source should not error: %v", err)
	}
	if len(optBox.GetContainers()[0].GetEnv()) != 0 {
		t.Errorf("optional missing env should be skipped, got %v", optBox.GetContainers()[0].GetEnv())
	}

	reqBox := &runtimev1.PodBox{
		Namespace: "prod",
		Containers: []*runtimev1.Container{{
			Name: "c0",
			Env: []*runtimev1.EnvVar{
				{Name: "REQ", ValueFrom: &runtimev1.EnvVarSource{ConfigMapKeyRef: &runtimev1.ConfigMapKeySelector{Name: "absent", Key: "k"}}},
			},
		}},
	}
	if err := resolvePodBoxEnv(ctx, reqBox, "n", "ip", r); err == nil {
		t.Fatal("required missing source must fail closed")
	}
}

// TestKubeCredentialsDockerConfig is the M2.6/imagePullSecret seam proof: a
// dockerconfigjson Secret resolves to the registry credential matching the image
// ref's host, and a non-matching host yields an anonymous pull.
func TestKubeCredentialsDockerConfig(t *testing.T) {
	ctx := context.Background()
	dockerCfg := `{"auths":{"registry.example.com":{"username":"u","password":"p","auth":"dXNlcjpwYXNz"}}}`
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "regcred"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(dockerCfg)},
	})
	k := newKubeCredentials(cs)
	refs := []*runtimev1.LocalObjectReference{{Name: "regcred"}}

	cred, ok, err := k.PullCredential(ctx, "prod", refs, "registry.example.com/app:latest")
	if err != nil {
		t.Fatalf("PullCredential: %v", err)
	}
	if !ok || cred.Username != "u" || cred.Password != "p" || cred.Auth != "dXNlcjpwYXNz" {
		t.Fatalf("credential = %+v ok=%v, want u/p for registry.example.com", cred, ok)
	}

	_, ok, err = k.PullCredential(ctx, "prod", refs, "other.io/app:latest")
	if err != nil {
		t.Fatalf("PullCredential (non-match): %v", err)
	}
	if ok {
		t.Error("a non-matching registry must resolve to an anonymous pull (ok=false)")
	}
}
