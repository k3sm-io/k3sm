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
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestResolveContainerEnvExpandsDependentVars pins the kubelet's "dependent
// environment variables" rule on the provider's env flattening: a literal env
// value has its $(NAME) references expanded, in declaration order, against the
// variables defined before it (the service links, the master service, envFrom
// keys and earlier env entries, valueFrom ones included). A forward or
// undefined reference stays verbatim, "$$" is a literal "$", and a value that
// came from valueFrom or envFrom is never itself expanded. The expanded env is
// what runtimed's command and args expansion then reads.
//
// Non-vacuity: before this change resolveContainerEnv upserted every literal
// verbatim, so ADDR came out as "$(MY_IP):8080" and the argv carried the
// unexpanded reference; every expanded case below fails on main.
func TestResolveContainerEnvExpandsDependentVars(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "cfg"},
			Data:       map[string]string{"DB_HOST": "pg", "RAW": "$(DB_HOST)"},
		},
	)
	c := &runtimev1.Container{
		Name:    "c0",
		Command: []string{"/app/serve", "--listen=$(ADDR)"},
		EnvFrom: []*runtimev1.EnvFromSource{{ConfigMapRef: &runtimev1.ConfigMapEnvSource{Name: "cfg"}}},
		Env: []*runtimev1.EnvVar{
			{Name: "MY_IP", ValueFrom: &runtimev1.EnvVarSource{FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
			{Name: "ADDR", Value: "$(MY_IP):8080"},
			{Name: "URL", Value: "http://$(ADDR)/v1"},
			{Name: "DSN", Value: "postgres://$(DB_HOST)/app"},
			{Name: "EARLY", Value: "$(LATE)-x"},
			{Name: "LATE", Value: "late"},
			{Name: "ESCAPED", Value: "$$(MY_IP)"},
			{Name: "UNDEFINED", Value: "$(NOPE)"},
			{Name: "API", Value: "$(KUBERNETES_SERVICE_HOST):$(KUBERNETES_SERVICE_PORT)"},
			{Name: "LINK", Value: "$(WEB_SERVICE_HOST)"},
			{Name: "KEYREF", ValueFrom: &runtimev1.EnvVarSource{ConfigMapKeyRef: &runtimev1.ConfigMapKeySelector{Name: "cfg", Key: "RAW"}}},
			{Name: "STAGE", Value: "one"},
			{Name: "BEFORE", Value: "$(STAGE)"},
			{Name: "STAGE", Value: "two"},
			{Name: "AFTER", Value: "$(STAGE)"},
		},
	}
	box := &runtimev1.PodBox{Namespace: "prod", Name: "api", PodIp: "10.42.0.9", Containers: []*runtimev1.Container{c}}
	facts := podFacts{
		apiServerVIP: "10.43.0.1",
		serviceLinks: []*runtimev1.EnvVar{{Name: "WEB_SERVICE_HOST", Value: "10.43.0.20"}},
	}
	if err := resolvePodBoxEnv(context.Background(), box, facts, newTestKubeResolver(cs)); err != nil {
		t.Fatalf("resolvePodBoxEnv: %v", err)
	}

	got := map[string]string{}
	for _, e := range c.GetEnv() {
		got[e.GetName()] = e.GetValue()
	}
	for _, tc := range []struct{ name, want, why string }{
		{"ADDR", "10.42.0.9:8080", "a literal referencing an earlier downward-API var"},
		{"URL", "http://10.42.0.9:8080/v1", "a chain: the earlier value is already expanded"},
		{"DSN", "postgres://pg/app", "a reference to an envFrom key"},
		{"EARLY", "$(LATE)-x", "a forward reference stays verbatim"},
		{"ESCAPED", "$(MY_IP)", "$$ is a literal $, so the reference is not expanded"},
		{"UNDEFINED", "$(NOPE)", "an undefined reference stays verbatim"},
		{"API", "10.43.0.1:443", "the master service variables are visible"},
		{"LINK", "10.43.0.20", "the namespace service links are visible"},
		{"RAW", "$(DB_HOST)", "an envFrom value is never itself expanded"},
		{"KEYREF", "$(DB_HOST)", "a valueFrom value is never itself expanded"},
		{"BEFORE", "one", "a reference sees the value defined before it"},
		{"AFTER", "two", "a redefinition is visible to later entries"},
	} {
		if got[tc.name] != tc.want {
			t.Errorf("env %s = %q, want %q (%s)", tc.name, got[tc.name], tc.want, tc.why)
		}
	}

	// runtimed reads this flattened env for its command and args expansion, so
	// a reference in argv to an expanded var gets the expanded value.
	spec, err := image.MergeRunSpec(image.ImageRunConfig{}, image.RunSpecRequest{Container: c})
	if err != nil {
		t.Fatalf("MergeRunSpec: %v", err)
	}
	if want := []string{"/app/serve", "--listen=10.42.0.9:8080"}; !slices.Equal(spec.Argv, want) {
		t.Errorf("argv = %q, want %q", spec.Argv, want)
	}
}
