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

// Command lintexamples is the cluster-free half of hack/verify-examples.sh: it
// parses every manifest it is given and asserts the shape a k3sm cluster will
// actually accept.
//
// It exists because the guarantees it checks are not expressible in a YAML schema
// — they are k3sm's admission and placement rules, and a manifest that violates
// them is rejected at `kubectl apply` or admitted and then never scheduled. An
// example that teaches such a shape is worse than no example, and until this
// existed nothing noticed.
//
// The checks, and what breaks without each:
//
//	nodeSelector kubernetes.io/os=darwin   a ValidatingAdmissionPolicy DENIES the
//	                                       pod outright (pkg/policy/admission.go,
//	                                       darwinSelectorExpr).
//	a toleration for the provider taint    every node carries
//	                                       policy.ProviderTaintKey:NoSchedule, so an
//	                                       untolerating pod stays Unschedulable.
//	                                       DaemonSet pods are exempt: a mutating
//	                                       policy injects it for them.
//	no spec.nodeName                       a hand-pinned pod bypasses the scheduler
//	                                       and with it the node/volume checks.
//	no blanket toleration                  a keyless `operator: Exists` also tolerates
//	                                       not-ready/unreachable, keeping a pod bound
//	                                       to a node that has stopped working.
//	native image conventions               `image: native` means command[0] is an
//	                                       absolute host binary; the only other legal
//	                                       form is an absolute path as the image.
//
// Decoding is STRICT (unknown or duplicated fields are errors), so a typo'd field
// name — the failure a hand-written example is most likely to carry — is caught
// here rather than being silently dropped by the apiserver.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"k3sm.io/k3sm/pkg/policy"
)

// The os=darwin selector the admission policy requires. It is RESTATED rather than
// imported because pkg/policy holds it only inside an unexported CEL string
// (darwinSelectorExpr); if that expression ever changes key or value, change these
// with it — they are the same contract seen from the author's side.
const (
	osLabelKey   = "kubernetes.io/os"
	osLabelValue = "darwin"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: lintexamples <file-or-directory>...\n\n"+
			"Lints k3sm example manifests for admission- and scheduling-correctness.\n"+
			"Directories are scanned for *.yaml and *.yml. Exits 1 on any finding.\n")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	files, err := collect(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "lintexamples: %v\n", err)
		os.Exit(2)
	}

	failed := 0
	for _, f := range files {
		findings := lintFile(f)
		if len(findings) == 0 {
			fmt.Printf("ok    %s\n", f)
			continue
		}
		failed++
		fmt.Printf("FAIL  %s\n", f)
		for _, fi := range findings {
			fmt.Printf("        %s\n", fi)
		}
	}
	fmt.Printf("lintexamples: %d file(s) checked, %d failed\n", len(files), failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// collect expands the arguments into a sorted, de-duplicated file list. A directory
// naming no manifests is an ERROR, not an empty green: "the examples directory moved"
// and "every example passes" must never look the same from the outside.
func collect(args []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, a := range args {
		info, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
			continue
		}
		entries, err := os.ReadDir(a)
		if err != nil {
			return nil, err
		}
		n := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			p := filepath.Join(a, e.Name())
			n++
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("%s contains no *.yaml manifests", a)
		}
	}
	sort.Strings(out)
	return out, nil
}

// podTarget is one pod spec found in a document, with the field path it was found at
// and the kind that owns it (the DaemonSet exemption keys off the kind).
type podTarget struct {
	kind  string
	where string
	spec  *corev1.PodSpec
}

// lintFile returns one human-readable finding per problem; an empty slice is a pass.
func lintFile(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("read: %v", err)}
	}

	var findings []string
	docs, err := splitDocuments(raw)
	if err != nil {
		return []string{fmt.Sprintf("yaml: %v", err)}
	}
	if len(docs) == 0 {
		return []string{"contains no YAML documents"}
	}
	for i, doc := range docs {
		prefix := ""
		if len(docs) > 1 {
			prefix = fmt.Sprintf("document %d: ", i+1)
		}
		kind, targets, err := decodeDocument(doc)
		if err != nil {
			findings = append(findings, prefix+err.Error())
			continue
		}
		for _, t := range targets {
			for _, f := range checkPodSpec(kind, t.where, t.spec) {
				findings = append(findings, fmt.Sprintf("%s%s/%s: %s", prefix, kind, describe(doc), f))
			}
		}
	}
	return findings
}

// describe returns the document's metadata.name for use in a finding, or "?" when it
// has none. Best-effort and non-strict: a decode problem is reported elsewhere.
func describe(doc []byte) string {
	var partial struct {
		Metadata metav1.ObjectMeta `json:"metadata"`
	}
	if err := yaml.Unmarshal(doc, &partial); err != nil || partial.Metadata.Name == "" {
		return "?"
	}
	return partial.Metadata.Name
}

// splitDocuments splits a multi-document YAML stream, dropping documents that are
// only comments or whitespace.
func splitDocuments(raw []byte) ([][]byte, error) {
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	var out [][]byte
	for {
		doc, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if isBlank(doc) {
			continue
		}
		out = append(out, doc)
	}
}

// isBlank reports whether a document carries nothing but comments and whitespace.
func isBlank(doc []byte) bool {
	for _, line := range strings.Split(string(doc), "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") && t != "---" {
			return false
		}
	}
	return true
}

// decodeDocument strict-decodes one document into its concrete type and returns the
// pod specs it carries. An unrecognized kind is an ERROR: silently passing a kind the
// linter does not understand is exactly how an unchecked example would slip in.
func decodeDocument(doc []byte) (string, []podTarget, error) {
	var tm metav1.TypeMeta
	if err := yaml.Unmarshal(doc, &tm); err != nil {
		return "", nil, fmt.Errorf("not valid YAML: %v", err)
	}
	if tm.Kind == "" || tm.APIVersion == "" {
		return "", nil, errors.New("missing apiVersion or kind")
	}
	id := tm.APIVersion + "/" + tm.Kind

	strict := func(obj any) error {
		if err := yaml.UnmarshalStrict(doc, obj); err != nil {
			return fmt.Errorf("%s does not decode against its schema: %v", id, err)
		}
		return nil
	}

	switch id {
	case "v1/Pod":
		var o corev1.Pod
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		return tm.Kind, []podTarget{{tm.Kind, "spec", &o.Spec}}, nil
	case "apps/v1/Deployment":
		var o appsv1.Deployment
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		return tm.Kind, []podTarget{{tm.Kind, "spec.template.spec", &o.Spec.Template.Spec}}, nil
	case "apps/v1/StatefulSet":
		var o appsv1.StatefulSet
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		return tm.Kind, []podTarget{{tm.Kind, "spec.template.spec", &o.Spec.Template.Spec}}, nil
	case "apps/v1/DaemonSet":
		var o appsv1.DaemonSet
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		return tm.Kind, []podTarget{{tm.Kind, "spec.template.spec", &o.Spec.Template.Spec}}, nil
	case "apps/v1/ReplicaSet":
		var o appsv1.ReplicaSet
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		return tm.Kind, []podTarget{{tm.Kind, "spec.template.spec", &o.Spec.Template.Spec}}, nil
	case "batch/v1/Job":
		var o batchv1.Job
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		return tm.Kind, []podTarget{{tm.Kind, "spec.template.spec", &o.Spec.Template.Spec}}, nil
	case "batch/v1/CronJob":
		var o batchv1.CronJob
		if err := strict(&o); err != nil {
			return tm.Kind, nil, err
		}
		spec := &o.Spec.JobTemplate.Spec.Template.Spec
		return tm.Kind, []podTarget{{tm.Kind, "spec.jobTemplate.spec.template.spec", spec}}, nil

	// Kinds that carry no pod spec: decoded strictly for the schema check, then
	// nothing further to assert.
	case "v1/Service":
		var o corev1.Service
		return tm.Kind, nil, strict(&o)
	case "v1/PersistentVolumeClaim":
		var o corev1.PersistentVolumeClaim
		return tm.Kind, nil, strict(&o)
	case "v1/ConfigMap":
		var o corev1.ConfigMap
		return tm.Kind, nil, strict(&o)
	case "v1/Secret":
		var o corev1.Secret
		return tm.Kind, nil, strict(&o)
	case "v1/ServiceAccount":
		var o corev1.ServiceAccount
		return tm.Kind, nil, strict(&o)
	case "v1/Namespace":
		var o corev1.Namespace
		return tm.Kind, nil, strict(&o)
	case "networking.k8s.io/v1/Ingress":
		var o networkingv1.Ingress
		return tm.Kind, nil, strict(&o)
	case "networking.k8s.io/v1/NetworkPolicy":
		var o networkingv1.NetworkPolicy
		return tm.Kind, nil, strict(&o)
	}
	return tm.Kind, nil, fmt.Errorf("unsupported kind %q — teach hack/examples/lintexamples about it "+
		"rather than shipping an example nothing checks", id)
}

// checkPodSpec applies the five pod-shape rules. where is the field path the spec was
// found at, so a finding on a Deployment names spec.template.spec and not spec.
func checkPodSpec(kind, where string, s *corev1.PodSpec) []string {
	var out []string

	if s.NodeSelector[osLabelKey] != osLabelValue {
		out = append(out, fmt.Sprintf("%s.nodeSelector must set %s=%s — the os=darwin "+
			"ValidatingAdmissionPolicy denies any pod without it", where, osLabelKey, osLabelValue))
	}

	if s.NodeName != "" {
		out = append(out, fmt.Sprintf("%s.nodeName is set (%q) — a hand-pinned pod bypasses the "+
			"scheduler and the node/volume checks that go with it; let the nodeSelector place it",
			where, s.NodeName))
	}

	for i, t := range s.Tolerations {
		if t.Key == "" {
			out = append(out, fmt.Sprintf("%s.tolerations[%d] is a blanket toleration (no key), so it "+
				"also tolerates not-ready and unreachable — key it on %s instead",
				where, i, policy.ProviderTaintKey))
		}
	}

	// DaemonSet pods are created by the DaemonSet controller and a mutating admission
	// policy injects the provider toleration for them, so requiring it in the template
	// would be requiring something the cluster already handles.
	if kind != "DaemonSet" && !toleratesProviderTaint(s.Tolerations) {
		out = append(out, fmt.Sprintf("%s has no toleration for the %s:NoSchedule taint every k3sm "+
			"node carries — the pod would be admitted and then stay Unschedulable",
			where, policy.ProviderTaintKey))
	}

	// A pod that opts into a RuntimeClass (today: vm) runs a Linux image in a micro-VM,
	// where the native-image conventions do not apply.
	if s.RuntimeClassName == nil || *s.RuntimeClassName == "" {
		out = append(out, checkImages(where+".initContainers", s.InitContainers)...)
		out = append(out, checkImages(where+".containers", s.Containers)...)
	}
	return out
}

// checkImages enforces the two native image conventions (see docs/user/images.md):
// `image: native` with an absolute command[0], or an absolute path as the image itself.
func checkImages(where string, containers []corev1.Container) []string {
	var out []string
	for _, c := range containers {
		switch {
		case c.Image == "":
			out = append(out, fmt.Sprintf("%s[%s] declares no image", where, c.Name))
		case c.Image == "native":
			if len(c.Command) == 0 {
				out = append(out, fmt.Sprintf("%s[%s] uses `image: native` but declares no command — "+
					"the sentinel means the workload IS command[0]", where, c.Name))
				continue
			}
			if !strings.HasPrefix(c.Command[0], "/") {
				out = append(out, fmt.Sprintf("%s[%s] uses `image: native` so command[0] must be an "+
					"absolute host path, got %q", where, c.Name, c.Command[0]))
			}
		case strings.HasPrefix(c.Image, "/"):
			// The `image: /abs/path` convention; command is optional.
		default:
			out = append(out, fmt.Sprintf("%s[%s] image %q is neither the `native` sentinel nor an "+
				"absolute host path — native pods do not run OCI Linux images; those need the vm "+
				"runtimeClassName", where, c.Name, c.Image))
		}
	}
	return out
}

// toleratesProviderTaint is the Toleration.ToleratesTaint predicate, evaluated against
// the provider taint (policy.ProviderTaintKey, effect NoSchedule, empty value). It
// mirrors the CEL the cluster's own Warn policy uses, so the linter and the cluster
// agree on what "tolerates" means.
func toleratesProviderTaint(ts []corev1.Toleration) bool {
	for _, t := range ts {
		if t.Effect != "" && t.Effect != corev1.TaintEffectNoSchedule {
			continue
		}
		if t.Key != "" && t.Key != policy.ProviderTaintKey {
			continue
		}
		if t.Operator == corev1.TolerationOpExists {
			return true
		}
		if (t.Operator == "" || t.Operator == corev1.TolerationOpEqual) && t.Value == "" {
			return true
		}
	}
	return false
}
