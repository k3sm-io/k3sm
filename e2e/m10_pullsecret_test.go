//go:build e2e

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

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The M10.2 imagePullSecrets criterion.
//
// WHAT IT PROVES. A pod naming a kubernetes.io/dockerconfigjson Secret in
// imagePullSecrets pulls a private image from a registry that refuses
// anonymous access, and runs the binary that image carries; the same image
// requested WITHOUT the secret is refused (ErrImagePull/ImagePullBackOff); and
// the resolved credential lands in none of the places a pod can expose it.
//
// THE REGISTRY. An in-process go-containerregistry registry behind HTTP basic
// auth (authregistry_fixture_test.go), started by the test on 127.0.0.1:<random port> over
// plain HTTP. runtimed's puller fetches with go-containerregistry, which infers
// http for a loopback authority (runtimed pkg/image primaryFetch routes a
// loopback reference through the ordinary fetcher for exactly that reason), so
// no TLS, CA injection or registry allowlist is involved. The consequence is
// that the pod must run on the SAME Mac as the test process: the pod is pinned
// with nodeName, and the test refuses to run against a node none of whose
// InternalIPs is an address of this host.
//
// WHICH FETCH PATH THIS EXERCISES. A loopback plain-HTTP registry is the class
// runtimed treats as this node's own ingest registry (the class its cluster
// mirror fallback is defined over), NOT an HTTPS remote registry such as a
// cloud or self-hosted TLS registry. The credential attachment is the same
// code either way (image.RemoteFetch with remote.WithAuth), and the unit tier
// proves it for this registry: TestAuthRegistryFixture's RemoteFetch subtest
// pulls with the docker-config credential and is refused without it. An HTTPS
// registry with a node-trusted CA is not covered here.
//
// MIRRORS. On a node with cluster mirrors wired, a failed pull of a loopback
// reference can be retried against the mirrors (runtimed pullFromMirrors). A
// 401 is not mirror-eligible today (mirrorFallbackEligible classes an auth
// refusal as a definitive answer), but should that change, the negative
// control's waiting message could name a mirror's answer instead of the
// registry's. The control stays sound either way, because it does not rest on
// the message: it requires the registry to have refused an anonymous manifest
// request (refused > 0) and to have served nothing for that tag (served == 0).
//
// THE IMAGE. A stdlib Go program (testdata/cmd/pullprobe) built for
// darwin/arm64 at test time and packaged by pkg/oci, the packager behind
// `k3sm build`: one layer, the binary at /pullprobe. Each run labels its two
// images with its own suffix, so both digests are new to the node and no
// earlier run's cache entry can answer either pull.
//
// NON-VACUITY. The registry records every request. The negative control must
// show an unauthenticated manifest request answered 401 (the node reached the
// registry and was refused, rather than never reaching it), and the positive
// pod must show an authenticated manifest GET answered 200.
//
// CONFIDENTIALITY, and what is and is not covered:
//
//   - the container log: read through the logs subresource, searched directly;
//   - the pod's Events: every core Event in the run's namespace, searched;
//   - the pod object (spec, so the env and args, and status): searched as JSON;
//   - the process environment the runtime actually built, and every regular
//     file under the pod's rootfs: searched FROM INSIDE the pod by pullprobe,
//     which receives only SHA-256 digests of the forbidden strings and reports
//     a leak by location, never by content. That is the reachable view of the
//     rootfs: the tree belongs to the node's runtime data root, which the test
//     process has no right to read.
//
// Not covered, stated rather than scanned:
//
//   - files the node keeps outside the pod rootfs (runtimed's own state and
//     image store), which the M2.6 unit tests for the pull path cover (the
//     credential is confined to the fetch transport and never written);
//   - the k3sm server, provider and runtimed daemon logs, which the test
//     neither locates nor reads (where they land depends on how the node was
//     installed, and runtimed's are root-owned);
//   - the pod process's argv as the kernel holds it. The args the pod spec
//     carries are searched (above); the exec'd argv is not read back, though
//     the runtime builds it from that spec and the image config, neither of
//     which carries the credential.
//
// RUN IT (on the node's own Mac):
//
//	KUBECONFIG=<path> [K3SM_E2E_NODE=<node>] CGO_ENABLED=1 go test -tags e2e \
//	  -count=1 -run '^TestM10_ImagePullSecret$' -timeout 20m ./e2e/ -v
//
// K3SM_E2E_NODE names the node to pin the pods to. Unset, the test picks the
// darwin node whose InternalIP belongs to this host.

const (
	// The fake credential. It is not a secret anywhere; it is what the
	// confidentiality checks look for.
	pullSecretUser = "testuser"
	pullSecretPass = "testpass"

	pullProbeRepo = "b80/pullprobe"
	pullProbeFile = "pullprobe"
)

func TestM10_ImagePullSecret(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	node := pullSecretNode(t, c)
	suffix := runSuffix(t)
	ns := "b80-" + suffix
	sentinel := "B80-SENTINEL-" + randomHex(t, 8)

	// The strings that must never surface. The username is not among them: it
	// is not a secret, and the dockerconfigjson Secret object names it anyway.
	forbidden := []string{
		pullSecretPass,
		basicAuthToken(pullSecretUser, pullSecretPass),
		pullSecretUser + ":" + pullSecretPass,
	}

	reg := listenAuthRegistry(t, pullSecretUser, pullSecretPass)
	contextDir := t.TempDir()
	buildPullProbe(t, filepath.Join(contextDir, pullProbeFile))
	stage := t.TempDir()
	posTag, negTag := "pos-"+suffix, "neg-"+suffix
	for _, tag := range []string{posTag, negTag} {
		img, err := buildNativeImage(contextDir, pullProbeFile, suffix+"-"+tag[:3], stage)
		if err != nil {
			t.Fatalf("build %s image: %v", tag, err)
		}
		if err := reg.Push(ctx, pullProbeRepo, tag, img); err != nil {
			t.Fatalf("push %s: %v", tag, err)
		}
		d, _ := img.Digest()
		t.Logf("pushed %s (%s)", reg.Ref(pullProbeRepo, tag), d)
	}

	t.Cleanup(func() {
		policy := metav1.DeletePropagationForeground
		err := c.Client.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{PropagationPolicy: &policy})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("cleanup: delete namespace %s: %v", ns, err)
			return
		}
		if !pollUntil(2*time.Minute, func() bool {
			_, err := c.Client.CoreV1().Namespaces().Get(context.Background(), ns, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}) {
			t.Logf("cleanup: namespace %s still terminating after 2m; it is uniquely named, so no rerun can meet it", ns)
		}
	})
	if _, err := c.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %s: %v", ns, err)
	}

	// Registry evidence is read only from after this point, so the test's own
	// authenticated push is never mistaken for the node's pull.
	pushed := len(reg.Requests())

	probeArgs := []string{"-sentinel", sentinel}
	for _, f := range forbidden {
		sum := sha256.Sum256([]byte(f))
		probeArgs = append(probeArgs, "-forbid-sha256", strconv.Itoa(len(f))+":"+hex.EncodeToString(sum[:]))
	}

	// NEGATIVE CONTROL, first, while nothing of this run is on the node: the
	// same repository, its own tag and digest, no secret, imagePullPolicy Always.
	negPod := pullProbePod(ns, "no-secret", node, reg.Ref(pullProbeRepo, negTag), "", probeArgs)
	if _, err := c.Client.CoreV1().Pods(ns).Create(ctx, negPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create negative-control pod: %v", err)
	}
	reason := waitImagePullRefused(t, c, ns, negPod.Name, 4*time.Minute)
	t.Logf("negative control %s/%s: %s", ns, negPod.Name, reason)
	var refused, served int
	for _, q := range reg.ManifestRequests(pullProbeRepo, negTag, pushed) {
		if !q.Authed && q.Status == 401 {
			refused++
		}
		if q.Authed || q.Status < 300 {
			served++
		}
	}
	if refused == 0 {
		t.Fatalf("negative control: the registry recorded no refused anonymous manifest request for %s, so the pull failure is not evidence of the auth gate (the node may not reach %s); requests: %+v",
			negTag, reg.Host, reg.Requests())
	}
	if served != 0 {
		t.Fatalf("negative control: the registry served or authenticated %d request(s) for %s with no secret on the pod", served, negTag)
	}

	// POSITIVE: the dockerconfigjson Secret, and a pod that names it.
	cfgJSON, err := dockerConfigJSON(reg.Host, pullSecretUser, pullSecretPass)
	if err != nil {
		t.Fatalf("render dockerconfigjson: %v", err)
	}
	secretName := "regcred"
	if _, err := c.Client.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: cfgJSON},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pull secret: %v", err)
	}
	posPod := pullProbePod(ns, "with-secret", node, reg.Ref(pullProbeRepo, posTag), secretName, probeArgs)
	if _, err := c.Client.CoreV1().Pods(ns).Create(ctx, posPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	defer func() {
		if t.Failed() {
			t.Logf("pod %s/%s logs:\n%s", ns, posPod.Name, podLogs(t, c, ns, posPod.Name))
		}
	}()
	c.WaitPodPhase(t, ns, posPod.Name, corev1.PodSucceeded, 5*time.Minute)

	authedServed := false
	for _, q := range reg.ManifestRequests(pullProbeRepo, posTag, pushed) {
		if q.Authed && q.Method == "GET" && q.Status == 200 {
			authedServed = true
		}
	}
	if !authedServed {
		t.Fatalf("the pod Succeeded but the registry served no authenticated manifest GET for %s: %+v", posTag, reg.Requests())
	}

	// The binary ran, from the pulled image, and saw no credential.
	logs, err := c.Client.CoreV1().Pods(ns).GetLogs(posPod.Name, &corev1.PodLogOptions{}).DoRaw(ctx)
	if err != nil {
		t.Fatalf("get logs %s/%s: %v", ns, posPod.Name, err)
	}
	out := string(logs)
	if !strings.Contains(out, sentinel) {
		t.Fatalf("log lacks the run sentinel %s; the pulled binary did not run:\n%s", sentinel, out)
	}
	if !strings.Contains(out, "B80-CONFIDENTIALITY clean") || strings.Contains(out, "B80-LEAK") {
		t.Fatalf("the in-pod scan found a credential or did not finish:\n%s", out)
	}
	if m := regexp.MustCompile(`B80-SCAN files=(\d+)`).FindStringSubmatch(out); m == nil || m[1] == "0" {
		t.Fatalf("the in-pod rootfs scan read no file, so it proves nothing:\n%s", out)
	}
	// Every file under the rootfs must have been READ, not passed over: a file
	// the probe could not open, or one over its 64 MiB per-file bound, is a
	// file whose content was never searched. The fixture image holds one file,
	// the probe binary (a few MiB), so a nonzero count means the pod's tree
	// holds something the scan could not vouch for, which fails the criterion.
	if m := regexp.MustCompile(`B80-SCAN files=\d+ bytes=\d+ skipped=(\d+)`).FindStringSubmatch(out); m == nil || m[1] != "0" ||
		strings.Contains(out, "B80-UNREADABLE") || strings.Contains(out, "B80-SKIPPED") {
		t.Fatalf("the in-pod rootfs scan skipped or could not read some files, so their content is unsearched:\n%s", out)
	}
	t.Logf("in-pod confidentiality scan:\n%s", out)
	assertNoCredential(t, "container log", out, forbidden)

	events, err := c.Client.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events in %s: %v", ns, err)
	}
	var ev strings.Builder
	for _, e := range events.Items {
		fmt.Fprintf(&ev, "%s %s %s: %s\n", e.InvolvedObject.Name, e.Type, e.Reason, e.Message)
	}
	t.Logf("%d event(s) in %s", len(events.Items), ns)
	assertNoCredential(t, "namespace Events", ev.String(), forbidden)

	for _, name := range []string{posPod.Name, negPod.Name} {
		pod, err := c.Client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get pod %s/%s: %v", ns, name, err)
		}
		raw, err := json.Marshal(pod)
		if err != nil {
			t.Fatalf("marshal pod %s: %v", name, err)
		}
		assertNoCredential(t, "pod object "+name+" (spec env/args, status)", string(raw), forbidden)
	}
}

// listenAuthRegistry serves the fixture registry on 127.0.0.1:<random port>
// over plain HTTP for the life of the test, and points its Host there.
func listenAuthRegistry(t *testing.T, user, pass string) *authRegistry {
	t.Helper()
	reg := newAuthRegistry(user, pass)
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	reg.Host = strings.TrimPrefix(srv.URL, "http://")
	return reg
}

// pullProbePod is the criterion's pod: pinned to node, the darwin
// toleration/selector convention, restartPolicy Never, imagePullPolicy Always so
// every start must reach the registry, and the probe exec'd from the image's
// own rootfs. secret is the imagePullSecret name, or "" for none.
func pullProbePod(ns, name, node, image, secret string, args []string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			NodeName:      node,
			RestartPolicy: corev1.RestartPolicyNever,
			NodeSelector:  map[string]string{"kubernetes.io/os": "darwin"},
			Tolerations: []corev1.Toleration{{
				Key:      "k3sm.io/provider",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}},
			Containers: []corev1.Container{{
				Name:            "probe",
				Image:           image,
				ImagePullPolicy: corev1.PullAlways,
				Command:         []string{"/" + pullProbeFile},
				Args:            args,
			}},
		},
	}
	if secret != "" {
		pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: secret}}
	}
	return pod
}

// waitImagePullRefused polls until the pod's container waits with reason
// ErrImagePull or ImagePullBackOff and returns "<reason>: <message>". It fails
// at once if the container ever runs or terminates: with no secret, that means
// the image was obtained without the credential.
func waitImagePullRefused(t *testing.T, c *Cluster, ns, name string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		pod, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			if pod.Status.Phase == corev1.PodRunning || terminalPhase(pod.Status.Phase) {
				t.Fatalf("negative control %s/%s reached %s without a pull secret — %s", ns, name, pod.Status.Phase, podFailureDetail(pod))
			}
			for _, cs := range pod.Status.ContainerStatuses {
				if cs.State.Running != nil || cs.State.Terminated != nil {
					t.Fatalf("negative control %s/%s: container started without a pull secret — %s", ns, name, podFailureDetail(pod))
				}
				if w := cs.State.Waiting; w != nil && (w.Reason == "ErrImagePull" || w.Reason == "ImagePullBackOff") {
					return w.Reason + ": " + w.Message
				}
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("negative control %s/%s: last get failed: %v", ns, name, err)
			}
			t.Fatalf("negative control %s/%s: no ErrImagePull/ImagePullBackOff within %s — %s", ns, name, timeout, podFailureDetail(pod))
		}
		time.Sleep(2 * time.Second)
	}
}

// assertNoCredential fails if text contains any forbidden string. The failure
// names which one by index, never by value.
func assertNoCredential(t *testing.T, where, text string, forbidden []string) {
	t.Helper()
	for i, f := range forbidden {
		if strings.Contains(text, f) {
			t.Errorf("CONFIDENTIALITY: forbidden credential string #%d appears in %s", i, where)
		}
	}
}

// pullSecretNode returns the node to pin the criterion's pods to:
// $K3SM_E2E_NODE when set, else the darwin node whose InternalIP is an address
// of this host. Either way the node must be this host, because the registry
// listens on this host's loopback.
func pullSecretNode(t *testing.T, c *Cluster) string {
	t.Helper()
	local := localAddrs(t)
	if name := os.Getenv("K3SM_E2E_NODE"); name != "" {
		n, err := c.Client.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node %s ($K3SM_E2E_NODE): %v", name, err)
		}
		if !nodeOnThisHost(n, local) {
			t.Fatalf("node %s (addresses %v) is not this host: the test registry listens on 127.0.0.1, so only a puller on the test's own Mac can reach it; run the test on that node's Mac", name, n.Status.Addresses)
		}
		return name
	}
	nodes, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: "kubernetes.io/os=darwin"})
	if err != nil {
		t.Fatalf("list darwin nodes: %v", err)
	}
	for i := range nodes.Items {
		if nodeOnThisHost(&nodes.Items[i], local) {
			return nodes.Items[i].Name
		}
	}
	t.Fatalf("no darwin node has an InternalIP on this host (%d node(s) listed); run the test on a node's Mac or set $K3SM_E2E_NODE", len(nodes.Items))
	return ""
}

// nodeOnThisHost reports whether any InternalIP of n is a local address.
func nodeOnThisHost(n *corev1.Node, local map[string]bool) bool {
	for _, a := range n.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(a.Address)
		if ip != nil && (ip.IsLoopback() || local[ip.String()]) {
			return true
		}
	}
	return false
}

// localAddrs returns this host's interface addresses.
func localAddrs(t *testing.T) map[string]bool {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("list interface addresses: %v", err)
	}
	out := map[string]bool{}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out[ipn.IP.String()] = true
		}
	}
	return out
}

// buildPullProbe compiles testdata/cmd/pullprobe for darwin/arm64 to out and
// ad-hoc signs it (the Go linker already does; re-signing is best-effort, as for
// the conformance helpers, and a real failure surfaces as the pod not running).
func buildPullProbe(t *testing.T, out string) {
	t.Helper()
	build := exec.Command("go", "build", "-trimpath", "-o", out, "./testdata/cmd/"+pullProbeFile)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=darwin", "GOARCH=arm64")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pullProbeFile, err, b)
	}
	if b, err := exec.Command("codesign", "-s", "-", "-f", out).CombinedOutput(); err != nil {
		t.Logf("codesign %s (non-fatal): %v\n%s", out, err, b)
	}
}

// randomHex returns n random bytes, hex-encoded.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return hex.EncodeToString(b)
}
