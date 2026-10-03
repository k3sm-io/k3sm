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

package vkadapter

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// The bounded waits every node-lifecycle test shares. A node over a fake
// clientset reaches Ready in milliseconds; the bounds exist so a regression
// fails the test instead of hanging the package.
const (
	readyTimeout = 10 * time.Second
	doneTimeout  = 5 * time.Second
	stepTimeout  = 10 * time.Second
)

// nodeHarness drives a VK node over a fake clientset. Pod events are delivered
// through a driven fake watcher (the only way to hand the pod informer a pod
// deterministically); every other resource uses the fake's object tracker.
// Each signal channel is closed exactly once, by a reactor, the first time the
// node issues the request it names.
type nodeHarness struct {
	cs       *fake.Clientset
	podWatch *watch.FakeWatcher

	podWatched   chan struct{}
	leaseCreated chan struct{}

	mu          sync.Mutex
	createdNode *corev1.Node
}

func newNodeHarness(t *testing.T) *nodeHarness {
	t.Helper()
	h := &nodeHarness{
		cs:           fake.NewSimpleClientset(),
		podWatch:     watch.NewFakeWithChanSize(16, false),
		podWatched:   make(chan struct{}),
		leaseCreated: make(chan struct{}),
	}
	var watchOnce, leaseOnce sync.Once
	h.cs.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		watchOnce.Do(func() { close(h.podWatched) })
		return true, h.podWatch, nil
	})
	// Observers only (handled=false): the tracker still answers the request.
	h.cs.PrependReactor("create", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		leaseOnce.Do(func() { close(h.leaseCreated) })
		return false, nil, nil
	})
	h.cs.PrependReactor("create", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if n, ok := a.(k8stesting.CreateAction).GetObject().(*corev1.Node); ok {
			h.mu.Lock()
			h.createdNode = n.DeepCopy()
			h.mu.Unlock()
		}
		return false, nil, nil
	})
	return h
}

// registeredNode returns the Node object the node controller created.
func (h *nodeHarness) registeredNode() *corev1.Node {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.createdNode == nil {
		return nil
	}
	return h.createdNode.DeepCopy()
}

// runNode starts n.Run and waits (bounded) for Ready. The returned stop
// cancels the node and waits (bounded) for Run to return its error.
func runNode(t *testing.T, n *Node) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- n.Run(ctx) }()
	select {
	case <-n.Ready():
	case err := <-errc:
		cancel()
		t.Fatalf("node Run returned before Ready: %v", err)
	case <-time.After(readyTimeout):
		cancel()
		t.Fatalf("node not Ready within %s", readyTimeout)
	}
	var once sync.Once
	var runErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case runErr = <-errc:
			case <-time.After(doneTimeout):
				runErr = errors.New("node Run did not return after cancel")
			}
		})
		return runErr
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// waitClosed waits (bounded) for ch to close.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(stepTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// testPod is a pod bound to node.
func testPod(node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cycle", UID: types.UID("cycle-uid"), ResourceVersion: "1"},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "c", Image: "example/app:1"}},
			Volumes: []corev1.Volume{{
				Name:         "creds",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}},
			}},
		},
	}
}

// cyclePod drives one pod create and delete through the node: the pod is added
// to the tracker (so VK's status writes land) and delivered as a watch event,
// then deleted the same way. It returns once the provider saw both.
func (h *nodeHarness) cyclePod(t *testing.T, p *recordingProvider, node string) {
	t.Helper()
	pod := testPod(node)
	if err := h.cs.Tracker().Add(pod); err != nil {
		t.Fatalf("tracker add pod: %v", err)
	}
	h.podWatch.Add(pod.DeepCopy())
	waitClosed(t, p.created, "provider CreatePod")
	if err := h.cs.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), pod.Namespace, pod.Name); err != nil {
		t.Fatalf("tracker delete pod: %v", err)
	}
	h.podWatch.Delete(pod.DeepCopy())
	waitClosed(t, p.deleted, "provider DeletePod")
}

// scmListWatches returns every list/watch the clientset recorded on secrets,
// configmaps or services.
func scmListWatches(actions []k8stesting.Action) []k8stesting.Action {
	var out []k8stesting.Action
	for _, a := range actions {
		if a.GetVerb() != "list" && a.GetVerb() != "watch" {
			continue
		}
		switch a.GetResource().Resource {
		case "secrets", "configmaps", "services":
			out = append(out, a)
		}
	}
	return out
}

// recordingProvider is the smallest Provider a node can run a pod through. It
// keeps the pods it was handed and signals the first create and delete.
type recordingProvider struct {
	mu      sync.Mutex
	pods    map[string]*corev1.Pod
	created chan struct{}
	deleted chan struct{}
	cOnce   sync.Once
	dOnce   sync.Once
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{pods: map[string]*corev1.Pod{}, created: make(chan struct{}), deleted: make(chan struct{})}
}

func podKey(ns, name string) string { return ns + "/" + name }

func (p *recordingProvider) CreatePod(_ context.Context, pod *corev1.Pod) error {
	p.mu.Lock()
	running := pod.DeepCopy()
	running.Status.Phase = corev1.PodRunning
	p.pods[podKey(pod.Namespace, pod.Name)] = running
	p.mu.Unlock()
	p.cOnce.Do(func() { close(p.created) })
	return nil
}

func (p *recordingProvider) UpdatePod(context.Context, *corev1.Pod) error { return nil }

func (p *recordingProvider) DeletePod(_ context.Context, pod *corev1.Pod) error {
	p.mu.Lock()
	delete(p.pods, podKey(pod.Namespace, pod.Name))
	p.mu.Unlock()
	p.dOnce.Do(func() { close(p.deleted) })
	return nil
}

func (p *recordingProvider) GetPod(_ context.Context, ns, name string) (*corev1.Pod, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pod, ok := p.pods[podKey(ns, name)]; ok {
		return pod.DeepCopy(), nil
	}
	return nil, NotFoundf("pod %s/%s", ns, name)
}

func (p *recordingProvider) GetPodStatus(ctx context.Context, ns, name string) (*corev1.PodStatus, error) {
	pod, err := p.GetPod(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	return &pod.Status, nil
}

func (p *recordingProvider) GetPods(context.Context) ([]*corev1.Pod, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*corev1.Pod, 0, len(p.pods))
	for _, pod := range p.pods {
		out = append(out, pod.DeepCopy())
	}
	return out, nil
}

func (p *recordingProvider) GetContainerLogs(context.Context, string, string, string, ContainerLogOpts) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (p *recordingProvider) RunInContainer(context.Context, string, string, string, []string, AttachIO) error {
	return errors.New("not implemented")
}

func (p *recordingProvider) AttachToContainer(context.Context, string, string, string, AttachIO) error {
	return errors.New("not implemented")
}

func (p *recordingProvider) GetStatsSummary(context.Context) (*statsv1alpha1.Summary, error) {
	return &statsv1alpha1.Summary{}, nil
}

func (p *recordingProvider) GetMetricsResource(context.Context) ([]*dto.MetricFamily, error) {
	return nil, nil
}

func (p *recordingProvider) PortForward(context.Context, string, string, int32, io.ReadWriteCloser) error {
	return errors.New("not implemented")
}

var _ Provider = (*recordingProvider)(nil)
