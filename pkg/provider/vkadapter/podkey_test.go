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
	"slices"
	"sync"
	"testing"

	vknode "github.com/virtual-kubelet/virtual-kubelet/node"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

// keyedProvider records the provider calls Virtual Kubelet makes, and holds the ones
// a test names, keyed "<verb> <uid>". It remembers any two calls of one namespace/name
// that ran at once.
type keyedProvider struct {
	mu       sync.Mutex
	pods     map[string]*corev1.Pod
	dangling []*corev1.Pod
	running  map[string]int
	overlaps []string
	entered  map[string]bool
	holds    map[string]chan struct{}
	releases []func()
	calls    map[string][]string // per pod name, "<verb> <uid>" of each call as it entered
	deleted  map[string]*corev1.Pod
}

func newKeyedProvider() *keyedProvider {
	return &keyedProvider{
		pods:    map[string]*corev1.Pod{},
		running: map[string]int{},
		entered: map[string]bool{},
		holds:   map[string]chan struct{}{},
		calls:   map[string][]string{},
		deleted: map[string]*corev1.Pod{},
	}
}

// hold makes the named call wait inside the provider until the returned func runs.
func (p *keyedProvider) hold(t *testing.T, call string) (release func()) {
	t.Helper()
	ch := make(chan struct{})
	p.mu.Lock()
	p.holds[call] = ch
	p.mu.Unlock()
	var once sync.Once
	release = func() { once.Do(func() { close(ch) }) }
	p.releases = append(p.releases, release)
	return release
}

// call runs one provider call under the bookkeeping, with body under p.mu at its end.
func (p *keyedProvider) call(verb string, pod *corev1.Pod, body func()) {
	key, name := pod.Namespace+"/"+pod.Name, verb+" "+string(pod.UID)
	p.mu.Lock()
	p.entered[name] = true
	p.calls[pod.Name] = append(p.calls[pod.Name], name)
	p.running[key]++
	if p.running[key] > 1 {
		p.overlaps = append(p.overlaps, name)
	}
	hold := p.holds[name]
	p.mu.Unlock()
	if hold != nil {
		<-hold
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	body()
	p.running[key]--
}

func (p *keyedProvider) wasEntered(call string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.entered[call]
}

func (p *keyedProvider) callsOf(name string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls[name])
}

func (p *keyedProvider) overlapped() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.overlaps...)
}

func (p *keyedProvider) CreatePod(_ context.Context, pod *corev1.Pod) error {
	p.call("create", pod, func() { p.pods[pod.Namespace+"/"+pod.Name] = pod.DeepCopy() })
	return nil
}

func (p *keyedProvider) UpdatePod(_ context.Context, pod *corev1.Pod) error {
	p.call("update", pod, func() { p.pods[pod.Namespace+"/"+pod.Name] = pod.DeepCopy() })
	return nil
}

func (p *keyedProvider) DeletePod(_ context.Context, pod *corev1.Pod) error {
	p.call("delete", pod, func() {
		delete(p.pods, pod.Namespace+"/"+pod.Name)
		p.deleted[string(pod.UID)] = pod.DeepCopy()
		p.dangling = nil
	})
	return nil
}

func (p *keyedProvider) GetPod(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pod := p.pods[namespace+"/"+name]; pod != nil {
		return pod.DeepCopy(), nil
	}
	return nil, NotFoundf("pod %s/%s not found", namespace, name)
}

func (p *keyedProvider) GetPodStatus(_ context.Context, namespace, name string) (*corev1.PodStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pod := p.pods[namespace+"/"+name]; pod != nil {
		return pod.Status.DeepCopy(), nil
	}
	return nil, NotFoundf("pod %s/%s not found", namespace, name)
}

func (p *keyedProvider) GetPods(context.Context) ([]*corev1.Pod, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]*corev1.Pod(nil), p.dangling...)
	for _, pod := range p.pods {
		out = append(out, pod.DeepCopy())
	}
	return out, nil
}

func (p *keyedProvider) NotifyPods(context.Context, func(*corev1.Pod)) {}

// runningPod is a pod Virtual Kubelet deletes through the provider: one with no
// running container goes straight to the apiserver (syncPodInProvider).
func runningPod(name string, uid types.UID) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: uid},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "i"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "c", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
}

// startPodController runs a real Virtual Kubelet pod controller over p, wrapped as
// newNode wraps its provider, with workers to spare beside the one call a test holds, so a held call never stops another key.
func startPodController(t *testing.T, p *keyedProvider, pods ...*corev1.Pod) (*fake.Clientset, *vknode.PodController, informers.SharedInformerFactory) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	for _, pod := range pods {
		if err := cs.Tracker().Add(pod); err != nil {
			t.Fatalf("seed pod: %v", err)
		}
	}
	factory := informers.NewSharedInformerFactory(cs, 0)
	pc, err := vknode.NewPodController(vknode.PodControllerConfig{
		PodClient:                 cs.CoreV1(),
		EventRecorder:             record.NewFakeRecorder(256),
		Provider:                  ReplaceRecreatedPods(p, factory.Core().V1().Pods().Lister()),
		PodInformer:               factory.Core().V1().Pods(),
		SecretInformer:            factory.Core().V1().Secrets(),
		ConfigMapInformer:         factory.Core().V1().ConfigMaps(),
		ServiceInformer:           factory.Core().V1().Services(),
		SkipDownwardAPIResolution: true,
	})
	if err != nil {
		t.Fatalf("NewPodController: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		// A failed test can leave a call held, and the controller waits for its workers.
		for _, release := range p.releases {
			release()
		}
		cancel()
		<-pc.Done()
	})
	factory.Start(ctx.Done())
	go func() { _ = pc.Run(ctx, 3) }()
	return cs, pc, factory
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// TestPodControllerRunsOneCallPerPodKey pins the Virtual Kubelet property the provider's
// create and delete rest on (createBehindDelete, teardownPod): its work queue runs one
// handler per namespace/name, so a create and a delete of a pod never overlap, and the
// one delete it makes off that queue, at startup, is over before any worker runs. A
// module bump that loses this reds here. A witness pod's create is what shows, with no
// clock, that the queue was free to run the held key's next call and did not.
func TestPodControllerRunsOneCallPerPodKey(t *testing.T) {
	ctx := context.Background()

	t.Run("a delete of a pod waits for its create", func(t *testing.T) {
		p := newKeyedProvider()
		release := p.hold(t, "create p")
		pod := runningPod("pod", "p")
		cs, pc, factory := startPodController(t, p, pod)
		waitFor(t, "the create to be entered", func() bool { return p.wasEntered("create p") })
		waitFor(t, "the controller to be ready", func() bool { return isClosed(pc.Ready()) })

		stamped := pod.DeepCopy()
		now, grace := metav1.Now(), int64(0)
		stamped.DeletionTimestamp, stamped.DeletionGracePeriodSeconds = &now, &grace
		if _, err := cs.CoreV1().Pods("default").Update(ctx, stamped, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("stamp the pod: %v", err)
		}
		lister := factory.Core().V1().Pods().Lister()
		waitFor(t, "the informer to read the stamp", func() bool {
			got, err := lister.Pods("default").Get("pod")
			return err == nil && got.DeletionTimestamp != nil
		})
		if _, err := cs.CoreV1().Pods("default").Create(ctx, runningPod("witness", "w"), metav1.CreateOptions{}); err != nil {
			t.Fatalf("create the witness: %v", err)
		}
		waitFor(t, "the witness's create", func() bool { return p.wasEntered("create w") })
		if p.wasEntered("delete p") {
			t.Fatal("DeletePod ran inside the pod's CreatePod")
		}
		release()
		waitFor(t, "the delete to follow the create", func() bool { return p.wasEntered("delete p") })
		if got := p.overlapped(); len(got) != 0 {
			t.Errorf("calls that overlapped one of their key: %v", got)
		}
	})

	// One key, two UIDs: the queue serializes a same-name successor behind its
	// predecessor's delete, and the provider keeps them apart by UID.
	t.Run("a same-name re-create waits for its predecessor's delete", func(t *testing.T) {
		p := newKeyedProvider()
		release := p.hold(t, "delete p")
		cs, pc, _ := startPodController(t, p, runningPod("pod", "p"))
		waitFor(t, "the create to be entered", func() bool { return p.wasEntered("create p") })
		waitFor(t, "the controller to be ready", func() bool { return isClosed(pc.Ready()) })
		waitFor(t, "the provider to hold the pod", func() bool {
			got, err := p.GetPod(ctx, "default", "pod")
			return err == nil && got != nil
		})

		if err := cs.CoreV1().Pods("default").Delete(ctx, "pod", metav1.DeleteOptions{}); err != nil {
			t.Fatalf("delete the pod: %v", err)
		}
		waitFor(t, "the delete to be entered", func() bool { return p.wasEntered("delete p") })
		if _, err := cs.CoreV1().Pods("default").Create(ctx, runningPod("pod", "q"), metav1.CreateOptions{}); err != nil {
			t.Fatalf("re-create the pod: %v", err)
		}
		if _, err := cs.CoreV1().Pods("default").Create(ctx, runningPod("witness", "w"), metav1.CreateOptions{}); err != nil {
			t.Fatalf("create the witness: %v", err)
		}
		waitFor(t, "the witness's create", func() bool { return p.wasEntered("create w") })
		if p.wasEntered("create q") {
			t.Fatal("the successor's CreatePod ran inside its predecessor's DeletePod")
		}
		release()
		waitFor(t, "the successor's create to follow", func() bool { return p.wasEntered("create q") })
		if got := p.overlapped(); len(got) != 0 {
			t.Errorf("calls that overlapped one of their key: %v", got)
		}
	})

	t.Run("the startup delete of a dangling pod is over before any worker runs", func(t *testing.T) {
		p := newKeyedProvider()
		p.dangling = []*corev1.Pod{runningPod("dangling", "d")}
		release := p.hold(t, "delete d")
		_, pc, _ := startPodController(t, p, runningPod("pod", "p"))
		waitFor(t, "the dangling delete to be entered", func() bool { return p.wasEntered("delete d") })
		if isClosed(pc.Ready()) {
			t.Fatal("the controller's workers started inside the dangling delete")
		}
		if p.wasEntered("create p") {
			t.Fatal("a CreatePod ran inside the dangling delete")
		}
		release()
		waitFor(t, "the controller to be ready", func() bool { return isClosed(pc.Ready()) })
		waitFor(t, "the create to follow", func() bool { return p.wasEntered("create p") })
	})
}

// TestRecreateCoalescedWithDeleteRemovesOldPod drives a delete and a same-name re-create
// that reach one queue key as one sync, with the old pod running: its key is held inside
// an update while the object is force-deleted and created again, so the delete has no
// deletion stamp to show and no sync of its own. Virtual Kubelet then asks GetPod, is
// answered with the old pod, and compares specs without the UID: a successor with the
// same spec gets no provider call at all, and one with another gets UpdatePod under the
// new UID, whose track does not exist. Either way no DeletePod comes, nothing creates the
// successor, and only the orphan reaper ever stops the old pod.
//
// The old pod's stop has to finish before the successor's create is entered, from the
// old pod's own object, which alone carries its grace period.
func TestRecreateCoalescedWithDeleteRemovesOldPod(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name   string
		labels map[string]string
	}{
		{"a successor with the old pod's spec", map[string]string{"edit": "1"}},
		{"a successor with another spec", map[string]string{"edit": "2"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := newKeyedProvider()
			releaseUpdate := p.hold(t, "update old")
			releaseDelete := p.hold(t, "delete old")
			grace := int64(45)
			old := runningPod("pod", "old")
			old.Spec.TerminationGracePeriodSeconds = &grace
			cs, pc, _ := startPodController(t, p, old)
			pods := cs.CoreV1().Pods("default")
			waitFor(t, "the controller to be ready", func() bool { return isClosed(pc.Ready()) })
			waitFor(t, "the provider to hold the pod", func() bool {
				got, err := p.GetPod(ctx, "default", "pod")
				return err == nil && got != nil
			})

			edited := old.DeepCopy()
			edited.Labels = map[string]string{"edit": "1"}
			if _, err := pods.Update(ctx, edited, metav1.UpdateOptions{}); err != nil {
				t.Fatalf("edit the pod: %v", err)
			}
			waitFor(t, "the update to hold the key", func() bool { return p.wasEntered("update old") })

			if err := pods.Delete(ctx, "pod", metav1.DeleteOptions{}); err != nil {
				t.Fatalf("delete the pod: %v", err)
			}
			successor := runningPod("pod", "new")
			successor.Labels = tt.labels
			successor.Status = corev1.PodStatus{}
			if _, err := pods.Create(ctx, successor, metav1.CreateOptions{}); err != nil {
				t.Fatalf("re-create the pod: %v", err)
			}
			// Created behind the re-create, so its create says the informer has read it.
			if _, err := pods.Create(ctx, runningPod("witness", "w"), metav1.CreateOptions{}); err != nil {
				t.Fatalf("create the witness: %v", err)
			}
			waitFor(t, "the witness's create", func() bool { return p.wasEntered("create w") })

			releaseUpdate()
			waitFor(t, "the old pod's delete", func() bool { return p.wasEntered("delete old") })
			if _, err := pods.Create(ctx, runningPod("witness2", "w2"), metav1.CreateOptions{}); err != nil {
				t.Fatalf("create the second witness: %v", err)
			}
			waitFor(t, "the second witness's create", func() bool { return p.wasEntered("create w2") })
			if p.wasEntered("create new") {
				t.Fatal("the successor's CreatePod ran inside the old pod's DeletePod")
			}

			releaseDelete()
			waitFor(t, "the successor's create", func() bool { return p.wasEntered("create new") })
			want := []string{"create old", "update old", "delete old", "create new"}
			if got := p.callsOf("pod"); !slices.Equal(got, want) {
				t.Errorf("provider calls = %v, want %v", got, want)
			}
			if got := p.overlapped(); len(got) != 0 {
				t.Errorf("calls that overlapped one of their key: %v", got)
			}
			p.mu.Lock()
			deleted := p.deleted["old"]
			p.mu.Unlock()
			if got := deleted.Spec.TerminationGracePeriodSeconds; got == nil || *got != grace {
				t.Errorf("the deleted pod's grace = %v, want the old pod's %d", got, grace)
			}
			if deleted.UID != "old" {
				t.Errorf("the delete names UID %q, want the old pod", deleted.UID)
			}
		})
	}
}
