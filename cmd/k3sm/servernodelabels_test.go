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
	"errors"
	"log/slog"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/provider"
)

// TestControlPlaneNodeLabel pins the server role label, set as k3s sets it: a
// server's Node carries node-role.kubernetes.io/control-plane=true, written once
// through the admin client with every other label kept, and a worker's Node does
// not, because the only label a worker's own registration stamps is
// configureNode's set, which never names it.
func TestControlPlaneNodeLabel(t *testing.T) {
	const name = "k3sm-server"
	patches := func(cs *fake.Clientset) int {
		n := 0
		for _, a := range cs.Actions() {
			if a.GetVerb() == "patch" {
				n++
			}
		}
		return n
	}
	node := func(labels map[string]string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	}
	for _, tc := range []struct {
		name        string
		objs        []runtime.Object
		wantErr     error
		wantChanged bool
		wantLabels  map[string]string
	}{
		{
			name:        "a server Node gains the label, every other label kept",
			objs:        []runtime.Object{node(map[string]string{"kubernetes.io/os": "darwin", "team": "ops"})},
			wantChanged: true,
			wantLabels:  map[string]string{"kubernetes.io/os": "darwin", "team": "ops", controlPlaneNodeLabel: "true"},
		},
		{
			name:       "already labelled: no write",
			objs:       []runtime.Object{node(map[string]string{controlPlaneNodeLabel: "true"})},
			wantLabels: map[string]string{controlPlaneNodeLabel: "true"},
		},
		{
			name:        "an empty value is set to k3s's value",
			objs:        []runtime.Object{node(map[string]string{controlPlaneNodeLabel: ""})},
			wantChanged: true,
			wantLabels:  map[string]string{controlPlaneNodeLabel: "true"},
		},
		{
			name:    "no Node yet (first boot)",
			wantErr: errNodeNotRegistered,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(tc.objs...)
			changed, err := ensureControlPlaneLabel(context.Background(), cs.CoreV1().Nodes(), name)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if want := map[bool]int{true: 1, false: 0}[tc.wantChanged]; patches(cs) != want {
				t.Errorf("%d patches, want %d", patches(cs), want)
			}
			if tc.wantErr != nil {
				return
			}
			n, err := cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(n.Labels, tc.wantLabels) {
				t.Errorf("labels = %v, want %v", n.Labels, tc.wantLabels)
			}
		})
	}

	t.Run("a worker Node does not carry it", func(t *testing.T) {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-worker"}}
		configureNode(n, "k3sm-worker", "100.64.1.1", nodeKubeletListen, provider.NodeCapabilities{})
		if v, ok := n.Labels[controlPlaneNodeLabel]; ok {
			t.Errorf("a worker's registration stamps %s=%q; only the server's admin client may set it", controlPlaneNodeLabel, v)
		}
	})
}

// TestLabelServerNode pins the first-boot path: the server's Node registers only
// after the server prepared it, so the label is retried until the Node appears,
// and the loop ends once it is set, or when ctx ends.
func TestLabelServerNode(t *testing.T) {
	const name = "k3sm-server"
	logger := slog.New(slog.DiscardHandler)

	t.Run("labels the Node once it registers", func(t *testing.T) {
		cs := fake.NewClientset()
		gets := 0
		cs.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			gets++
			if gets == 2 {
				if err := cs.Tracker().Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
					t.Error(err)
				}
			}
			return false, nil, nil
		})
		done := make(chan struct{})
		go func() {
			defer close(done)
			labelServerNode(context.Background(), cs.CoreV1().Nodes(), name, time.Millisecond, logger)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("labelServerNode did not return after the Node registered")
		}
		n, err := cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if n.Labels[controlPlaneNodeLabel] != controlPlaneNodeLabelValue {
			t.Errorf("labels = %v, want %s=%s", n.Labels, controlPlaneNodeLabel, controlPlaneNodeLabelValue)
		}
	})

	t.Run("it honours ctx while the Node is absent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			labelServerNode(ctx, fake.NewClientset().CoreV1().Nodes(), name, time.Hour, logger)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("labelServerNode did not return on a cancelled ctx")
		}
	})
}
