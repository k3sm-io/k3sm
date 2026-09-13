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

package podlogs

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeBackend answers the handler's three questions from fixed values and
// records the options it was handed, so the table below can assert BOTH the
// status code and that the decoded options reached the reader intact.
type fakeBackend struct {
	mu     sync.Mutex
	pod    *corev1.Pod
	status *corev1.PodStatus
	body   string
	err    error
	got    *corev1.PodLogOptions
	// block, when non-nil, holds ContainerLogs until it is closed — the way a
	// `-f` on a silent container behaves.
	block chan struct{}
}

func (f *fakeBackend) GetPodByName(_ context.Context, _, _ string) (*corev1.Pod, bool) {
	if f.pod == nil {
		return nil, false
	}
	return f.pod, true
}

func (f *fakeBackend) GetPodStatus(context.Context, string, string) (*corev1.PodStatus, error) {
	return f.status, nil
}

func (f *fakeBackend) ContainerLogs(_ context.Context, _, _, _ string, opts *corev1.PodLogOptions, stdout, _ io.Writer) error {
	f.mu.Lock()
	f.got = opts
	f.mu.Unlock()
	if f.block != nil {
		<-f.block
	}
	if f.err != nil {
		return f.err
	}
	_, err := io.WriteString(stdout, f.body)
	return err
}

// logPod is a pod with one regular, one init and one ephemeral container.
func logPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{{Name: "c0"}},
			InitContainers: []corev1.Container{{Name: "init0"}},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"}},
			},
		},
	}
}

// runningStatus is a status whose named container is running.
func runningStatus(name string) *corev1.PodStatus {
	return &corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		Name:        name,
		ContainerID: "runtimed://abc123",
		State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}}
}

// TestContainerLogsHandlerMatchesKubelet is the status-code and body table for
// GET /containerLogs/<ns>/<pod>/<container>.
//
// `kubectl logs` reaches a node through the apiserver's proxy to this path, so
// the codes and the exact body strings ARE the contract as far as kubectl and
// every client library are concerned — including the two bodies that are JSON
// while their neighbours are plain text, which is upstream's inconsistency and
// therefore also k3sm's.
func TestContainerLogsHandlerMatchesKubelet(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		backend  *fakeBackend
		wantCode int
		wantBody string
		// wantOpts, when non-nil, asserts what reached the reader.
		wantOpts func(t *testing.T, opts *corev1.PodLogOptions)
	}{
		{
			name:     "missing podID",
			path:     "/containerLogs/default",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusBadRequest,
			wantBody: `{"message": "Missing podID."}`,
		},
		{
			name:     "missing container name",
			path:     "/containerLogs/default/web",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusBadRequest,
			wantBody: `{"message": "Missing container name."}`,
		},
		{
			name:     "missing namespace",
			path:     "/containerLogs//web/c0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusBadRequest,
			wantBody: `{"message": "Missing podNamespace."}`,
		},
		{
			name:     "an undecodable query",
			path:     "/containerLogs/default/web/c0?tailLines=notanumber",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusBadRequest,
			wantBody: `{"message": "Unable to decode query."}`,
		},
		{
			name:     "a negative tailLines is invalid",
			path:     "/containerLogs/default/web/c0?tailLines=-1",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: `{"message": "Invalid request."}`,
		},
		{
			name:     "limitBytes below 1 is invalid",
			path:     "/containerLogs/default/web/c0?limitBytes=0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: `{"message": "Invalid request."}`,
		},
		{
			name:     "sinceSeconds below 1 is invalid",
			path:     "/containerLogs/default/web/c0?sinceSeconds=0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: `{"message": "Invalid request."}`,
		},
		{
			name:     "both since forms together are invalid",
			path:     "/containerLogs/default/web/c0?sinceSeconds=10&sinceTime=2026-09-13T10:00:00Z",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: `{"message": "Invalid request."}`,
		},
		{
			// PodLogsQuerySplitStreams is Alpha and defaults to FALSE at v1.36.2,
			// and k3sm registers no feature gates, so ANY stream selection is
			// forbidden — which is exactly what a kubelet with the gate off does.
			name:     "stream selection is rejected with the gate off",
			path:     "/containerLogs/default/web/c0?stream=Stdout",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: `{"message": "Invalid request."}`,
		},
		{
			name:     "stream=All is rejected too, with the gate off",
			path:     "/containerLogs/default/web/c0?stream=All",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: `{"message": "Invalid request."}`,
		},
		{
			name:     "an unknown pod",
			path:     "/containerLogs/default/web/c0",
			backend:  &fakeBackend{status: runningStatus("c0")},
			wantCode: http.StatusNotFound,
			wantBody: `pod "web" does not exist`,
		},
		{
			name:     "an unknown container",
			path:     "/containerLogs/default/web/nope",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusNotFound,
			wantBody: `container "nope" not found in pod "web"`,
		},
		{
			name:     "previous with no terminated instance",
			path:     "/containerLogs/default/web/c0?previous=true",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusBadRequest,
			wantBody: `previous terminated container "c0" in pod "web" not found`,
		},
		{
			name: "a waiting container explains why instead of returning nothing",
			path: "/containerLogs/default/web/c0",
			backend: &fakeBackend{pod: logPod(), status: &corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "c0",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}},
			}}}},
			wantCode: http.StatusBadRequest,
			wantBody: `container "c0" in pod "web" is waiting to start: trying and failing to pull image`,
		},
		{
			// A read failure that happens AFTER the priming write can no longer
			// change the status code — the 200 is already on the wire — so the
			// raw error text is appended to the body, which is what upstream does
			// and what the client shows. The failures that CAN still be a 400 are
			// the ones ValidateContainerLogStatus catches, two rows up.
			name:     "a read failure surfaces its raw text in the body",
			path:     "/containerLogs/default/web/c0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0"), err: errRead},
			wantCode: http.StatusOK,
			wantBody: "the log file went away",
		},
		{
			name:     "a plain request streams the log",
			path:     "/containerLogs/default/web/c0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0"), body: "hello\n"},
			wantCode: http.StatusOK,
			wantBody: "hello\n",
			wantOpts: func(t *testing.T, opts *corev1.PodLogOptions) {
				if opts.TailLines != nil {
					t.Errorf("TailLines = %d, want unset (no tail asked for)", *opts.TailLines)
				}
			},
		},
		{
			name:     "tailLines=0 reaches the reader as zero, not as unset",
			path:     "/containerLogs/default/web/c0?tailLines=0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusOK,
			wantBody: "",
			wantOpts: func(t *testing.T, opts *corev1.PodLogOptions) {
				if opts.TailLines == nil {
					t.Fatal("TailLines is nil; `--tail=0` must mean zero lines, which an int cannot express")
				}
				if *opts.TailLines != 0 {
					t.Errorf("TailLines = %d, want 0", *opts.TailLines)
				}
			},
		},
		{
			name:     "the legacy tail parameter becomes tailLines",
			path:     "/containerLogs/default/web/c0?tail=5",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusOK,
			wantOpts: func(t *testing.T, opts *corev1.PodLogOptions) {
				if opts.TailLines == nil || *opts.TailLines != 5 {
					t.Errorf("TailLines = %v, want 5", opts.TailLines)
				}
			},
		},
		{
			name:     "tail=all is the ABSENCE of a limit, not a value",
			path:     "/containerLogs/default/web/c0?tail=all",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusOK,
			wantOpts: func(t *testing.T, opts *corev1.PodLogOptions) {
				if opts.TailLines != nil {
					t.Errorf("TailLines = %d, want unset for tail=all", *opts.TailLines)
				}
			},
		},
		{
			name:     "an init container's logs are addressable",
			path:     "/containerLogs/default/web/init0",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("init0"), body: "init output\n"},
			wantCode: http.StatusOK,
			wantBody: "init output\n",
		},
		{
			name:     "an ephemeral container's logs are addressable",
			path:     "/containerLogs/default/web/debug",
			backend:  &fakeBackend{pod: logPod(), status: ephemeralRunning("debug"), body: "debug output\n"},
			wantCode: http.StatusOK,
			wantBody: "debug output\n",
		},
		{
			name:     "every option round-trips to the reader",
			path:     "/containerLogs/default/web/c0?tailLines=3&limitBytes=64&timestamps=true&follow=true&sinceSeconds=90",
			backend:  &fakeBackend{pod: logPod(), status: runningStatus("c0")},
			wantCode: http.StatusOK,
			wantOpts: func(t *testing.T, opts *corev1.PodLogOptions) {
				if opts.TailLines == nil || *opts.TailLines != 3 {
					t.Errorf("TailLines = %v, want 3", opts.TailLines)
				}
				if opts.LimitBytes == nil || *opts.LimitBytes != 64 {
					t.Errorf("LimitBytes = %v, want 64", opts.LimitBytes)
				}
				if opts.SinceSeconds == nil || *opts.SinceSeconds != 90 {
					t.Errorf("SinceSeconds = %v, want 90", opts.SinceSeconds)
				}
				if !opts.Timestamps || !opts.Follow {
					t.Errorf("Timestamps/Follow = %v/%v, want true/true", opts.Timestamps, opts.Follow)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(tt.backend, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
			if tt.wantOpts != nil {
				tt.backend.mu.Lock()
				got := tt.backend.got
				tt.backend.mu.Unlock()
				if got == nil {
					t.Fatal("the reader was never called")
				}
				tt.wantOpts(t, got)
			}
		})
	}

	// The zero-byte priming write: a `-f` on a container that has said nothing
	// must return its headers immediately rather than appearing to hang. The
	// backend below blocks forever, so the headers can only have been committed
	// by the priming write.
	t.Run("follow commits the response before any output arrives", func(t *testing.T) {
		block := make(chan struct{})
		b := &fakeBackend{pod: logPod(), status: runningStatus("c0"), block: block}
		h := NewHandler(b, nil)

		srv := httptest.NewServer(h)
		// Order matters: Close waits for the in-flight handler, so the blocked
		// read has to be released FIRST or the test deadlocks on its own fixture.
		defer srv.Close()
		defer close(block)

		resp, err := http.Get(srv.URL + "/containerLogs/default/web/c0?follow=true")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 before any log output", resp.StatusCode)
		}
		if got := resp.TransferEncoding; len(got) != 1 || got[0] != "chunked" {
			t.Errorf("Transfer-Encoding = %v, want [chunked]", got)
		}
	})
}

// errRead is the read failure the table asserts on.
var errRead = errTest("the log file went away")

// errTest is a minimal error type for the table.
type errTest string

// Error returns the message.
func (e errTest) Error() string { return string(e) }

// ephemeralRunning is a status whose EPHEMERAL container is running.
func ephemeralRunning(name string) *corev1.PodStatus {
	return &corev1.PodStatus{EphemeralContainerStatuses: []corev1.ContainerStatus{{
		Name:        name,
		ContainerID: "runtimed://abc123",
		State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}}
}
