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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"

	"k3sm.io/k3sm/pkg/dataroot"
)

// The metrics API `k3sm status top` reads. It is read as raw JSON through the
// report's own client into the small local shapes below, so the view needs no
// metrics client module; only the usage fields it prints are decoded.
const (
	// MetricsAPIService is the APIService metrics-server registers.
	MetricsAPIService = "v1beta1.metrics.k8s.io"

	metricsAPIServicePath = "/apis/apiregistration.k8s.io/v1/apiservices/" + MetricsAPIService
	nodeMetricsPath       = "/apis/metrics.k8s.io/v1beta1/nodes"
	podMetricsPath        = "/apis/metrics.k8s.io/v1beta1/pods"
)

// TopMetricsMinInterval is the shortest time between two reads of the metrics
// API, whatever --watch interval was asked for. metrics-server resolves at 15s,
// so reading it faster only repeats a sample; the age column shows the lag.
const TopMetricsMinInterval = 5 * time.Second

// DefaultTopLimit is how many pod rows `k3sm status top` prints by default.
const DefaultTopLimit = 20

// TopSchemaVersion is the version of the `k3sm status top -o json` shape.
const TopSchemaVersion = 1

// TopSort orders the pod table: by the named resource first, the other second.
type TopSort string

// The two pod-table orders.
const (
	TopSortCPU    TopSort = "cpu"
	TopSortMemory TopSort = "memory"
)

// TopOptions narrow the view: the pod order, a namespace (empty means all) and
// the number of pod rows (zero means all of them). The node table is never
// narrowed: it describes the cluster's load, which a namespace does not change.
type TopOptions struct {
	Sort      TopSort
	Namespace string
	Limit     int
}

// Reasons the metrics header gives when the APIService itself has none to give.
const (
	// TopReasonNotRegistered: the APIService does not exist.
	TopReasonNotRegistered = "NotRegistered"
	// TopReasonUnreadable: the APIService could not be read.
	TopReasonUnreadable = "Unreadable"
	// TopReasonNoCondition: the APIService carries no Available condition yet.
	TopReasonNoCondition = "NoCondition"
	// TopReasonReadFailed: the APIService says Available, and reading the
	// metrics themselves failed.
	TopReasonReadFailed = "ReadFailed"
)

// TopMetrics says whether usage could be read, and when it could not, why: the
// reason and message of the APIService's Available condition, or one of the
// TopReason* values when the APIService gave none.
type TopMetrics struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

// TopCPU is a CPU figure in millicores. Used and Percent are null when there is
// no sample for the row.
type TopCPU struct {
	UsedMillicores        *int64 `json:"usedMillicores"`
	AllocatableMillicores int64  `json:"allocatableMillicores"`
	Percent               *int64 `json:"percent"`
}

// TopMemory is a memory figure in bytes. Used and Percent are null when there
// is no sample for the row.
type TopMemory struct {
	UsedBytes        *int64 `json:"usedBytes"`
	AllocatableBytes int64  `json:"allocatableBytes"`
	Percent          *int64 `json:"percent"`
}

// TopNode is one row of the node table.
type TopNode struct {
	Name string `json:"name"`
	// Role is "server" when the Node carries the control-plane label, "agent"
	// otherwise, as in the full report's workers.
	Role dataroot.Role `json:"role"`
	// Sampled is false when metrics-server has no sample for the node yet.
	Sampled bool      `json:"sampled"`
	CPU     TopCPU    `json:"cpu"`
	Memory  TopMemory `json:"memory"`
	// Pods counts the node's non-terminated pods in every namespace.
	Pods int `json:"pods"`
	// SampleAgeSeconds is how old the sample is, null with no sample.
	SampleAgeSeconds *int64 `json:"sampleAgeSeconds"`
}

// TopPod is one row of the pod table.
type TopPod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Node is empty while the pod is unscheduled.
	Node          string `json:"node"`
	Sampled       bool   `json:"sampled"`
	CPUMillicores *int64 `json:"cpuMillicores"`
	MemoryBytes   *int64 `json:"memoryBytes"`
	Restarts      int32  `json:"restarts"`
}

// TopReport is one frame of `k3sm status top`, and its JSON shape.
type TopReport struct {
	SchemaVersion int       `json:"schemaVersion"`
	Timestamp     time.Time `json:"timestamp"`
	// ClusterError is set when the nodes or pods could not be read at all; the
	// tables are then empty.
	ClusterError string     `json:"clusterError,omitempty"`
	Metrics      TopMetrics `json:"metrics"`
	Sort         TopSort    `json:"sort"`
	Namespace    string     `json:"namespace,omitempty"`
	Limit        int        `json:"limit"`
	Nodes        []TopNode  `json:"nodes"`
	// PodsTotal is how many pods matched before --limit cut the table.
	PodsTotal int      `json:"podsTotal"`
	Pods      []TopPod `json:"pods"`
}

// TopCollector reads the core API and the metrics API for `k3sm status top`.
//
// It keeps the last metrics sample between frames so a --watch loop faster than
// TopMetricsMinInterval re-reads the nodes, pods and APIService every frame but
// the metrics API at most every TopMetricsMinInterval. A collector is used from
// one goroutine (the status command's render loop), so the cache takes no lock.
type TopCollector struct {
	Kube Kube
	// KubeErr is why there is no Kube, reported as the cluster error.
	KubeErr error
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	// tried, attempted, sample and sampleErr are the last read of the metrics
	// API: when it was made, and what it returned.
	tried     bool
	attempted time.Time
	sample    *topSample
	sampleErr error
}

// topSample is one read of the metrics API.
type topSample struct {
	nodes map[string]usageSample
	pods  map[string]usageSample
}

// usageSample is one object's usage at a timestamp.
type usageSample struct {
	cpuMilli    int64
	memoryBytes int64
	timestamp   time.Time
}

// The local slices of NodeMetrics, PodMetrics and APIService this view reads.
type (
	metricsObjectMeta struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	nodeMetricsList struct {
		Items []struct {
			Metadata  metricsObjectMeta            `json:"metadata"`
			Timestamp time.Time                    `json:"timestamp"`
			Usage     map[string]resource.Quantity `json:"usage"`
		} `json:"items"`
	}
	podMetricsList struct {
		Items []struct {
			Metadata   metricsObjectMeta `json:"metadata"`
			Timestamp  time.Time         `json:"timestamp"`
			Containers []struct {
				Usage map[string]resource.Quantity `json:"usage"`
			} `json:"containers"`
		} `json:"items"`
	}
	apiService struct {
		Status struct {
			Conditions []struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"conditions"`
		} `json:"status"`
	}
)

func (c *TopCollector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Collect reads one frame. It never fails: a cluster that cannot be read is the
// report's ClusterError, and metrics that cannot be read are its Metrics reason,
// with the tables filled from the core API alone.
func (c *TopCollector) Collect(ctx context.Context, o TopOptions) TopReport {
	if o.Sort == "" {
		o.Sort = TopSortCPU
	}
	now := c.now()
	rep := TopReport{
		SchemaVersion: TopSchemaVersion,
		Timestamp:     now,
		Sort:          o.Sort,
		Namespace:     o.Namespace,
		Limit:         o.Limit,
		Nodes:         []TopNode{},
		Pods:          []TopPod{},
	}
	if c.Kube == nil {
		err := c.KubeErr
		if err == nil {
			err = errors.New("no apiserver client")
		}
		rep.ClusterError = Redact(err.Error())
		return rep
	}
	nodes, err := c.Kube.Nodes(ctx)
	if err != nil {
		rep.ClusterError = Redact(fmt.Sprintf("list nodes: %v", err))
		return rep
	}
	pods, err := c.Kube.Pods(ctx)
	if err != nil {
		rep.ClusterError = Redact(fmt.Sprintf("list pods: %v", err))
		return rep
	}
	rep.Metrics = c.readMetrics(ctx, now)
	sample := c.sample
	if !rep.Metrics.Available {
		sample = nil
	}
	rep.Nodes = topNodes(nodes, pods, sample, now)
	rep.PodsTotal, rep.Pods = topPods(pods, sample, o)
	return rep
}

// readMetrics reads the APIService's Available condition every frame, and the
// metrics themselves when it is True and the last read, successful or not, is
// at least TopMetricsMinInterval old. A failed read is therefore not retried on
// the next fast frame either.
func (c *TopCollector) readMetrics(ctx context.Context, now time.Time) TopMetrics {
	state := c.apiServiceState(ctx)
	if !state.Available {
		return state
	}
	if !c.tried || now.Sub(c.attempted) >= TopMetricsMinInterval {
		c.tried, c.attempted = true, now
		c.sample, c.sampleErr = c.fetchSample(ctx)
	}
	if c.sampleErr != nil {
		return TopMetrics{Reason: TopReasonReadFailed, Message: Redact(c.sampleErr.Error())}
	}
	return state
}

// apiServiceState reads v1beta1.metrics.k8s.io and reports its Available
// condition.
func (c *TopCollector) apiServiceState(ctx context.Context) TopMetrics {
	raw, err := c.Kube.RawGet(ctx, metricsAPIServicePath)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return TopMetrics{Reason: TopReasonNotRegistered, Message: "the APIService " + MetricsAPIService + " does not exist; metrics-server is not installed"}
		}
		return TopMetrics{Reason: TopReasonUnreadable, Message: Redact(fmt.Sprintf("read the APIService %s: %v", MetricsAPIService, err))}
	}
	var svc apiService
	if err := json.Unmarshal(raw, &svc); err != nil {
		return TopMetrics{Reason: TopReasonUnreadable, Message: fmt.Sprintf("decode the APIService %s: %v", MetricsAPIService, err)}
	}
	for _, cond := range svc.Status.Conditions {
		if cond.Type != "Available" {
			continue
		}
		if cond.Status == string(corev1.ConditionTrue) {
			return TopMetrics{Available: true}
		}
		return TopMetrics{Reason: cond.Reason, Message: Redact(cond.Message)}
	}
	return TopMetrics{Reason: TopReasonNoCondition, Message: "the APIService " + MetricsAPIService + " reports no Available condition yet"}
}

// fetchSample reads NodeMetrics and PodMetrics once.
func (c *TopCollector) fetchSample(ctx context.Context) (*topSample, error) {
	rawNodes, err := c.Kube.RawGet(ctx, nodeMetricsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", nodeMetricsPath, err)
	}
	var nl nodeMetricsList
	if err := json.Unmarshal(rawNodes, &nl); err != nil {
		return nil, fmt.Errorf("decode %s: %w", nodeMetricsPath, err)
	}
	rawPods, err := c.Kube.RawGet(ctx, podMetricsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", podMetricsPath, err)
	}
	var pl podMetricsList
	if err := json.Unmarshal(rawPods, &pl); err != nil {
		return nil, fmt.Errorf("decode %s: %w", podMetricsPath, err)
	}
	s := &topSample{nodes: map[string]usageSample{}, pods: map[string]usageSample{}}
	for _, it := range nl.Items {
		cpu, mem := it.Usage[string(corev1.ResourceCPU)], it.Usage[string(corev1.ResourceMemory)]
		s.nodes[it.Metadata.Name] = usageSample{cpuMilli: cpu.MilliValue(), memoryBytes: mem.Value(), timestamp: it.Timestamp}
	}
	for _, it := range pl.Items {
		var cpu, mem resource.Quantity
		for _, ctr := range it.Containers {
			cpu.Add(ctr.Usage[string(corev1.ResourceCPU)])
			mem.Add(ctr.Usage[string(corev1.ResourceMemory)])
		}
		s.pods[podKey(it.Metadata.Namespace, it.Metadata.Name)] = usageSample{cpuMilli: cpu.MilliValue(), memoryBytes: mem.Value(), timestamp: it.Timestamp}
	}
	return s, nil
}

func podKey(namespace, name string) string { return namespace + "/" + name }

// terminated reports whether a pod has finished, which is when it stops
// counting against its node, as in `kubectl describe node`.
func terminated(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

// topNodes builds the node table, sorted by name so a node keeps its line from
// frame to frame.
func topNodes(nodes []corev1.Node, pods []corev1.Pod, sample *topSample, now time.Time) []TopNode {
	count := map[string]int{}
	for i := range pods {
		if p := &pods[i]; !terminated(p) && p.Spec.NodeName != "" {
			count[p.Spec.NodeName]++
		}
	}
	out := make([]TopNode, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		row := TopNode{Name: n.Name, Role: dataroot.RoleAgent, Pods: count[n.Name]}
		if _, cp := n.Labels[controlPlaneNodeLabel]; cp {
			row.Role = dataroot.RoleServer
		}
		allocCPU, allocMem := n.Status.Allocatable[corev1.ResourceCPU], n.Status.Allocatable[corev1.ResourceMemory]
		row.CPU.AllocatableMillicores = allocCPU.MilliValue()
		row.Memory.AllocatableBytes = allocMem.Value()
		if sample != nil {
			if u, ok := sample.nodes[n.Name]; ok {
				row.Sampled = true
				row.CPU.UsedMillicores = ptr(u.cpuMilli)
				row.CPU.Percent = percent(u.cpuMilli, row.CPU.AllocatableMillicores)
				row.Memory.UsedBytes = ptr(u.memoryBytes)
				row.Memory.Percent = percent(u.memoryBytes, row.Memory.AllocatableBytes)
				age := max(int64(now.Sub(u.timestamp)/time.Second), 0)
				row.SampleAgeSeconds = &age
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// topPods builds the pod table: the non-terminated pods of the namespace,
// sampled pods first by the chosen resource then the other (both descending),
// ties and unsampled pods by namespace and name. It returns the number that
// matched before the limit.
func topPods(pods []corev1.Pod, sample *topSample, o TopOptions) (int, []TopPod) {
	out := []TopPod{}
	for i := range pods {
		p := &pods[i]
		if terminated(p) || (o.Namespace != "" && p.Namespace != o.Namespace) {
			continue
		}
		row := TopPod{Namespace: p.Namespace, Name: p.Name, Node: p.Spec.NodeName, Restarts: restarts(p)}
		if sample != nil {
			if u, ok := sample.pods[podKey(p.Namespace, p.Name)]; ok {
				row.Sampled = true
				row.CPUMillicores = ptr(u.cpuMilli)
				row.MemoryBytes = ptr(u.memoryBytes)
			}
		}
		out = append(out, row)
	}
	keys := func(p TopPod) (int64, int64) {
		if !p.Sampled {
			return 0, 0
		}
		if o.Sort == TopSortMemory {
			return *p.MemoryBytes, *p.CPUMillicores
		}
		return *p.CPUMillicores, *p.MemoryBytes
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Sampled != b.Sampled {
			return a.Sampled
		}
		a1, a2 := keys(a)
		b1, b2 := keys(b)
		if a1 != b1 {
			return a1 > b1
		}
		if a2 != b2 {
			return a2 > b2
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	total := len(out)
	if o.Limit > 0 && len(out) > o.Limit {
		out = out[:o.Limit]
	}
	return total, out
}

// restarts counts a pod's restarts the way `kubectl get pods` does once it is
// initialised: every app container, plus the sidecars (restartable init
// containers), whose restarts are the pod's restarts too.
func restarts(p *corev1.Pod) int32 {
	sidecar := map[string]bool{}
	for _, c := range p.Spec.InitContainers {
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			sidecar[c.Name] = true
		}
	}
	var n int32
	for _, s := range p.Status.InitContainerStatuses {
		if sidecar[s.Name] {
			n += s.RestartCount
		}
	}
	for _, s := range p.Status.ContainerStatuses {
		n += s.RestartCount
	}
	return n
}

// percent is used as a whole percentage of allocatable, truncated as `kubectl
// top node` truncates it; null when there is nothing allocatable to divide by.
func percent(used, allocatable int64) *int64 {
	if allocatable <= 0 {
		return nil
	}
	return ptr(used * 100 / allocatable)
}

func ptr(v int64) *int64 { return &v }
