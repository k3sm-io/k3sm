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
	"sort"
	"time"

	dto "github.com/prometheus/client_model/go"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// The resource-metrics family names and label names, spelled EXACTLY as the
// kubelet's own /metrics/resource collector spells them
// (k8s.io/kubernetes/pkg/kubelet/metrics/collectors/resource_metrics.go). They are
// a wire contract, not a naming preference: metrics-server matches the family name
// byte-for-byte and reads the labels by name
// (metrics-server/pkg/scraper/client/resource/decode.go), so a synonym or a
// differently-spelled label is silently invisible to the only consumer this
// endpoint has.
//
// Note the deliberate divergence from the virtual-kubelet MOCK provider, which
// emits `node_`/`pod_`/`container_` prefixed families labelled NodeName/PodName/
// containerName. Those labels are the mock's own invention; metrics-server does not
// read them, so copying the mock would produce a well-formed endpoint that scrapes
// to nothing.
const (
	nodeCPUFamily      = "node_cpu_usage_seconds_total"
	nodeMemoryFamily   = "node_memory_working_set_bytes"
	podCPUFamily       = "pod_cpu_usage_seconds_total"
	podMemoryFamily    = "pod_memory_working_set_bytes"
	ctrCPUFamily       = "container_cpu_usage_seconds_total"
	ctrMemoryFamily    = "container_memory_working_set_bytes"
	ctrStartTimeFamily = "container_start_time_seconds"

	labelNamespace = "namespace"
	labelPod       = "pod"
	labelContainer = "container"
)

// buildResourceMetrics transcodes a kubelet Summary snapshot into the Prometheus
// families the kubelet's /metrics/resource endpoint serves — the scrape target
// metrics-server reads to populate metrics.k8s.io (so, `kubectl top` and
// HPA-on-CPU).
//
// # The joint-emission rule, and why it is the whole design
//
// CPU and memory are emitted TOGETHER or NOT AT ALL, per pod and for the node.
// metrics.k8s.io has no memory-only path: metrics-server computes CPU as a RATE
// between two cumulative samples and fills a single ResourceList carrying both
// resources, so its resource decoder DROPS a record that is missing either half —
// a node when `node.Timestamp.IsZero() || node.CumulativeCPUUsed == 0 ||
// node.MemoryUsage == 0`, and the WHOLE pod when any one of its containers has
// `containerMetric.CumulativeCPUUsed == 0 || containerMetric.MemoryUsage == 0`
// (metrics-server pkg/scraper/client/resource/decode.go).
//
// The consequence is counter-intuitive and is exactly the regression this function
// exists to avoid: an endpoint that published memory alone would be WORSE than
// publishing nothing. Every k3sm pod would be dropped on every scrape, `kubectl
// top` would stay empty, and the scraper would log a failure per pod per interval
// — where an endpoint serving nothing at all is merely unimplemented. So a pod
// whose CPU sample is missing is withheld here, deliberately and visibly, rather
// than half-published.
//
// The drop is applied at POD granularity for the same reason metrics-server
// applies it there: it aggregates a pod from its containers, so one incomplete
// container makes the pod's total wrong, not merely partial.
//
// # What is emitted
//
// Node level (no labels): node_cpu_usage_seconds_total, node_memory_working_set_bytes.
// Pod level (namespace, pod): pod_cpu_usage_seconds_total, pod_memory_working_set_bytes.
// Container level (namespace, pod, container): container_cpu_usage_seconds_total,
// container_memory_working_set_bytes, container_start_time_seconds.
//
// metrics-server itself consumes only the node_* and container_* families (it
// derives pod totals by summing containers); the pod_* families are emitted for
// parity with the kubelet's endpoint, which any other Prometheus consumer will
// expect to find there.
//
// CPU is reported in CORE-SECONDS as a monotone COUNTER — the cumulative CPU time
// runtimed reads from proc_pid_rusage. It is USAGE accounting, never a millicore
// entitlement: k3sm enforces no CFS quota (see DESIGN §5a / runtimed
// docs/resources.md), so a pod can exceed any `limits.cpu` it declares. Memory is
// the ri_phys_footprint working set as a GAUGE.
//
// Every sample carries its own timestamp, as the kubelet's collector does, so a
// consumer can tell a fresh sample from a stale one.
func buildResourceMetrics(summary *statsv1alpha1.Summary) []*dto.MetricFamily {
	if summary == nil {
		return nil
	}

	var (
		nodeCPU, nodeMem         []*dto.Metric
		podCPU, podMem           []*dto.Metric
		ctrCPU, ctrMem, ctrStart []*dto.Metric
	)

	// --- node ---
	if cpuSecs, cpuTime, okCPU := cpuSample(summary.Node.CPU); okCPU {
		if memBytes, memTime, okMem := memorySample(summary.Node.Memory); okMem {
			nodeCPU = append(nodeCPU, newMetric(nil, counterValue(cpuSecs), cpuTime))
			nodeMem = append(nodeMem, newMetric(nil, gaugeValue(memBytes), memTime))
		}
	}

	// --- pods ---
	pods := make([]statsv1alpha1.PodStats, len(summary.Pods))
	copy(pods, summary.Pods)
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].PodRef.Namespace != pods[j].PodRef.Namespace {
			return pods[i].PodRef.Namespace < pods[j].PodRef.Namespace
		}
		return pods[i].PodRef.Name < pods[j].PodRef.Name
	})

	for _, ps := range pods {
		rows, ok := podRows(ps)
		if !ok {
			continue
		}
		podCPU = append(podCPU, rows.podCPU)
		podMem = append(podMem, rows.podMemory)
		ctrCPU = append(ctrCPU, rows.containerCPU...)
		ctrMem = append(ctrMem, rows.containerMemory...)
		ctrStart = append(ctrStart, rows.containerStart...)
	}

	families := []*dto.MetricFamily{
		family(nodeCPUFamily, "Cumulative cpu time consumed by the node in core-seconds", dto.MetricType_COUNTER, nodeCPU),
		family(nodeMemoryFamily, "Current working set of the node in bytes", dto.MetricType_GAUGE, nodeMem),
		family(podCPUFamily, "Cumulative cpu time consumed by the pod in core-seconds", dto.MetricType_COUNTER, podCPU),
		family(podMemoryFamily, "Current working set of the pod in bytes", dto.MetricType_GAUGE, podMem),
		family(ctrCPUFamily, "Cumulative cpu time consumed by the container in core-seconds", dto.MetricType_COUNTER, ctrCPU),
		family(ctrMemoryFamily, "Current working set of the container in bytes", dto.MetricType_GAUGE, ctrMem),
		family(ctrStartTimeFamily, "Start time of the container since unix epoch in seconds", dto.MetricType_GAUGE, ctrStart),
	}

	out := make([]*dto.MetricFamily, 0, len(families))
	for _, mf := range families {
		// An empty family is omitted rather than published with no samples: a
		// present-but-empty family reads to a consumer as "the node has no pods",
		// which is a different (and unverified) claim from "no complete sample".
		if len(mf.GetMetric()) == 0 {
			continue
		}
		out = append(out, mf)
	}
	return out
}

// podResourceRows is one pod's complete, joint-verified set of metric rows.
type podResourceRows struct {
	podCPU          *dto.Metric
	podMemory       *dto.Metric
	containerCPU    []*dto.Metric
	containerMemory []*dto.Metric
	containerStart  []*dto.Metric
}

// podRows builds every row for one pod, reporting ok=false when the pod's sample
// is not JOINTLY complete — no containers at all, or any container (or the pod
// itself) missing CPU or memory. See buildResourceMetrics for why an incomplete
// pod is withheld whole rather than partially published.
func podRows(ps statsv1alpha1.PodStats) (podResourceRows, bool) {
	if len(ps.Containers) == 0 {
		return podResourceRows{}, false
	}
	podCPUSecs, podCPUTime, ok := cpuSample(ps.CPU)
	if !ok {
		return podResourceRows{}, false
	}
	podMemBytes, podMemTime, ok := memorySample(ps.Memory)
	if !ok {
		return podResourceRows{}, false
	}

	ns, name := ps.PodRef.Namespace, ps.PodRef.Name
	podLabels := []*dto.LabelPair{
		labelPair(labelNamespace, ns),
		labelPair(labelPod, name),
	}

	containers := make([]statsv1alpha1.ContainerStats, len(ps.Containers))
	copy(containers, ps.Containers)
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })

	rows := podResourceRows{
		podCPU:    newMetric(podLabels, counterValue(podCPUSecs), podCPUTime),
		podMemory: newMetric(podLabels, gaugeValue(podMemBytes), podMemTime),
	}
	for _, c := range containers {
		cpuSecs, cpuTime, okCPU := cpuSample(c.CPU)
		if !okCPU {
			return podResourceRows{}, false
		}
		memBytes, memTime, okMem := memorySample(c.Memory)
		if !okMem {
			return podResourceRows{}, false
		}
		ctrLabels := []*dto.LabelPair{
			labelPair(labelNamespace, ns),
			labelPair(labelPod, name),
			labelPair(labelContainer, c.Name),
		}
		rows.containerCPU = append(rows.containerCPU, newMetric(ctrLabels, counterValue(cpuSecs), cpuTime))
		rows.containerMemory = append(rows.containerMemory, newMetric(ctrLabels, gaugeValue(memBytes), memTime))
		if !c.StartTime.Time.IsZero() {
			start := float64(c.StartTime.UnixNano()) / float64(time.Second)
			rows.containerStart = append(rows.containerStart, newMetric(ctrLabels, gaugeValue(start), c.StartTime.Time))
		}
	}
	return rows, true
}

// cpuSample extracts cumulative CPU as CORE-SECONDS plus its sample time.
//
// ok is false when the sample is absent OR ZERO, because zero is precisely what
// the consumer treats as missing (its decoder drops on `CumulativeCPUUsed == 0`).
// Distinguishing "genuinely used no CPU" from "not sampled" is not possible on the
// wire, so k3sm resolves it the same way the consumer does rather than publishing a
// record the consumer will throw away.
func cpuSample(c *statsv1alpha1.CPUStats) (seconds float64, ts time.Time, ok bool) {
	if c == nil || c.UsageCoreNanoSeconds == nil || *c.UsageCoreNanoSeconds == 0 {
		return 0, time.Time{}, false
	}
	return float64(*c.UsageCoreNanoSeconds) / float64(time.Second), c.Time.Time, true
}

// memorySample extracts the working set in bytes plus its sample time. ok is false
// for an absent or zero working set, for the same reason cpuSample rejects zero.
func memorySample(m *statsv1alpha1.MemoryStats) (bytes float64, ts time.Time, ok bool) {
	if m == nil || m.WorkingSetBytes == nil || *m.WorkingSetBytes == 0 {
		return 0, time.Time{}, false
	}
	return float64(*m.WorkingSetBytes), m.Time.Time, true
}

// family assembles a MetricFamily. Metrics are attached as given (already ordered
// by the caller) so the endpoint's output is deterministic across scrapes.
func family(name, help string, typ dto.MetricType, metrics []*dto.Metric) *dto.MetricFamily {
	n, h, t := name, help, typ
	return &dto.MetricFamily{Name: &n, Help: &h, Type: &t, Metric: metrics}
}

// newMetric attaches labels and a sample timestamp to a value. The timestamp is
// carried per-sample exactly as the kubelet's collector does, so a consumer can
// detect a stale scrape; a zero time is left off rather than encoded as the epoch.
func newMetric(labels []*dto.LabelPair, set func(*dto.Metric), ts time.Time) *dto.Metric {
	m := &dto.Metric{Label: labels}
	set(m)
	if !ts.IsZero() {
		ms := ts.UnixMilli()
		m.TimestampMs = &ms
	}
	return m
}

// counterValue sets a counter value on a metric.
func counterValue(v float64) func(*dto.Metric) {
	return func(m *dto.Metric) { x := v; m.Counter = &dto.Counter{Value: &x} }
}

// gaugeValue sets a gauge value on a metric.
func gaugeValue(v float64) func(*dto.Metric) {
	return func(m *dto.Metric) { x := v; m.Gauge = &dto.Gauge{Value: &x} }
}

// labelPair builds one label pair.
func labelPair(name, value string) *dto.LabelPair {
	n, v := name, value
	return &dto.LabelPair{Name: &n, Value: &v}
}
