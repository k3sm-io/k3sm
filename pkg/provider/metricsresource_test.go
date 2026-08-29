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
	"bytes"
	"context"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// --- the consumer fake -------------------------------------------------------
//
// scrapeAsMetricsServer is a deliberate re-implementation of the ONLY consumer
// this endpoint has: metrics-server's resource scrape client
// (pkg/scraper/client/resource/decode.go). It is not a convenience wrapper over
// the producer — it goes through the real wire:
//
//  1. encode the families to Prometheus text with expfmt, which is exactly what
//     virtual-kubelet's HandlePodMetricsResource does before writing the HTTP
//     response (node/api/metrics.go), so a family the encoder rejects fails here;
//  2. parse that text back with the Prometheus text parser, as metrics-server does;
//  3. apply metrics-server's own decode + completeness rules.
//
// Rule (3) is the reason this fake exists at all. metrics-server keeps a record
// ONLY when it has both halves:
//
//   - a node is kept only if its timestamp is set and neither CumulativeCPUUsed
//     nor MemoryUsage is zero;
//   - a POD is dropped ENTIRELY if ANY of its containers has CumulativeCPUUsed == 0
//     or MemoryUsage == 0.
//
// A test that merely asserted "some field is non-nil" would pass on the broken
// memory-only shape this item exists to prevent — which is why the gate is written
// against a consumer, not against the producer's own struct.

// msMetricsPoint mirrors metrics-server's storage.MetricsPoint.
type msMetricsPoint struct {
	timestamp         time.Time
	startTime         time.Time
	cumulativeCPUUsed float64 // core-seconds
	memoryUsage       float64 // bytes
}

// msBatch mirrors metrics-server's storage.MetricsBatch: what actually reaches
// metrics.k8s.io (so, what `kubectl top` can show).
type msBatch struct {
	nodes map[string]msMetricsPoint
	// pods is keyed "namespace/pod"; the value is keyed by container name.
	pods map[string]map[string]msMetricsPoint
}

func (b msBatch) hasPod(namespace, name string) bool {
	_, ok := b.pods[namespace+"/"+name]
	return ok
}

// scrapeAsMetricsServer encodes families to Prometheus text and decodes them the
// way metrics-server does, INCLUDING its drop rules. The raw text is returned too,
// so a test can assert on the wire form the endpoint actually serves.
func scrapeAsMetricsServer(t *testing.T, families []*dto.MetricFamily) (msBatch, string) {
	t.Helper()

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range families {
		if err := enc.Encode(mf); err != nil {
			t.Fatalf("encoding %q to prometheus text format: %v", mf.GetName(), err)
		}
	}
	text := buf.String()

	// LegacyValidation is the classic `[a-zA-Z_:][a-zA-Z0-9_:]*` metric-name rule.
	// The kubelet's resource-metrics names are all legacy-valid, so parsing under
	// the strict scheme additionally proves the emitted names would be accepted by
	// a pre-UTF-8 scraper.
	parser := expfmt.NewTextParser(model.LegacyValidation)
	parsed, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		t.Fatalf("re-parsing the served text: %v\n%s", err, text)
	}

	batch := msBatch{
		nodes: map[string]msMetricsPoint{},
		pods:  map[string]map[string]msMetricsPoint{},
	}

	// The node point, assembled from the two node families.
	var node msMetricsPoint
	label := func(m *dto.Metric, name string) string {
		for _, l := range m.GetLabel() {
			if l.GetName() == name {
				return l.GetValue()
			}
		}
		return ""
	}
	value := func(m *dto.Metric) float64 {
		if m.GetCounter() != nil {
			return m.GetCounter().GetValue()
		}
		return m.GetGauge().GetValue()
	}
	stamp := func(m *dto.Metric) time.Time {
		if m.TimestampMs == nil {
			return time.Time{}
		}
		return time.UnixMilli(m.GetTimestampMs())
	}
	container := func(m *dto.Metric) (key, name string) {
		return label(m, "namespace") + "/" + label(m, "pod"), label(m, "container")
	}
	touch := func(key, name string) msMetricsPoint {
		if batch.pods[key] == nil {
			batch.pods[key] = map[string]msMetricsPoint{}
		}
		return batch.pods[key][name]
	}

	for famName, mf := range parsed {
		for _, m := range mf.GetMetric() {
			switch famName {
			case "node_cpu_usage_seconds_total":
				node.cumulativeCPUUsed = value(m)
				node.timestamp = stamp(m)
			case "node_memory_working_set_bytes":
				node.memoryUsage = value(m)
				if node.timestamp.IsZero() {
					node.timestamp = stamp(m)
				}
			case "container_cpu_usage_seconds_total":
				key, name := container(m)
				p := touch(key, name)
				p.cumulativeCPUUsed = value(m)
				p.timestamp = stamp(m)
				batch.pods[key][name] = p
			case "container_memory_working_set_bytes":
				key, name := container(m)
				p := touch(key, name)
				p.memoryUsage = value(m)
				if p.timestamp.IsZero() {
					p.timestamp = stamp(m)
				}
				batch.pods[key][name] = p
			case "container_start_time_seconds":
				key, name := container(m)
				p := touch(key, name)
				sec, frac := math.Modf(value(m))
				p.startTime = time.Unix(int64(sec), int64(frac*1e9))
				batch.pods[key][name] = p
			}
		}
	}

	// metrics-server's node completeness rule.
	if !node.timestamp.IsZero() && node.cumulativeCPUUsed != 0 && node.memoryUsage != 0 {
		batch.nodes["k3sm-node"] = node
	}

	// metrics-server's pod completeness rule: one incomplete container drops the
	// WHOLE pod.
	for key, containers := range batch.pods {
		if len(containers) == 0 {
			delete(batch.pods, key)
			continue
		}
		for _, p := range containers {
			if p.cumulativeCPUUsed == 0 || p.memoryUsage == 0 {
				delete(batch.pods, key)
				break
			}
		}
	}

	return batch, text
}

// --- fixtures ----------------------------------------------------------------

func u64(v uint64) *uint64 { return &v }

func summaryTime() metav1.Time {
	return metav1.NewTime(time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC))
}

func startTime() metav1.Time {
	return metav1.NewTime(time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC))
}

// completePod is a pod sampled JOINTLY: cpu and memory at both levels.
func completePod(namespace, name string, cpuNanos, wsBytes uint64) statsv1alpha1.PodStats {
	ts := summaryTime()
	return statsv1alpha1.PodStats{
		PodRef:    statsv1alpha1.PodReference{Namespace: namespace, Name: name, UID: namespace + "-" + name},
		StartTime: startTime(),
		CPU:       &statsv1alpha1.CPUStats{Time: ts, UsageCoreNanoSeconds: u64(cpuNanos)},
		Memory:    &statsv1alpha1.MemoryStats{Time: ts, WorkingSetBytes: u64(wsBytes)},
		Containers: []statsv1alpha1.ContainerStats{{
			Name:      "app",
			StartTime: startTime(),
			CPU:       &statsv1alpha1.CPUStats{Time: ts, UsageCoreNanoSeconds: u64(cpuNanos)},
			Memory:    &statsv1alpha1.MemoryStats{Time: ts, WorkingSetBytes: u64(wsBytes)},
		}},
	}
}

// memoryOnlyPod is the SHAPE THIS ITEM EXISTS TO REJECT: a real working set and no
// CPU sample at all — what a metrics endpoint built on k3sm's pre-B14 stats would
// have emitted for every pod on the node.
func memoryOnlyPod(namespace, name string, wsBytes uint64) statsv1alpha1.PodStats {
	ps := completePod(namespace, name, 0, wsBytes)
	ps.CPU = nil
	ps.Containers[0].CPU = nil
	return ps
}

// --- the gate ----------------------------------------------------------------

// TestGetMetricsResource is the B14 gate. It drives the provider's
// /metrics/resource surface end to end — Summary in, Prometheus families out,
// through the real expfmt encoder — and judges the result with a
// metrics-server-shaped consumer (scrapeAsMetricsServer), because that is the only
// judge whose verdict matches production.
//
// The binding assertion is the JOINT one: a pod is visible to the consumer only
// when CPU and memory are BOTH present. A pod carrying memory alone must NOT
// appear, and — this is the load-bearing half — its absence must be caused by the
// PRODUCER withholding it, not merely by the consumer discarding it. Both are
// checked: the memory-only pod's name never reaches the wire text at all.
func TestGetMetricsResource(t *testing.T) {
	nodeTS := summaryTime()
	summary := &statsv1alpha1.Summary{
		Node: statsv1alpha1.NodeStats{
			NodeName: "k3sm-node",
			CPU:      &statsv1alpha1.CPUStats{Time: nodeTS, UsageCoreNanoSeconds: u64(300_000_000_000)},
			Memory:   &statsv1alpha1.MemoryStats{Time: nodeTS, WorkingSetBytes: u64(8 << 30)},
		},
		Pods: []statsv1alpha1.PodStats{
			completePod("default", "web", 12_500_000_000, 64<<20),
			memoryOnlyPod("default", "cpu-less", 32<<20),
		},
	}

	p := NewVKProvider(&fakeStatsRuntime{summary: summary}, "k3sm-node")
	families, err := p.GetMetricsResource(context.Background())
	if err != nil {
		t.Fatalf("GetMetricsResource: %v", err)
	}
	if len(families) == 0 {
		t.Fatal("GetMetricsResource returned no metric families — the /metrics/resource scrape target is empty")
	}

	batch, text := scrapeAsMetricsServer(t, families)

	// 1. The jointly-sampled pod SURVIVES a metrics-server scrape.
	if !batch.hasPod("default", "web") {
		t.Errorf("a pod with BOTH cpu and memory was dropped by the consumer; served text:\n%s", text)
	}

	// 2. Its two resources both arrived, with the right values and units. CPU is
	//    core-SECONDS (12.5 s from 12 500 000 000 ns); memory is bytes.
	web := batch.pods["default/web"]["app"]
	if got, want := web.cumulativeCPUUsed, 12.5; math.Abs(got-want) > 1e-9 {
		t.Errorf("container cpu = %v core-seconds, want %v (nanoseconds must be divided by 1e9)", got, want)
	}
	if got, want := web.memoryUsage, float64(64<<20); got != want {
		t.Errorf("container memory = %v bytes, want %v", got, want)
	}
	if web.startTime.IsZero() {
		t.Error("container_start_time_seconds is missing — metrics-server parses it for staleness")
	}
	if web.timestamp.IsZero() {
		t.Error("container samples carry no timestamp; metrics-server needs one to compute a rate")
	}

	// 3. The memory-only pod is NOT visible to the consumer...
	if batch.hasPod("default", "cpu-less") {
		t.Errorf("a memory-only pod reached metrics.k8s.io; served text:\n%s", text)
	}
	// ...and the reason is that the PRODUCER withheld it. Publishing it and
	// letting metrics-server discard it is the regression this item exists to
	// prevent: it costs a dropped-metric log line per pod per scrape and shows the
	// operator nothing.
	if strings.Contains(text, "cpu-less") {
		t.Errorf("the memory-only pod was PUBLISHED and only dropped downstream; "+
			"it must be withheld at the source. served text:\n%s", text)
	}

	// 4. The node sample is complete, so the node survives too.
	if _, ok := batch.nodes["k3sm-node"]; !ok {
		t.Errorf("a node with BOTH cpu and memory was dropped by the consumer; served text:\n%s", text)
	}

	// 5. The families are spelled the way metrics-server matches them.
	for _, want := range []string{
		"node_cpu_usage_seconds_total",
		"node_memory_working_set_bytes",
		"container_cpu_usage_seconds_total",
		"container_memory_working_set_bytes",
		"container_start_time_seconds",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("family %q absent from the served text — metrics-server matches the name byte-for-byte:\n%s", want, text)
		}
	}
	// The container rows carry the label names metrics-server reads.
	if !strings.Contains(text, `container="app"`) ||
		!strings.Contains(text, `namespace="default"`) ||
		!strings.Contains(text, `pod="web"`) {
		t.Errorf("container rows must be labelled {container,pod,namespace}; served text:\n%s", text)
	}
}

// TestGetMetricsResourceNodeIsJointToo closes the node half of the joint rule: a
// node sampled for memory but not CPU publishes NEITHER node family, because
// metrics-server drops a node whose CumulativeCPUUsed is zero and `kubectl top
// node` would be empty either way — with the memory-only variant additionally
// generating scrape noise.
func TestGetMetricsResourceNodeIsJointToo(t *testing.T) {
	ts := summaryTime()
	summary := &statsv1alpha1.Summary{
		Node: statsv1alpha1.NodeStats{
			NodeName: "k3sm-node",
			Memory:   &statsv1alpha1.MemoryStats{Time: ts, WorkingSetBytes: u64(8 << 30)},
			// CPU deliberately absent.
		},
		Pods: []statsv1alpha1.PodStats{completePod("default", "web", 1_000_000_000, 1<<20)},
	}

	p := NewVKProvider(&fakeStatsRuntime{summary: summary}, "k3sm-node")
	families, err := p.GetMetricsResource(context.Background())
	if err != nil {
		t.Fatalf("GetMetricsResource: %v", err)
	}
	batch, text := scrapeAsMetricsServer(t, families)

	if len(batch.nodes) != 0 {
		t.Errorf("a CPU-less node reached metrics.k8s.io: %+v", batch.nodes)
	}
	if strings.Contains(text, "node_memory_working_set_bytes") {
		t.Errorf("node memory was published without node cpu — the pair is joint; served text:\n%s", text)
	}
	if strings.Contains(text, "node_cpu_usage_seconds_total") {
		t.Errorf("node cpu was published from an absent sample; served text:\n%s", text)
	}
	// The pods on that node are unaffected: the node's incompleteness is not theirs.
	if !batch.hasPod("default", "web") {
		t.Error("a complete pod must survive an incomplete NODE sample")
	}
}

// TestGetMetricsResourceDropsPodWithOneIncompleteContainer pins the granularity of
// the drop: metrics-server aggregates a pod FROM its containers, so one container
// missing a half makes the pod's total wrong, not merely partial — and it discards
// the whole pod. Publishing the pod's other container would therefore be published
// data that can never be shown.
func TestGetMetricsResourceDropsPodWithOneIncompleteContainer(t *testing.T) {
	ts := summaryTime()
	pod := completePod("prod", "two-ctr", 5_000_000_000, 16<<20)
	pod.Containers = append(pod.Containers, statsv1alpha1.ContainerStats{
		Name:      "sidecar",
		StartTime: startTime(),
		Memory:    &statsv1alpha1.MemoryStats{Time: ts, WorkingSetBytes: u64(4 << 20)},
		// CPU deliberately absent for this container only.
	})
	summary := &statsv1alpha1.Summary{
		Node: statsv1alpha1.NodeStats{NodeName: "k3sm-node"},
		Pods: []statsv1alpha1.PodStats{pod, completePod("prod", "healthy", 2_000_000_000, 8<<20)},
	}

	p := NewVKProvider(&fakeStatsRuntime{summary: summary}, "k3sm-node")
	families, err := p.GetMetricsResource(context.Background())
	if err != nil {
		t.Fatalf("GetMetricsResource: %v", err)
	}
	batch, text := scrapeAsMetricsServer(t, families)

	if batch.hasPod("prod", "two-ctr") {
		t.Errorf("a pod with one CPU-less container reached metrics.k8s.io; served text:\n%s", text)
	}
	if strings.Contains(text, "two-ctr") {
		t.Errorf("a pod with one incomplete container was published (including its complete container); "+
			"the drop is whole-pod at the source. served text:\n%s", text)
	}
	if !batch.hasPod("prod", "healthy") {
		t.Errorf("an unrelated complete pod must not be affected; served text:\n%s", text)
	}
}

// TestGetMetricsResourceZeroCPUIsTreatedAsMissing pins the one judgement call in
// the transcode: a ZERO cumulative CPU counter is treated as "not sampled", not as
// "used no CPU". That is not a preference — metrics-server's decoder drops on
// `CumulativeCPUUsed == 0` regardless of how the zero arose, so publishing it
// produces a record that can never be shown and a log line every scrape.
func TestGetMetricsResourceZeroCPUIsTreatedAsMissing(t *testing.T) {
	summary := &statsv1alpha1.Summary{
		Node: statsv1alpha1.NodeStats{NodeName: "k3sm-node"},
		Pods: []statsv1alpha1.PodStats{completePod("default", "idle", 0, 16<<20)},
	}
	p := NewVKProvider(&fakeStatsRuntime{summary: summary}, "k3sm-node")
	families, err := p.GetMetricsResource(context.Background())
	if err != nil {
		t.Fatalf("GetMetricsResource: %v", err)
	}
	_, text := scrapeAsMetricsServer(t, families)
	if strings.Contains(text, `pod="idle"`) {
		t.Errorf("a pod with a zero CPU counter was published; the consumer drops it, so it must be withheld:\n%s", text)
	}
}

// TestGetMetricsResourceWithoutStatsSource keeps the honest empty case honest: a
// Runtime that reports no stats at all (the M0 HostProcess path) serves an EMPTY
// scrape target, which is what an unimplemented metering surface should look like —
// not a set of families full of zeroes.
func TestGetMetricsResourceWithoutStatsSource(t *testing.T) {
	p := NewVKProvider(&statsLessRuntime{}, "k3sm-node")
	families, err := p.GetMetricsResource(context.Background())
	if err != nil {
		t.Fatalf("GetMetricsResource: %v", err)
	}
	if len(families) != 0 {
		t.Errorf("a Runtime with no StatsSource must serve no families, got %d", len(families))
	}
}

// --- Runtime fakes -----------------------------------------------------------

// statsLessRuntime satisfies provider.Runtime and NOTHING else — the M0-shaped
// backend with no metering at all.
type statsLessRuntime struct{}

func (statsLessRuntime) CreatePod(context.Context, *corev1.Pod) error { return nil }
func (statsLessRuntime) UpdatePod(context.Context, *corev1.Pod) error { return nil }
func (statsLessRuntime) DeletePod(context.Context, *corev1.Pod) error { return nil }
func (statsLessRuntime) GetPodStatus(context.Context, string, string) (*corev1.PodStatus, error) {
	return nil, vkadapter.NotFound("no pods")
}
func (statsLessRuntime) GetPods(context.Context) ([]*corev1.Pod, error) { return nil, nil }
func (statsLessRuntime) GetContainerLogs(context.Context, string, string, string, vkadapter.ContainerLogOpts) (io.ReadCloser, error) {
	return nil, vkadapter.NotFound("no logs")
}
func (statsLessRuntime) Watch(context.Context, func(*corev1.Pod)) {}

// fakeStatsRuntime is a Runtime that also implements StatsSource, returning a
// canned Summary — the seam the provider's resource-metrics transcode reads. It
// fakes at the Summary boundary rather than at the gRPC one on purpose: the
// runtimed→Summary mapping is already covered by the runtimed_test suite, and this
// gate is about the Summary→Prometheus half.
type fakeStatsRuntime struct {
	statsLessRuntime
	summary *statsv1alpha1.Summary
	err     error
}

var _ StatsSource = (*fakeStatsRuntime)(nil)

func (f *fakeStatsRuntime) StatsSummary(context.Context) (*statsv1alpha1.Summary, error) {
	return f.summary, f.err
}
