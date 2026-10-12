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

package interconnect

import (
	"net/http"
	"sort"
	"sync"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
)

// MetricsPath is the kubelet-endpoint route the interconnect metrics are served
// on, beside the node's /metrics/resource and behind the same authentication
// (`kubectl get --raw /api/v1/nodes/<node>/proxy/metrics/interconnect`).
const MetricsPath = "/metrics/interconnect"

// Metric family names.
const (
	metricMemberUp          = "k3sm_interconnect_member_up"
	metricMemberTransitions = "k3sm_interconnect_member_transitions_total"
	metricAttachedPods      = "k3sm_interconnect_attached_pods"
	metricPeerProbeSuccess  = "k3sm_interconnect_peer_probe_success"
	metricReportRejected    = "k3sm_interconnect_report_rejected_total"
	metricNetdVerbResults   = "k3sm_interconnect_netd_verb_results_total"
)

// Metrics holds the interconnect counters and gauges of one process. The server
// side (member up, transitions, attached pods, rejected reports) and the node
// side (peer probe success, netd verb results) share one value, because the
// server process also runs a node and serves one endpoint.
//
// Locking discipline: mu guards every map; Families copies under it.
type Metrics struct {
	mu           sync.Mutex
	memberUp     map[string]float64
	transitions  map[string]float64
	attachedPods float64
	probe        map[string]float64
	rejected     map[string]float64
	netd         map[[2]string]float64
}

// NewMetrics returns an empty Metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		memberUp:    map[string]float64{},
		transitions: map[string]float64{},
		probe:       map[string]float64{},
		rejected:    map[string]float64{},
		netd:        map[[2]string]float64{},
	}
}

// SetMembers replaces the member-up gauge with the given node→up set.
func (m *Metrics) SetMembers(up map[string]bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.memberUp = make(map[string]float64, len(up))
	for n, u := range up {
		m.memberUp[n] = b2f(u)
	}
}

// Transition counts one member state change of node.
func (m *Metrics) Transition(node string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transitions[node]++
}

// SetAttachedPods sets the attached-pods gauge.
func (m *Metrics) SetAttachedPods(n int32) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attachedPods = float64(n)
}

// SetProbes replaces the per-peer probe success gauge.
func (m *Metrics) SetProbes(alive map[string]bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probe = make(map[string]float64, len(alive))
	for p, a := range alive {
		m.probe[p] = b2f(a)
	}
}

// Rejected counts one rejected report by reason.
func (m *Metrics) Rejected(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejected[reason]++
}

// NetdResult counts one netd interconnect verb call by verb and result.
func (m *Metrics) NetdResult(verb, result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.netd[[2]string{verb, result}]++
}

// Families renders the metrics as Prometheus families, every series sorted by
// its labels so the output is stable.
func (m *Metrics) Families() []*dto.MetricFamily {
	m.mu.Lock()
	defer m.mu.Unlock()
	return []*dto.MetricFamily{
		labelled(metricMemberUp, "Whether the member is up (1) or not (0), per node.", dto.MetricType_GAUGE, "node", m.memberUp),
		labelled(metricMemberTransitions, "Member state transitions, per node.", dto.MetricType_COUNTER, "node", m.transitions),
		{
			Name: proto.String(metricAttachedPods), Help: proto.String("Pods holding an interconnect address."),
			Type:   dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(m.attachedPods)}}},
		},
		labelled(metricPeerProbeSuccess, "Whether the peer's slot-0 address answers the probe (1) or not (0), per peer node.", dto.MetricType_GAUGE, "peer", m.probe),
		labelled(metricReportRejected, "Interconnect reports the server ignored, per reason.", dto.MetricType_COUNTER, "reason", m.rejected),
		netdFamily(m.netd),
	}
}

// ServeHTTP writes the families in the Prometheus text format.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	w.Header().Set("Content-Type", string(format))
	enc := expfmt.NewEncoder(w, format)
	for _, f := range m.Families() {
		if len(f.Metric) == 0 {
			continue
		}
		if err := enc.Encode(f); err != nil {
			return
		}
	}
}

func labelled(name, help string, typ dto.MetricType, label string, values map[string]float64) *dto.MetricFamily {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f := &dto.MetricFamily{Name: proto.String(name), Help: proto.String(help), Type: typ.Enum()}
	for _, k := range keys {
		f.Metric = append(f.Metric, sample(typ, values[k], label, k))
	}
	return f
}

func netdFamily(values map[[2]string]float64) *dto.MetricFamily {
	keys := make([][2]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	f := &dto.MetricFamily{
		Name: proto.String(metricNetdVerbResults),
		Help: proto.String("netd interconnect verb calls, per verb and result."),
		Type: dto.MetricType_COUNTER.Enum(),
	}
	for _, k := range keys {
		f.Metric = append(f.Metric, sample(dto.MetricType_COUNTER, values[k], "verb", k[0], "result", k[1]))
	}
	return f
}

func sample(typ dto.MetricType, v float64, kv ...string) *dto.Metric {
	s := &dto.Metric{}
	for i := 0; i+1 < len(kv); i += 2 {
		s.Label = append(s.Label, &dto.LabelPair{Name: proto.String(kv[i]), Value: proto.String(kv[i+1])})
	}
	if typ == dto.MetricType_COUNTER {
		s.Counter = &dto.Counter{Value: proto.Float64(v)}
	} else {
		s.Gauge = &dto.Gauge{Value: proto.Float64(v)}
	}
	return s
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
