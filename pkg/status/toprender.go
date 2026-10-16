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
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// topNoSample is the node row's usage cell while metrics-server has not
// sampled that node yet.
const topNoSample = "no metrics yet"

// RenderTop returns the `k3sm status top` screen: a metrics header line, the
// node table and the pod table. Colour, when the style allows it, is applied to
// the header's state word only, outside the tables, so the columns stay aligned.
func RenderTop(r TopReport, s Style) string {
	var b strings.Builder
	if r.ClusterError != "" {
		fmt.Fprintf(&b, "cluster: %s, %s\n", colorize("unreachable", ansiRed, s), r.ClusterError)
		return b.String()
	}
	b.WriteString(topHeader(r.Metrics, s))
	b.WriteString("\n")
	renderTopNodes(&b, r)
	b.WriteString("\n")
	renderTopPods(&b, r)
	return b.String()
}

// topHeader is the line that says whether the usage columns are live, and when
// they are not, why.
func topHeader(m TopMetrics, s Style) string {
	if m.Available {
		return fmt.Sprintf("metrics: %s from %s, read at most every %s\n",
			colorize("available", ansiGreen, s), MetricsAPIService, TopMetricsMinInterval)
	}
	why := m.Reason
	if m.Message != "" {
		why += ": " + m.Message
	}
	return fmt.Sprintf("metrics: %s (%s); showing nodes and pods without usage\n",
		colorize("unavailable", ansiYellow, s), why)
}

func renderTopNodes(b *strings.Builder, r TopReport) {
	if len(r.Nodes) == 0 {
		b.WriteString("nodes: none\n")
		return
	}
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tROLE\tCPU\tCPU%\tMEMORY\tMEM%\tPODS\tAGE")
	for _, n := range r.Nodes {
		cpu, cpuPct, mem, memPct, age := "-/"+milli(n.CPU.AllocatableMillicores), "-", "-/"+mebi(n.Memory.AllocatableBytes), "-", "-"
		switch {
		case n.Sampled:
			cpu = milli(*n.CPU.UsedMillicores) + "/" + milli(n.CPU.AllocatableMillicores)
			cpuPct = pct(n.CPU.Percent)
			mem = mebi(*n.Memory.UsedBytes) + "/" + mebi(n.Memory.AllocatableBytes)
			memPct = pct(n.Memory.Percent)
			age = topAge(*n.SampleAgeSeconds)
		case r.Metrics.Available:
			cpu, cpuPct, mem, memPct = topNoSample, "", "", ""
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", n.Name, n.Role, cpu, cpuPct, mem, memPct, n.Pods, age)
	}
	// tabwriter writes into a strings.Builder, whose Write never fails.
	_ = tw.Flush()
}

func renderTopPods(b *strings.Builder, r TopReport) {
	where := "in all namespaces"
	if r.Namespace != "" {
		where = "in namespace " + r.Namespace
	}
	if r.PodsTotal == 0 {
		fmt.Fprintf(b, "pods: none %s\n", where)
		return
	}
	order := "by " + string(r.Sort)
	if !r.Metrics.Available {
		order = "by namespace and name"
	}
	count := strconv.Itoa(r.PodsTotal)
	if len(r.Pods) < r.PodsTotal {
		count = fmt.Sprintf("%d of %d", len(r.Pods), r.PodsTotal)
	}
	fmt.Fprintf(b, "pods: %s %s, %s\n", count, where, order)
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAMESPACE\tPOD\tNODE\tCPU\tMEMORY\tRESTARTS")
	for _, p := range r.Pods {
		node, cpu, mem := p.Node, "-", "-"
		if node == "" {
			node = "-"
		}
		if p.Sampled {
			cpu, mem = milli(*p.CPUMillicores), mebi(*p.MemoryBytes)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", p.Namespace, p.Name, node, cpu, mem, p.Restarts)
	}
	// tabwriter writes into a strings.Builder, whose Write never fails.
	_ = tw.Flush()
}

// milli and mebi print CPU and memory in the units `kubectl top` prints.
func milli(m int64) string { return strconv.FormatInt(m, 10) + "m" }
func mebi(b int64) string  { return strconv.FormatInt(b/(1<<20), 10) + "Mi" }

func pct(p *int64) string {
	if p == nil {
		return "-"
	}
	return strconv.FormatInt(*p, 10) + "%"
}

// topAge prints a sample's age to the second: 9s, 2m5s, 1h3m.
func topAge(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", seconds)
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	default:
		return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
	}
}
