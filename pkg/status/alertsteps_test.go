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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestFixStepNeedsAdmin pins when a step needs an administrator: sudo as a word
// anywhere in the command, a download piped into a shell, the install script.
func TestFixStepNeedsAdmin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		command string
		want    bool
	}{
		{UpdateUpgradeRemedy, true},
		{"k3sm status && sudo k3sm install", true},
		{"sudo k3sm install", true},
		{"curl -fsSL https://example.com/x | sudo bash", true},
		{"k3sm status logs server", false},
		{"k3sm kubectl get pods -A", false},
		{"k3sm pseudo-sudo-ish", false},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			if got := cmd("Run it", tc.command); got.NeedsAdmin != tc.want || got.Command != tc.command {
				t.Errorf("cmd(%q) = %+v, want needsAdmin %v", tc.command, got, tc.want)
			}
		})
	}
	if s := manual("Run sudo k3sm install with a valid address"); !s.NeedsAdmin {
		t.Errorf("a step done by hand that says sudo is not marked: %+v", s)
	}
}

// TestFixStepConfirm pins the steps a person must confirm before they run.
func TestFixStepConfirm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		command string
		want    bool
	}{
		{"sudo rm -r /var/lib/k3sm.pre-volume", true},
		{"sudo rm -r /var/lib/k3sm/run", true},
		{"kubectl delete pod -n default web-0 --grace-period=0 --force", true},
		{"kubectl delete pod -n default web-0 --force", true},
		{"kubectl delete pod -n default web-0 --grace-period=0", true},
		{"kubectl taint node gone " + outOfServiceTaint, true},
		{"k3sm token create", true},
		{"sudo k3sm token create --work-dir /var/lib/k3sm/server", true},
		{"sudo k3sm server --cluster-reset", true},
		{"sudo k3sm server --clear-crashloop", true},
		{UpdateUpgradeRemedy, true},
		{"kubectl delete pod -n default web-0", false},
		{"kubectl taint node gone example.com/other=x:NoSchedule", false},
		{"sudo k3sm install", false},
		{"sudo launchctl kickstart -k system/io.k3sm.server", false},
		{"k3sm kubectl get pods -A", false},
		{"k3sm image prune", false},
		{"k3sm status logs server", false},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			if got := cmd("Run it", tc.command); got.Confirm != tc.want || got.Command != tc.command {
				t.Errorf("cmd(%q) = %+v, want confirm %v", tc.command, got, tc.want)
			}
		})
	}
	if s := manual("If a majority is gone for good, run sudo k3sm server --cluster-reset there"); !s.Confirm || !s.NeedsAdmin {
		t.Errorf("a step done by hand that resets etcd is not marked: %+v", s)
	}
}

// TestFixStepNeverAnUnrunnableCommand pins the two ways a command becomes an
// instruction: it holds a placeholder, or a cluster-supplied name in it is not a
// valid Kubernetes name.
func TestFixStepNeverAnUnrunnableCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, command string
		valid         bool
		mention       string
	}{
		{"placeholder", "k3sm kubectl describe pod -n <namespace> <pod>", false, "<namespace>"},
		{"valid names", "kubectl delete pod -n default web-0 --grace-period=0 --force", true, ""},
		{"valid node", "kubectl taint node my-mac.local " + outOfServiceTaint, true, ""},
		{"bad pod", "kubectl delete pod -n default web;reboot --grace-period=0 --force", false, `"web;reboot"`},
		{"pod with a space", "kubectl delete pod -n default web 0 --grace-period=0 --force", false, `"web 0"`},
		{"bad namespace", "kubectl delete pod -n Default web-0 --force", false, `namespace is named "Default"`},
		{"bad node", "kubectl taint node $(id) " + outOfServiceTaint, false, `node is named "$(id)"`},
		{"upper-case node", "kubectl taint node MyMac " + outOfServiceTaint, false, `"MyMac"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cmd("Act on it", tc.command)
			if tc.valid {
				if got.Command != tc.command {
					t.Errorf("a valid command was dropped: %+v", got)
				}
				return
			}
			if got.Command != "" {
				t.Errorf("command %q was emitted: %+v", got.Command, got)
			}
			if !strings.HasPrefix(got.Step, "Act on it") || !strings.Contains(got.Step, tc.mention) {
				t.Errorf("instruction %q does not name %s", got.Step, tc.mention)
			}
		})
	}

	// The same end to end: a pod stuck on a deleted node, whose name the
	// apiserver would refuse but a hostile or broken one could still return.
	now := goldenTime
	p := podIn(corev1.PodRunning)
	p.Namespace, p.Name, p.Spec.NodeName = "default", "web-0;reboot", "gone"
	del := metav1.NewTime(now.Add(-10 * time.Minute))
	p.DeletionTimestamp = &del
	row := Collector{Kube: fakeKube{nodes: []corev1.Node{readyNode("my-mac")}, pods: []corev1.Pod{p}}}.
		workloadsRow(context.Background(), true, 0, []corev1.Node{readyNode("my-mac")}, nil, now)
	rows := []Row{row}
	attachAlerts(rows, serverCtx)
	if rows[0].Alert == nil {
		t.Fatalf("no alert on %+v", row)
	}
	for _, s := range rows[0].Alert.Fix {
		if strings.Contains(s.Command, "web-0;reboot") {
			t.Errorf("the hostile pod name reached a command: %+v", s)
		}
	}
	if !strings.Contains(stepTexts(rows[0].Alert.Fix), `pod is named "web-0;reboot"`) {
		t.Errorf("no instruction names the pod: %+v", rows[0].Alert.Fix)
	}
}

func stepTexts(steps []FixStep) string {
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(s.Step + "\n")
	}
	return b.String()
}

// TestEvidenceRedactsSecrets puts every credential shape the redactor knows
// into a row's quoted log line and other wide values, and asserts no secret byte
// reaches the alert's evidence.
func TestEvidenceRedactsSecrets(t *testing.T) {
	t.Parallel()
	// The PEM markers are assembled at run time so the source holds no
	// key-shaped literal for a secret scanner to flag.
	pem := func(edge, kind string) string { return "-----" + edge + " " + kind + "-----" }
	secrets := []string{"S3CRETbearerA", "S3CRETbearerB", "S3CRETpemC", "S3CRETkeyD", "S3CRETcertE", "S3CRETtokenF", "S3CRETpwG", "S3CRETpwH", "S3CRETpemI", "S3CRETpemJ"}
	row := Row{Name: RowServer, State: StateFailed, Severity: SeverityFail, Detail: "io.k3sm.server exited 1", Wide: map[string]string{
		"log": "dial: Authorization: Bearer S3CRETbearerA; retry with bearer S3CRETbearerB" +
			" key " + pem("BEGIN", "EC PRIVATE KEY") + "S3CRETpemC" + pem("END", "EC PRIVATE KEY") + " after" +
			" client-key-data: S3CRETkeyD client-certificate-data: S3CRETcertE token: S3CRETtokenF" +
			" --node-password S3CRETpwG --node-password=S3CRETpwH",
		"path":  pem("BEGIN", "CERTIFICATE") + "\nS3CRETpemI\n" + pem("END", "CERTIFICATE"),
		"label": "cut off: " + pem("BEGIN", "RSA PRIVATE KEY") + " S3CRETpemJ",
	}}
	ev := strings.Join(evidence(row), "\n")
	for _, s := range secrets {
		if strings.Contains(ev, s) {
			t.Errorf("evidence carries %s:\n%s", s, ev)
		}
	}
	if !strings.Contains(ev, "after") || !strings.Contains(ev, "Authorization: Bearer "+redacted) {
		t.Errorf("redaction ate the text around the secrets:\n%s", ev)
	}
}
