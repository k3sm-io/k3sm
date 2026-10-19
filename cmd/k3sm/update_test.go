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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/updatectl"
	"k3sm.io/k3sm/pkg/version"
)

// fakeIndexURL is where fakeReleaseIndex answers; no socket is opened.
const fakeIndexURL = "https://index.test/releases"

// fakeReleaseIndex is a client for a release index whose stable channel is tag,
// at fakeIndexURL, answering as GitHub's redirect and releases API do. Every
// request is served in process (handlerTransport).
func fakeReleaseIndex(tag, published, notes string) *http.Client {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/releases/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "draft": false, "published_at": published, "body": notes})
	})
	return &http.Client{Transport: handlerTransport{mux}}
}

// downTransport is an index that does not answer.
type downTransport struct{}

func (downTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connect: connection refused")
}

// installedWorkDir is a server work dir with the status directory beside it,
// as install lays them out (<data root>/server and <data root>/status).
func installedWorkDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	wd := filepath.Join(root, "server")
	for _, d := range []string{wd, status.Dir(wd)} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return wd
}

// kubeletNode is a Node whose kubelet reports v.
func kubeletNode(name, v string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: v}}}
}

// TestUpdateCheckComparesInstalledAndLatest is the update check end to end
// through the verb: a release index whose stable release is v0.2.0, a cluster
// with one node on it and one on v0.1.7, and this binary on v0.1.7. The report
// names the release, its date and Kubernetes version and each node's state; the
// record lands 0644 in the user-readable status directory; and the status row it
// yields warns naming the behind node and only it.
func TestUpdateCheckComparesInstalledAndLatest(t *testing.T) {
	index := fakeReleaseIndex("v0.2.0", "2026-10-01T00:00:00Z", "- **The control plane runs Kubernetes v1.37.1**.")
	current := version.Info{KubeVersion: "v1.37.1", Version: "0.2.0"}.NodeVersion()
	behind := version.Info{KubeVersion: "v1.36.2", Version: "0.1.7"}.NodeVersion()
	cs := fake.NewClientset(kubeletNode("studio", current), kubeletNode("laptop", behind))
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	wd := installedWorkDir(t)
	var out, errOut bytes.Buffer
	env := updateEnv{
		out:    &out,
		errOut: &errOut,
		inputs: update.Inputs{
			BaseURL:   fakeIndexURL,
			HTTP:      index,
			Kube:      cs,
			Installed: version.Info{Version: "0.1.7"},
			Now:       func() time.Time { return now },
		},
		workDir: wd,
	}
	if code := runUpdate(context.Background(), []string{"check", "-o", "json"}, env); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	var rep update.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("report %q: %v", out.String(), err)
	}
	wantLatest := update.Release{Tag: "v0.2.0", Published: "2026-10-01T00:00:00Z", KubeVersion: "v1.37.1"}
	if rep.Latest != wantLatest || rep.Installed != "0.1.7" || rep.InstalledState != status.UpdateBehind || !rep.CheckedAt.Equal(now) {
		t.Errorf("report = %+v", rep)
	}
	wantNodes := []update.Node{
		{Name: "laptop", Version: behind, State: status.UpdateBehind},
		{Name: "studio", Version: current, State: status.UpdateCurrent},
	}
	if len(rep.Nodes) != 2 || rep.Nodes[0] != wantNodes[0] || rep.Nodes[1] != wantNodes[1] {
		t.Errorf("nodes = %+v, want %+v", rep.Nodes, wantNodes)
	}

	path := status.UpdatePath(wd)
	if path != filepath.Join(filepath.Dir(wd), "status", "update.json") {
		t.Fatalf("record path %s", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no record: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("record mode %v, want 0644", fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec status.UpdateRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	row := status.UpdateRowFrom(rec, now.Add(time.Minute))
	if row.Name != status.RowUpdate || row.State != status.StateBehind || row.Severity != status.SeverityWarn {
		t.Fatalf("row = %+v, want behind/warn", row)
	}
	if !strings.Contains(row.Detail, "v0.2.0 is available") || !strings.Contains(row.Detail, "laptop ("+behind+")") || strings.Contains(row.Detail, "studio") {
		t.Errorf("row detail %q does not name exactly the behind node", row.Detail)
	}

	// Once every node runs it, the row is ok.
	cs = fake.NewClientset(kubeletNode("studio", current), kubeletNode("laptop", current))
	env.inputs.Kube, env.inputs.Installed = cs, version.Info{Version: "0.2.0"}
	out.Reset()
	if code := runUpdate(context.Background(), []string{"check"}, env); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	for _, want := range []string{"v0.2.0, published 2026-10-01T00:00:00Z", "v1.37.1", "0.2.0 (current)", "laptop", "current"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, out.String())
		}
	}
	raw, _ = os.ReadFile(path)
	rec = status.UpdateRecord{}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if row := status.UpdateRowFrom(rec, now); row.State != status.StateOK || row.Severity != status.SeverityOK {
		t.Errorf("row = %+v, want ok", row)
	}
}

// TestUpdateCheckUnreachableIsRecorded pins the failure: an index that does
// not answer exits 1 and leaves a record whose row is unknown with the error.
func TestUpdateCheckUnreachableIsRecorded(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	wd := installedWorkDir(t)
	var out, errOut bytes.Buffer
	env := updateEnv{out: &out, errOut: &errOut, workDir: wd, inputs: update.Inputs{
		BaseURL: fakeIndexURL, HTTP: &http.Client{Transport: downTransport{}}, Timeout: time.Second, Installed: version.Info{Version: "0.1.7"}, Now: func() time.Time { return now },
	}}
	if code := runUpdate(context.Background(), []string{"check"}, env); code != exitInternalError {
		t.Fatalf("exit %d, want %d", code, exitInternalError)
	}
	raw, err := os.ReadFile(status.UpdatePath(wd))
	if err != nil {
		t.Fatal(err)
	}
	var rec status.UpdateRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	row := status.UpdateRowFrom(rec, now)
	if row.State != status.StateUnknown || !strings.Contains(row.Detail, "could not check for an update: resolve the latest release") || row.Remedy != status.UpdateCheckRemedy {
		t.Errorf("row = %+v", row)
	}
}

// TestUpdateUsage pins the verb's usage exits.
func TestUpdateUsage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"bogus"}, {"check", "-o", "yaml"}, {"check", "extra"},
		{"apply", "extra"}, {"apply", "--signature", "none"}, {"apply", "--version", "v1;rm"},
		{"status", "-o", "yaml"}, {"status", "extra"}, {"cancel", "extra"}, {"abort", "extra"},
	} {
		var out, errOut bytes.Buffer
		if code := runUpdate(context.Background(), args, updateEnv{out: &out, errOut: &errOut}); code != exitUsage {
			t.Errorf("k3sm update %v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

// TestUpdateCheckDue pins "at most once an hour": a server restarted ten
// minutes after a check waits the other fifty, and an absent, unparseable or
// old record is due at once.
func TestUpdateCheckDue(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	wd := installedWorkDir(t)
	if d := updateCheckDue(wd, now, time.Hour); d != 0 {
		t.Errorf("absent record: due in %s", d)
	}
	if err := writeUpdateRecord(wd, status.UpdateRecord{CheckedAt: now.Add(-10 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if d := updateCheckDue(wd, now, time.Hour); d != 50*time.Minute {
		t.Errorf("fresh record: due in %s, want 50m", d)
	}
	if err := writeUpdateRecord(wd, status.UpdateRecord{CheckedAt: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if d := updateCheckDue(wd, now, time.Hour); d != 0 {
		t.Errorf("old record: due in %s", d)
	}
	if err := os.WriteFile(status.UpdatePath(wd), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d := updateCheckDue(wd, now, time.Hour); d != 0 {
		t.Errorf("unparseable record: due in %s", d)
	}
}

// TestUpdateRecordRefusesAnUnsafeStatusDir pins the check before every write:
// a symlink or a file where the status directory belongs is refused and
// nothing is written through it, a directory owned by anyone but root or the
// work dir's owner is refused with the uids, and a work dir with no status
// directory beside it is errNoStatusDir with nothing created.
func TestUpdateRecordRefusesAnUnsafeStatusDir(t *testing.T) {
	rec := status.UpdateRecord{CheckedAt: time.Now()}
	bare := func(t *testing.T) string {
		wd := filepath.Join(t.TempDir(), "server")
		if err := os.Mkdir(wd, 0o755); err != nil {
			t.Fatal(err)
		}
		return wd
	}
	t.Run("symlink", func(t *testing.T) {
		wd, elsewhere := bare(t), t.TempDir()
		if err := os.Symlink(elsewhere, status.Dir(wd)); err != nil {
			t.Fatal(err)
		}
		err := writeUpdateRecord(wd, rec)
		if err == nil || !strings.Contains(err.Error(), "is a symlink") {
			t.Fatalf("err = %v, want the symlink refusal", err)
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Errorf("wrote through the symlink: %v", entries)
		}
	})
	t.Run("file", func(t *testing.T) {
		wd := bare(t)
		if err := os.WriteFile(status.Dir(wd), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := writeUpdateRecord(wd, rec); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("err = %v, want the not-a-directory refusal", err)
		}
	})
	t.Run("foreign owner", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root owns every directory it makes")
		}
		dir := t.TempDir()
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		mine := uint32(os.Geteuid())
		if err := checkStatusDir(dir, fi, mine); err != nil {
			t.Errorf("the work dir owner's directory: %v", err)
		}
		if err := checkStatusDir(dir, fi, mine+1); err == nil || !strings.Contains(err.Error(), "neither root nor the work dir's owner") {
			t.Errorf("err = %v, want the owner refusal", err)
		}
	})
	t.Run("absent", func(t *testing.T) {
		wd := bare(t)
		if err := writeUpdateRecord(wd, rec); !errors.Is(err, errNoStatusDir) {
			t.Fatalf("err = %v, want errNoStatusDir", err)
		}
		if _, err := os.Lstat(status.Dir(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the status directory was created: %v", err)
		}
	})
	t.Run("installed", func(t *testing.T) {
		wd := installedWorkDir(t)
		if err := writeUpdateRecord(wd, rec); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(status.UpdatePath(wd))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
			t.Errorf("record %v, err %v; want a 0644 file", fi, err)
		}
	})
}

// updateCluster is a fake cluster for the managed-update subcommands: a
// clientset with its Nodes and the controller's Lease, and a dynamic client
// that stores the Updates as unstructured, as the apiserver serves them.
type updateCluster struct {
	cs  *fake.Clientset
	dyn *dynamicfake.FakeDynamicClient
}

func newUpdateCluster(objs ...runtime.Object) updateCluster {
	return updateCluster{
		cs:  fake.NewClientset(objs...),
		dyn: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{updateGVR: "UpdateList"}),
	}
}

// run runs `k3sm update <args>` against the cluster, with --yes or not.
func (c updateCluster) run(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	return c.runWith(t, nil, args...)
}

// runWith is run with env adjusted by mutate first (nil changes nothing).
func (c updateCluster) runWith(t *testing.T, mutate func(*updateEnv), args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	env := updateEnv{
		out:    &o,
		errOut: &e,
		inputs: update.Inputs{
			BaseURL:   fakeIndexURL,
			HTTP:      fakeReleaseIndex("v0.2.0", "2026-10-01T00:00:00Z", ""),
			Kube:      c.cs,
			Installed: version.Info{Version: "0.1.7"},
			Now:       func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) },
		},
		dyn:        c.dyn,
		in:         strings.NewReader(""),
		watchEvery: time.Millisecond,
	}
	if mutate != nil {
		mutate(&env)
	}
	code = runUpdate(context.Background(), args, env)
	return code, o.String(), e.String()
}

func (c updateCluster) get(t *testing.T) *updatesv1alpha1.Update {
	t.Helper()
	u, err := getUpdate(context.Background(), c.dyn)
	if err != nil || u == nil {
		t.Fatalf("get current: %v, %v", u, err)
	}
	return u
}

// setStatus replaces the current Update's status, as the controller would.
func (c updateCluster) setStatus(t *testing.T, st updatesv1alpha1.UpdateStatus) {
	t.Helper()
	u := c.get(t)
	u.Status = st
	if err := writeUpdateStatus(context.Background(), c.dyn, u); err != nil {
		t.Fatal(err)
	}
}

func (c updateCluster) node(t *testing.T, name string) *corev1.Node {
	t.Helper()
	n, err := c.cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// progressing is a Progressing condition with the given status and reason.
func progressing(st metav1.ConditionStatus, reason string) metav1.Condition {
	return metav1.Condition{Type: updatectl.ConditionProgressing, Status: st, Reason: reason, Message: reason, LastTransitionTime: metav1.Now()}
}

// TestUpdateApplyCreatesThePlan is the managed-update verb end to end against
// a fake cluster: a worker and the server that holds the controller's Lease,
// both on v0.1.7, and a release index whose latest is v0.2.0.
func TestUpdateApplyCreatesThePlan(t *testing.T) {
	behind := version.Info{KubeVersion: "v1.36.2", Version: "0.1.7"}.NodeVersion()
	server := kubeletNode("studio", behind)
	server.Labels = map[string]string{"node-role.kubernetes.io/control-plane": "true"}
	worker := kubeletNode("laptop", behind)
	holder := "studio"
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: updatectl.LeaseName, Namespace: updatectl.LeaseNamespace},
		Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
	c := newUpdateCluster(server, worker, lease)

	// Without --yes, a stdin that is not a terminal refuses and creates nothing.
	if code, _, errOut := c.run(t, "apply"); code != exitUsage || !strings.Contains(errOut, "pass --yes") {
		t.Fatalf("apply without --yes: exit %d, stderr %q", code, errOut)
	}
	if u, _ := getUpdate(context.Background(), c.dyn); u != nil {
		t.Fatalf("apply without --yes created %+v", u)
	}

	// apply --yes prints the plan, the worker first, and creates current.
	code, out, errOut := c.run(t, "apply", "--yes", "--drain", "--signature", "required")
	if code != 0 {
		t.Fatalf("apply: exit %d, stderr %s", code, errOut)
	}
	for _, want := range []string{"target            v0.2.0", "drain             yes", "signature         required", "1       laptop", "2       studio", "Created the Update current to v0.2.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply output lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "laptop") > strings.Index(out, "studio") {
		t.Errorf("the server is not last:\n%s", out)
	}
	wantSpec := updatesv1alpha1.UpdateSpec{
		Version:  "v0.2.0",
		Strategy: updatesv1alpha1.UpdateStrategy{Drain: true},
		Verify:   updatesv1alpha1.UpdateVerify{Signature: updatesv1alpha1.UpdateSignatureRequired},
	}
	if got := c.get(t).Spec; got != wantSpec {
		t.Errorf("spec = %+v, want %+v", got, wantSpec)
	}

	// A second apply while the first is Rolling refuses, naming the phase.
	c.setStatus(t, updatesv1alpha1.UpdateStatus{
		Phase:    updatesv1alpha1.UpdatePhaseRolling,
		Resolved: &updatesv1alpha1.UpdateResolved{Version: "v0.2.0", Digest: "sha256:abc"},
		Nodes: []updatesv1alpha1.UpdateNodeStatus{
			{Name: "laptop", From: "v0.1.7", To: "v0.2.0", Phase: updatesv1alpha1.UpdateNodePhaseInstalling, Message: "installing; last progress 2026-10-15T11:59:00Z"},
			{Name: "studio", From: "v0.1.7", To: "v0.2.0", Phase: updatesv1alpha1.UpdateNodePhasePending, Message: "last progress 2026-10-15T11:58:00Z"},
			{Name: "studio2", From: "v0.1.7", To: "v0.2.0", Phase: updatesv1alpha1.UpdateNodePhaseDone, AdminTokenRotated: true,
				Message: "runs v0.2.0; " + updatectl.AdminTokenRotatedMessage + "; last progress 2026-10-15T11:57:00Z"},
		},
		Conditions: []metav1.Condition{progressing(metav1.ConditionTrue, updatectl.ReasonRolling)},
	})
	if code, _, errOut := c.run(t, "apply", "--yes", "--version", "v0.2.1"); code != exitInternalError || !strings.Contains(errOut, "is Rolling") {
		t.Errorf("apply while Rolling: exit %d, stderr %q", code, errOut)
	}
	if got := c.get(t).Spec.Version; got != "v0.2.0" {
		t.Errorf("apply while Rolling changed the version to %s", got)
	}

	// status -o json renders the per-node table.
	code, out, errOut = c.run(t, "status", "-o", "json")
	if code != 0 {
		t.Fatalf("status: exit %d, stderr %s", code, errOut)
	}
	var v updateStatusView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("status json %q: %v", out, err)
	}
	wantNodes := []updateStatusNode{
		{Name: "laptop", From: "v0.1.7", To: "v0.2.0", Phase: "Installing", Message: "installing", LastProgress: "2026-10-15T11:59:00Z"},
		{Name: "studio", From: "v0.1.7", To: "v0.2.0", Phase: "Pending", LastProgress: "2026-10-15T11:58:00Z"},
		{Name: "studio2", From: "v0.1.7", To: "v0.2.0", Phase: "Done", LastProgress: "2026-10-15T11:57:00Z", AdminTokenRotated: true,
			Message: "runs v0.2.0; " + updatectl.AdminTokenRotatedMessage},
	}
	if v.Name != "current" || v.Phase != "Rolling" || v.Finished || v.Version != "v0.2.0" || !v.Drain || v.Signature != "required" ||
		v.Resolved == nil || v.Resolved.Digest != "sha256:abc" || len(v.Conditions) != 1 {
		t.Errorf("status view = %+v", v)
	}
	if len(v.Nodes) != 3 || v.Nodes[0] != wantNodes[0] || v.Nodes[1] != wantNodes[1] || v.Nodes[2] != wantNodes[2] {
		t.Errorf("status nodes = %+v, want %+v", v.Nodes, wantNodes)
	}
	// The app reads the flag by this key, set only on the node it describes.
	if strings.Count(out, `"adminTokenRotated": true`)+strings.Count(out, `"adminTokenRotated":true`) != 1 {
		t.Errorf("status json does not carry adminTokenRotated on exactly one node:\n%s", out)
	}
	// The text form carries the same table, and the remedy under the node
	// whose credential was re-minted, and only there.
	_, out, _ = c.run(t, "status")
	if !strings.Contains(out, "laptop    v0.1.7   v0.2.0   Installing   2026-10-15T11:59:00Z   installing") {
		t.Errorf("status text:\n%s", out)
	}
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, adminTokenRotatedRemedy) && (i == 0 || !strings.HasPrefix(lines[i-1], "studio2 ")) {
			t.Errorf("the remedy is not under studio2:\n%s", out)
		}
	}
	if strings.Count(out, adminTokenRotatedRemedy) != 1 {
		t.Errorf("status text carries the remedy %d times, want once:\n%s", strings.Count(out, adminTokenRotatedRemedy), out)
	}

	// cancel sets the flag and says what it means.
	code, out, errOut = c.run(t, "cancel")
	if code != 0 || !c.get(t).Spec.Cancel || !strings.Contains(out, "The node being updated finishes") {
		t.Errorf("cancel: exit %d, cancel %v, out %q, stderr %q", code, c.get(t).Spec.Cancel, out, errOut)
	}

	// A terminal current is replaced: a retry is a new current.
	c.setStatus(t, updatesv1alpha1.UpdateStatus{Phase: updatesv1alpha1.UpdatePhaseCancelled, Conditions: []metav1.Condition{progressing(metav1.ConditionFalse, updatectl.ReasonCancelled)}})
	code, out, errOut = c.run(t, "apply", "--yes", "--version", "v0.2.1")
	if code != 0 || !strings.Contains(out, "Removed the finished Update current to v0.2.0 (Cancelled)") {
		t.Fatalf("apply over a finished Update: exit %d, out %q, stderr %q", code, out, errOut)
	}
	if u := c.get(t); u.Spec.Version != "v0.2.1" || u.Spec.Cancel || u.Spec.Strategy.Drain || u.Spec.Verify.Signature != updatesv1alpha1.UpdateSignatureIfSigned {
		t.Errorf("replaced spec = %+v", u.Spec)
	}

	// abort after a failed server step: the annotations go on every node, only
	// the controller's cordon is lifted, and the Update ends Cancelled.
	c.setStatus(t, updatesv1alpha1.UpdateStatus{
		Phase: updatesv1alpha1.UpdatePhaseFailed,
		Nodes: []updatesv1alpha1.UpdateNodeStatus{
			{Name: "laptop", Phase: updatesv1alpha1.UpdateNodePhaseDone},
			{Name: "studio", To: "v0.2.1", Phase: updatesv1alpha1.UpdateNodePhaseFailed, Message: "install failed"},
		},
		Conditions: []metav1.Condition{
			progressing(metav1.ConditionFalse, updatectl.ReasonFailed),
			{Type: updatectl.ConditionFailed, Status: metav1.ConditionTrue, Reason: updatectl.ReasonFailed, Message: "node studio: install failed", LastTransitionTime: metav1.Now()},
		},
	})
	all := map[string]string{
		updatesv1alpha1.AnnotationUpdateVersion: "v0.2.1",
		updatesv1alpha1.AnnotationUpdatePayload: "{}",
		updatesv1alpha1.AnnotationUpdatePhase:   "Failed: install failed",
		updatectl.CordonedAnnotation:            "true",
		updatectl.HandedOverAnnotation:          "2026-10-15T11:00:00Z",
		updatectl.ReadyAtAnnotation:             "2026-10-15T11:05:00Z",
		// The server's install minted a new admin token before the step
		// failed: abort records it on the Update before clearing it.
		updatectl.AdminTokenRotatedAnnotation: "0.2.1 2026-10-15T11:04:00Z",
		"k3sm.io/other":                       "kept",
	}
	controllerCordoned := c.node(t, "studio")
	controllerCordoned.Annotations, controllerCordoned.Spec.Unschedulable = all, true
	operatorCordoned := c.node(t, "laptop")
	operatorCordoned.Annotations = map[string]string{updatesv1alpha1.AnnotationUpdateVersion: "v0.2.1", "k3sm.io/other": "kept"}
	operatorCordoned.Spec.Unschedulable = true
	for _, n := range []*corev1.Node{controllerCordoned, operatorCordoned} {
		if _, err := c.cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errOut = c.run(t, "abort")
	if code != 0 {
		t.Fatalf("abort: exit %d, stderr %s", code, errOut)
	}
	for _, want := range []string{"Marked the Update current to v0.2.1 Cancelled (it was Failed)", "Node studio: uncordoned", "Node laptop: left cordoned", "Node studio: " + adminTokenRotatedRemedy} {
		if !strings.Contains(out, want) {
			t.Errorf("abort output lacks %q:\n%s", want, out)
		}
	}
	for name, cordoned := range map[string]bool{"studio": false, "laptop": true} {
		n := c.node(t, name)
		if n.Spec.Unschedulable != cordoned {
			t.Errorf("node %s unschedulable = %v, want %v", name, n.Spec.Unschedulable, cordoned)
		}
		for k := range n.Annotations {
			if strings.HasPrefix(k, "k3sm.io/update-") {
				t.Errorf("node %s keeps %s", name, k)
			}
		}
		if n.Annotations["k3sm.io/other"] != "kept" {
			t.Errorf("node %s lost an unrelated annotation: %v", name, n.Annotations)
		}
	}
	u := c.get(t)
	for _, e := range u.Status.Nodes {
		if want := e.Name == "studio"; e.AdminTokenRotated != want || strings.Contains(e.Message, updatectl.AdminTokenRotatedMessage) != want {
			t.Errorf("aborted entry %s: AdminTokenRotated %v, message %q; want the flag and the remedy %v", e.Name, e.AdminTokenRotated, e.Message, want)
		}
	}
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseCancelled || !updateEndedAs(u, updatectl.ReasonCancelled) ||
		!meta.IsStatusConditionTrue(u.Status.Conditions, updatectl.ConditionFailed) {
		t.Errorf("aborted status = %+v", u.Status)
	}
}

// TestUpdateStatusWatchStopsWhenFinished pins --watch: it prints each change
// once and returns when the Update finishes.
func TestUpdateStatusWatchStopsWhenFinished(t *testing.T) {
	c := newUpdateCluster()
	// Each get answers the next state; the reactor builds the object itself,
	// since the fake holds its lock while a reactor runs.
	states := []updatesv1alpha1.UpdateStatus{
		{},
		{},
		{Phase: updatesv1alpha1.UpdatePhaseRolling, Conditions: []metav1.Condition{progressing(metav1.ConditionTrue, updatectl.ReasonRolling)}},
		{Phase: updatesv1alpha1.UpdatePhaseRolling, Conditions: []metav1.Condition{progressing(metav1.ConditionTrue, updatectl.ReasonRolling)}},
		{Phase: updatesv1alpha1.UpdatePhaseSucceeded, Conditions: []metav1.Condition{progressing(metav1.ConditionFalse, updatectl.ReasonSucceeded)}},
	}
	gets := 0
	c.dyn.PrependReactor("get", "updates", func(k8stesting.Action) (bool, runtime.Object, error) {
		st := states[min(gets, len(states)-1)]
		gets++
		obj, err := newUpdateObject(updatesv1alpha1.UpdateSpec{Version: "v0.2.0"})
		if err != nil {
			return true, nil, err
		}
		raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&st)
		if err != nil {
			return true, nil, err
		}
		obj.Object["status"] = raw
		return true, obj, nil
	})
	code, out, errOut := c.run(t, "status", "--watch")
	if code != 0 {
		t.Fatalf("watch: exit %d, stderr %s", code, errOut)
	}
	if strings.Count(out, "update   current to v0.2.0") != 3 || strings.Count(out, "phase    Rolling") != 1 ||
		!strings.Contains(out, "phase    not yet reconciled") || strings.LastIndex(out, "phase    Succeeded") < strings.LastIndex(out, "Rolling") {
		t.Errorf("watch output:\n%s", out)
	}
}

// TestUpdateStatusNoUpdate pins the no-update answer the app reads: exit 0,
// "no managed update", and the fixed empty JSON.
func TestUpdateStatusNoUpdate(t *testing.T) {
	c := newUpdateCluster()
	code, out, errOut := c.run(t, "status", "-o", "json")
	if code != 0 {
		t.Fatalf("status -o json: exit %d, stderr %s", code, errOut)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(out)); err != nil {
		t.Fatal(err)
	}
	if want := `{"phase":"","version":"","resolved":null,"nodes":[],"conditions":[]}`; compact.String() != want {
		t.Errorf("status -o json = %s, want %s", compact.String(), want)
	}
	if code, out, _ := c.run(t, "status", "--watch"); code != 0 || !strings.HasPrefix(out, "no managed update") {
		t.Errorf("status --watch: exit %d, out %q", code, out)
	}
}

// TestUpdateRecorderRecordsTheRoll is the server's recorder against a fake
// release check and a fake cluster: while the Update is not finished the
// record carries the roll (so the status row is `rolling` naming the phase and
// the node) beside the check's fields, and once it finishes the roll goes.
func TestUpdateRecorderRecordsTheRoll(t *testing.T) {
	wd := installedWorkDir(t)
	c := newUpdateCluster()
	obj, err := newUpdateObject(updatesv1alpha1.UpdateSpec{Version: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.dyn.Resource(updateGVR).Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	c.setStatus(t, updatesv1alpha1.UpdateStatus{
		Phase: updatesv1alpha1.UpdatePhaseRolling,
		Nodes: []updatesv1alpha1.UpdateNodeStatus{
			{Name: "laptop", Phase: updatesv1alpha1.UpdateNodePhaseDone},
			{Name: "studio", Phase: updatesv1alpha1.UpdateNodePhaseInstalling},
		},
		Conditions: []metav1.Condition{progressing(metav1.ConditionTrue, updatectl.ReasonRolling)},
	})
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		updateRecorder{
			workDir: wd,
			check: func(context.Context) (update.Report, error) {
				return update.Report{CheckedAt: now, Latest: update.Release{Tag: "v0.2.0"}, Installed: "0.1.7", Nodes: []update.Node{}}, nil
			},
			dyn:       c.dyn,
			interval:  time.Hour,
			rollEvery: time.Millisecond,
			now:       func() time.Time { return now },
			logger:    slog.New(slog.DiscardHandler),
		}.run(ctx)
	}()
	defer func() { cancel(); <-done }()

	waitRecord := func(what string, ok func(status.UpdateRecord) bool) status.UpdateRecord {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			rec := readUpdateRecord(wd)
			if ok(rec) {
				return rec
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: record %+v", what, rec)
			}
			time.Sleep(time.Millisecond)
		}
	}
	rec := waitRecord("the roll and the check", func(r status.UpdateRecord) bool { return r.Roll != nil && r.Latest == "v0.2.0" })
	if want := (status.UpdateRoll{ObservedAt: now, Version: "v0.2.0", Phase: "Rolling", Node: "studio", NodePhase: "Installing"}); *rec.Roll != want {
		t.Errorf("roll = %+v, want %+v", *rec.Roll, want)
	}
	row := status.UpdateRowFrom(rec, now)
	if row.State != status.StateRolling || row.Wide["phase"] != "Rolling" || row.Wide["node"] != "studio" || !strings.Contains(row.Detail, "node studio Installing") {
		t.Errorf("row = %+v", row)
	}

	c.setStatus(t, updatesv1alpha1.UpdateStatus{Phase: updatesv1alpha1.UpdatePhaseSucceeded, Conditions: []metav1.Condition{progressing(metav1.ConditionFalse, updatectl.ReasonSucceeded)}})
	rec = waitRecord("the roll cleared", func(r status.UpdateRecord) bool { return r.Roll == nil })
	if rec.Latest != "v0.2.0" {
		t.Errorf("clearing the roll lost the check: %+v", rec)
	}
}

// TestUpdateRecorderPublishesTheLatestOnItsNode is the server half of a
// worker's update row: after a check the recorder merge-patches the latest
// release and when it was checked onto the server's own Node, keeping every
// other annotation, and a worker's status reads that pair back through the
// node list (status.PublishedUpdateRecord). A failed check publishes nothing.
func TestUpdateRecorderPublishesTheLatestOnItsNode(t *testing.T) {
	wd := installedWorkDir(t)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:        "studio",
		Labels:      map[string]string{"node-role.kubernetes.io/control-plane": ""},
		Annotations: map[string]string{"k3sm.io/update-phase": "Done"},
	}}
	cs := fake.NewClientset(node)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		updateRecorder{
			workDir: wd,
			check: func(context.Context) (update.Report, error) {
				return update.Report{CheckedAt: now, Latest: update.Release{Tag: "v0.2.0"}, Installed: "0.1.7", Nodes: []update.Node{}}, nil
			},
			interval:  time.Hour,
			rollEvery: time.Millisecond,
			now:       func() time.Time { return now },
			logger:    slog.New(slog.DiscardHandler),
			publish:   nodeAnnotationPublisher(cs, "studio"),
		}.run(ctx)
	}()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(10 * time.Second)
	var got *corev1.Node
	for {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), "studio", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if n.Annotations[status.NodeReleaseLatestAnnotation] != "" {
			got = n
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the latest release was never published: %v", n.Annotations)
		}
		time.Sleep(time.Millisecond)
	}
	want := map[string]string{
		"k3sm.io/update-phase":              "Done",
		status.NodeReleaseLatestAnnotation:  "v0.2.0",
		status.NodeReleaseCheckedAnnotation: "2026-10-15T12:00:00Z",
	}
	if !sameAnnotations(got.Annotations, want) {
		t.Errorf("annotations = %v, want %v", got.Annotations, want)
	}
	rec, server, ok := status.PublishedUpdateRecord([]corev1.Node{*got})
	if !ok || server != "studio" || rec.Latest != "v0.2.0" || !rec.CheckedAt.Equal(now) {
		t.Errorf("PublishedUpdateRecord = %+v, %q, %v", rec, server, ok)
	}
	if nodeAnnotationPublisher(nil, "studio") != nil || nodeAnnotationPublisher(cs, "") != nil {
		t.Error("a publisher with no client or no Node name publishes")
	}
}

// TestUpdateApplyPinRequiresRoot pins the release pin's CLI half: only root
// writes or clears the pin, --pin-sha256 needs --version and a well-formed
// digest, nothing is written while an Update is in progress, and the pin is
// written before the Update is created. Without the flags apply is unchanged.
func TestUpdateApplyPinRequiresRoot(t *testing.T) {
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	behind := version.Info{KubeVersion: "v1.36.2", Version: "0.1.7"}.NodeVersion()
	server := kubeletNode("studio", behind)
	server.Labels = map[string]string{"node-role.kubernetes.io/control-plane": "true"}

	// pins records the seams' calls; asRoot wires them and sets root.
	type pins struct {
		written []updatectl.ReleasePin
		cleared int
		// updateAtWrite is whether an Update existed when the pin was written.
		updateAtWrite bool
	}
	asRoot := func(c updateCluster, p *pins, root bool) func(*updateEnv) {
		return func(env *updateEnv) {
			env.root = root
			env.workDir = t.TempDir()
			env.writePin = func(_ string, pin updatectl.ReleasePin) error {
				u, _ := getUpdate(context.Background(), c.dyn)
				p.updateAtWrite = u != nil
				p.written = append(p.written, pin)
				return nil
			}
			env.clearPin = func(wd string) (updatectl.Cleared, error) {
				p.cleared++
				return updatectl.Cleared{Path: updatectl.ReleasePinPath(wd)}, nil
			}
		}
	}

	for _, tc := range []struct {
		name     string
		root     bool
		args     []string
		wantCode int
		wantErr  string
	}{
		{name: "pin as a user", args: []string{"apply", "--yes", "--version", "v0.2.0", "--pin-sha256", sum}, wantCode: exitInternalError, wantErr: "must run as root"},
		{name: "an empty pin as a user", args: []string{"apply", "--yes", "--version", "v0.2.0", "--pin-sha256", ""}, wantCode: exitInternalError, wantErr: "must run as root"},
		{name: "clear as a user", args: []string{"apply", "--clear-pin"}, wantCode: exitInternalError, wantErr: "must run as root"},
		{name: "pin without --version", root: true, args: []string{"apply", "--yes", "--pin-sha256", sum}, wantCode: exitUsage, wantErr: "--version"},
		{name: "a malformed digest", root: true, args: []string{"apply", "--yes", "--version", "v0.2.0", "--pin-sha256", strings.ToUpper(sum)}, wantCode: exitUsage, wantErr: "64 lowercase hex"},
		{name: "clear with another flag", root: true, args: []string{"apply", "--clear-pin", "--version", "v0.2.0"}, wantCode: exitUsage, wantErr: "takes no other flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newUpdateCluster(server)
			var p pins
			code, _, errOut := c.runWith(t, asRoot(c, &p, tc.root), tc.args...)
			if code != tc.wantCode || !strings.Contains(errOut, tc.wantErr) {
				t.Fatalf("exit %d, stderr %q; want %d and %q", code, errOut, tc.wantCode, tc.wantErr)
			}
			if len(p.written) != 0 || p.cleared != 0 {
				t.Fatalf("the pin was touched: %+v", p)
			}
			if u, _ := getUpdate(context.Background(), c.dyn); u != nil {
				t.Fatalf("an Update was created: %+v", u.Spec)
			}
		})
	}

	t.Run("root writes the pin, then creates the Update", func(t *testing.T) {
		c := newUpdateCluster(server)
		var p pins
		code, out, errOut := c.runWith(t, asRoot(c, &p, true), "apply", "--yes", "--version", "v0.2.0", "--pin-sha256", sum)
		if code != 0 {
			t.Fatalf("exit %d, stderr %s", code, errOut)
		}
		if len(p.written) != 1 || p.written[0].Version != "v0.2.0" || p.written[0].SHA256 != sum || p.written[0].At.IsZero() {
			t.Fatalf("pin %+v", p.written)
		}
		if p.updateAtWrite {
			t.Fatal("the Update existed before the pin was written")
		}
		if got := c.get(t); got.Spec.Version != "v0.2.0" || got.Annotations[updatectl.ReleasePinRequiredAnnotation] != "v0.2.0" {
			t.Fatalf("Update version %s, annotations %v", got.Spec.Version, got.Annotations)
		}
		if !strings.Contains(out, "Pinned v0.2.0 to sha256:"+sum) {
			t.Fatalf("output %s", out)
		}

		// A second pinned apply while that Update is in progress writes nothing.
		c.setStatus(t, updatesv1alpha1.UpdateStatus{
			Phase:      updatesv1alpha1.UpdatePhaseRolling,
			Conditions: []metav1.Condition{progressing(metav1.ConditionTrue, updatectl.ReasonRolling)},
		})
		code, _, errOut = c.runWith(t, asRoot(c, &p, true), "apply", "--yes", "--version", "v0.2.1", "--pin-sha256", sum)
		if code != exitInternalError || !strings.Contains(errOut, "is Rolling") || len(p.written) != 1 {
			t.Fatalf("pinned apply while Rolling: exit %d, stderr %q, pins %+v", code, errOut, p.written)
		}
	})

	t.Run("root clears the pin without touching the cluster", func(t *testing.T) {
		c := newUpdateCluster(server)
		var p pins
		code, out, errOut := c.runWith(t, asRoot(c, &p, true), "apply", "--clear-pin")
		if code != 0 || p.cleared != 1 || !strings.Contains(out, "Removed the release pin") {
			t.Fatalf("exit %d, stderr %q, out %q, cleared %d", code, errOut, out, p.cleared)
		}
		if u, _ := getUpdate(context.Background(), c.dyn); u != nil {
			t.Fatalf("--clear-pin created an Update: %+v", u.Spec)
		}
	})

	t.Run("a contested clear names every aside and the recovery", func(t *testing.T) {
		c := newUpdateCluster(server)
		asides := []string{"/w/update.untrusted-1", "/w/update.untrusted-2"}
		code, _, errOut := c.runWith(t, func(env *updateEnv) {
			env.root, env.workDir = true, t.TempDir()
			env.clearPin = func(string) (updatectl.Cleared, error) {
				return updatectl.Cleared{}, &updatectl.PinDirContestedError{Dir: "/w/update", Attempts: 8, Asides: asides}
			}
		}, "apply", "--clear-pin")
		if code != exitInternalError {
			t.Fatalf("exit %d, stderr %s", code, errOut)
		}
		for _, want := range append(asides, "sudo launchctl bootout system/io.k3sm.server", "sudo k3sm update apply --clear-pin", "8 attempts") {
			if !strings.Contains(errOut, want) {
				t.Errorf("stderr lacks %q:\n%s", want, errOut)
			}
		}
	})

	t.Run("without the flags apply never touches the pin", func(t *testing.T) {
		c := newUpdateCluster(server)
		var p pins
		if code, _, errOut := c.runWith(t, asRoot(c, &p, true), "apply", "--yes", "--version", "v0.2.0"); code != 0 {
			t.Fatalf("exit %d, stderr %s", code, errOut)
		}
		if len(p.written) != 0 || p.cleared != 0 {
			t.Fatalf("the pin was touched: %+v", p)
		}
		if a := c.get(t).Annotations; a[updatectl.ReleasePinRequiredAnnotation] != "" {
			t.Fatalf("an unpinned Update requires a pin: %v", a)
		}
	})
}
