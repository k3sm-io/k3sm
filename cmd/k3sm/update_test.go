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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/update"
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
	for _, args := range [][]string{nil, {"bogus"}, {"check", "-o", "yaml"}, {"check", "extra"}} {
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
