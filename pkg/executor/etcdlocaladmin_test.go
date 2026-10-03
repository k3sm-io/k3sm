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

package executor

import (
	"context"
	"reflect"
	"testing"
)

// TestLocalEtcdAdminPassesThrough pins the exported loopback admin: it reports the
// local member's ID from Status, converts the member list field for field, closes the
// client, and refuses to connect without the work dir's etcd client identity.
func TestLocalEtcdAdminPassesThrough(t *testing.T) {
	members := []etcdMember{
		{ID: 1, Name: "a", PeerURLs: []string{"https://192.168.0.50:2380"}, ClientURLs: []string{"https://127.0.0.1:2379"}},
		{ID: 2, PeerURLs: []string{"https://192.168.0.111:2380"}, IsLearner: true},
	}
	fake := &fakeEtcd{status: etcdMemberStatus{MemberID: 1, Leader: 1}, members: members}
	a := &LocalEtcdAdmin{admin: fake}
	ctx := context.Background()

	id, err := a.LocalMemberID(ctx)
	if err != nil || id != 1 {
		t.Fatalf("LocalMemberID = %d, %v; want 1", id, err)
	}
	got, err := a.MemberList(ctx)
	if err != nil {
		t.Fatalf("MemberList: %v", err)
	}
	want := []EtcdMember{
		{ID: 1, Name: "a", PeerURLs: []string{"https://192.168.0.50:2380"}, ClientURLs: []string{"https://127.0.0.1:2379"}},
		{ID: 2, PeerURLs: []string{"https://192.168.0.111:2380"}, IsLearner: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MemberList = %+v, want %+v", got, want)
	}
	if err := a.Close(); err != nil || !fake.closed {
		t.Errorf("Close = %v, closed=%v", err, fake.closed)
	}

	if _, err := NewLocalEtcdAdmin(ctx, t.TempDir(), DefaultKinePort); err == nil {
		t.Error("NewLocalEtcdAdmin connected with no etcd client identity in the work dir")
	}
}
