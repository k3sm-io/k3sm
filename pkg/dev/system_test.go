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

package dev

import (
	"os/exec"
	"reflect"
	"testing"
)

// TestParseLo0Inet pins the ifconfig lo0 parser against a realistic fixture:
// only the inet (IPv4) addresses are extracted; inet6 lines are ignored.
func TestParseLo0Inet(t *testing.T) {
	out := `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
	inet 10.43.0.10 netmask 0xffffffff
	inet 100.64.0.5 netmask 0xffffffff
	nd6 options=201<PERFORMNUD,DAD>
`
	got := parseLo0Inet(out)
	want := []string{"127.0.0.1", "10.43.0.10", "100.64.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseLo0Inet = %v, want %v", got, want)
	}
}

func TestParseLo0InetEmpty(t *testing.T) {
	if got := parseLo0Inet("lo0: flags=8049\n\tinet6 ::1 prefixlen 128\n"); len(got) != 0 {
		t.Errorf("parseLo0Inet with no inet lines = %v, want empty", got)
	}
}

// TestRealSystemRunsIfconfigByAbsolutePath proves Lo0Aliases and Lo0RemoveAlias
// build their command from the absolute ifconfig path, without running ifconfig.
func TestRealSystemRunsIfconfigByAbsolutePath(t *testing.T) {
	if ifconfigPath != "/sbin/ifconfig" {
		t.Fatalf("ifconfigPath = %q, want /sbin/ifconfig", ifconfigPath)
	}
	var got [][]string
	orig := ifconfigCommand
	t.Cleanup(func() { ifconfigCommand = orig })
	ifconfigCommand = func(args ...string) *exec.Cmd {
		c := orig(args...)
		got = append(got, c.Args)
		return exec.Command("/usr/bin/true")
	}
	s := realSystem{}
	if _, err := s.Lo0Aliases(); err != nil {
		t.Fatalf("Lo0Aliases: %v", err)
	}
	if err := s.Lo0RemoveAlias("100.64.0.2"); err != nil {
		t.Fatalf("Lo0RemoveAlias: %v", err)
	}
	want := [][]string{
		{"/sbin/ifconfig", "lo0"},
		{"/sbin/ifconfig", "lo0", "-alias", "100.64.0.2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}
