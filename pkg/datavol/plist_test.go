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

package datavol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads one of the captured diskutil outputs in testdata/.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// TestPlistDictReader pins the decoder against real diskutil output captured
// from the lab rig, and pins its strictness: a key with the wrong type and an
// element the decoder does not know are errors, never a silent zero, because
// every decision this package makes is read out of this structure.
func TestPlistDictReader(t *testing.T) {
	const rigUUID = "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD"
	const quotaUUID = "49533279-726B-4618-BEAB-BFD3980D9D31"

	t.Run("diskutil info of the rig's data volume", func(t *testing.T) {
		info, err := parseInfoPlist(fixture(t, "disk3s7.plist"))
		if err != nil {
			t.Fatalf("parseInfoPlist: %v", err)
		}
		want := Info{
			DeviceIdentifier:   "disk3s7",
			VolumeUUID:         rigUUID,
			VolumeName:         "k3sm-pods",
			MountPoint:         "/private/var/lib/k3sm",
			ContainerReference: "disk3",
			FilesystemType:     "apfs",
			FilesystemName:     "Case-sensitive APFS",
			CaseSensitive:      true,
			Encrypted:          true,
			FileVault:          false,
			Locked:             false,
		}
		if info != want {
			t.Fatalf("parseInfoPlist\n got %+v\nwant %+v", info, want)
		}
	})

	t.Run("a quota'd volume reports it in the container listing", func(t *testing.T) {
		got, err := parseCapacityPlist(fixture(t, "apfs-list.plist"), "disk3", quotaUUID)
		if err != nil {
			t.Fatalf("parseCapacityPlist: %v", err)
		}
		want := Capacity{Quota: 1000001536, Reserve: 0, InUse: 24576}
		if got != want {
			t.Fatalf("parseCapacityPlist = %+v, want %+v", got, want)
		}
	})

	t.Run("a volume with no quota reports zero, not an error", func(t *testing.T) {
		got, err := parseCapacityPlist(fixture(t, "apfs-list.plist"), "disk3", strings.ToLower(rigUUID))
		if err != nil {
			t.Fatalf("parseCapacityPlist: %v", err)
		}
		if got.Quota != 0 {
			t.Fatalf("Quota = %d, want 0 (the rig's volume carries no quota)", got.Quota)
		}
		if got.InUse == 0 {
			t.Fatal("InUse = 0, want the rig's real usage")
		}
	})

	t.Run("a volume that is not in the container is an error", func(t *testing.T) {
		if _, err := parseCapacityPlist(fixture(t, "apfs-list.plist"), "disk3", "NO-SUCH-UUID"); err == nil {
			t.Fatal("parseCapacityPlist accepted a UUID that is not in the listing")
		}
	})

	t.Run("a key with the wrong type is an error, not a zero", func(t *testing.T) {
		doc := plistDoc(`<dict><key>CapacityQuota</key><string>lots</string></dict>`)
		d, err := rootDict([]byte(doc))
		if err != nil {
			t.Fatalf("rootDict: %v", err)
		}
		if _, err := dictUint(d, "CapacityQuota"); err == nil {
			t.Fatal("dictUint accepted a string")
		}
		if _, err := dictBool(d, "CapacityQuota"); err == nil {
			t.Fatal("dictBool accepted a string")
		}
		if _, err := dictArray(d, "CapacityQuota"); err == nil {
			t.Fatal("dictArray accepted a string")
		}
		if v, err := dictString(d, "Absent"); err != nil || v != "" {
			t.Fatalf("dictString of an absent key = %q, %v; want \"\", nil", v, err)
		}
	})

	t.Run("an unknown element is an error", func(t *testing.T) {
		for _, doc := range []string{
			plistDoc(`<dict><key>K</key><ordereddict/></dict>`),
			plistDoc(`<dict><key>K</key></dict>`),
			plistDoc(`<dict><string>no key</string></dict>`),
			plistDoc(`<dict><key>K</key><integer>not a number</integer></dict>`),
			`<plist version="1.0"><dict><key>K</key><string>x</string>`,
			`<notaplist/>`,
		} {
			if _, err := decodePlist([]byte(doc)); err == nil {
				t.Fatalf("decodePlist accepted %q", doc)
			}
		}
	})

	t.Run("nested arrays and dicts decode all the way down", func(t *testing.T) {
		v, err := decodePlist([]byte(plistDoc(
			`<dict><key>Outer</key><array><dict><key>N</key><integer>7</integer>` +
				`<key>Sub</key><array><string>a</string><real>1.5</real><true/><false/></array>` +
				`</dict><array/></array></dict>`)))
		if err != nil {
			t.Fatalf("decodePlist: %v", err)
		}
		root, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("root is %T, want a dict", v)
		}
		outer, err := dictArray(root, "Outer")
		if err != nil || len(outer) != 2 {
			t.Fatalf("Outer = %v, %v; want two entries", outer, err)
		}
		first, ok := outer[0].(map[string]any)
		if !ok {
			t.Fatalf("Outer[0] is %T, want a dict", outer[0])
		}
		n, err := dictUint(first, "N")
		if err != nil || n != 7 {
			t.Fatalf("N = %d, %v; want 7", n, err)
		}
		sub, err := dictArray(first, "Sub")
		if err != nil {
			t.Fatalf("Sub: %v", err)
		}
		if len(sub) != 4 || sub[0] != "a" || sub[1] != 1.5 || sub[2] != true || sub[3] != false {
			t.Fatalf("Sub = %#v", sub)
		}
		if empty, ok := outer[1].([]any); !ok || len(empty) != 0 {
			t.Fatalf("Outer[1] = %#v, want an empty array", outer[1])
		}
	})
}

// plistDoc wraps a body in the plist envelope diskutil emits.
func plistDoc(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0">` + body + `</plist>`
}

// FuzzPlistDict drives the decoder with arbitrary input. diskutil's output
// shape is not a contract k3sm controls, and the decoder runs as root in the
// boot daemon, so the property that matters is that it always returns -- with
// a value or an error, never a panic.
func FuzzPlistDict(f *testing.F) {
	for _, name := range []string{"disk3s7.plist", "apfs-list.plist"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatalf("read fixture: %v", err)
		}
		f.Add(string(data))
	}
	f.Add(plistDoc(`<dict><key>K</key><integer>1</integer></dict>`))
	f.Add(plistDoc(`<array><true/><data>aGk=</data><date>2026-09-13T00:00:00Z</date></array>`))
	f.Add(`<plist><dict>`)
	f.Fuzz(func(t *testing.T, s string) {
		v, err := decodePlist([]byte(s))
		if err != nil {
			return
		}
		if d, ok := v.(map[string]any); ok {
			_, _ = dictString(d, "VolumeUUID")
			_, _ = dictUint(d, "CapacityQuota")
			_, _ = dictBool(d, "Locked")
			_, _ = dictArray(d, "Containers")
		}
		_, _ = parseInfoPlist([]byte(s))
		_, _ = parseCapacityPlist([]byte(s), "disk3", "x")
	})
}
