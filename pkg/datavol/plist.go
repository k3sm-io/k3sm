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
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// decodePlist decodes an XML property list into Go values: <dict> becomes
// map[string]any, <array> becomes []any, <integer> becomes int64, <real>
// becomes float64, <true/> and <false/> become bool, and <string>, <date> and
// <data> become string.
//
// It is deliberately strict. An element it does not know, a <key> with no
// value, a value with no key, or a truncated document is an error -- never a
// silent zero. Everything this package decides (is the volume case-sensitive,
// did the quota land, is it locked) is read out of this structure, so a
// diskutil output shape that drifted on a future macOS must announce itself
// rather than answer "false".
//
// Only the shapes diskutil emits are supported; this is not a general plist
// library, and binary plists are not read (diskutil's -plist output is XML).
func decodePlist(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("plist: no <plist> element")
		}
		if err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "plist" {
			return nil, fmt.Errorf("plist: root element is <%s>, want <plist>", start.Name.Local)
		}
		v, err := decodeNext(d, "plist")
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, fmt.Errorf("plist: <plist> is empty")
		}
		return v, nil
	}
}

// decodeNext reads the next value inside the element named parent. It returns
// (nil, nil) when the parent's end tag arrives first, which is how the dict and
// array loops terminate.
func decodeNext(d *xml.Decoder, parent string) (any, error) {
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("plist: unexpected end of document inside <%s>", parent)
		}
		if err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return decodeValue(d, t)
		case xml.EndElement:
			if t.Name.Local != parent {
				return nil, fmt.Errorf("plist: </%s> closes <%s>", t.Name.Local, parent)
			}
			return nil, nil
		}
	}
}

// decodeValue decodes the element that has just started.
func decodeValue(d *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		return decodeDict(d)
	case "array":
		return decodeArray(d)
	case "string", "date", "data":
		return elementText(d, start)
	case "integer":
		text, err := elementText(d, start)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("plist: <integer>%s</integer>: %w", text, err)
		}
		return n, nil
	case "real":
		text, err := elementText(d, start)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			return nil, fmt.Errorf("plist: <real>%s</real>: %w", text, err)
		}
		return f, nil
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, fmt.Errorf("plist: <%s/>: %w", start.Name.Local, err)
		}
		return start.Name.Local == "true", nil
	default:
		return nil, fmt.Errorf("plist: unknown element <%s>", start.Name.Local)
	}
}

// decodeDict decodes the body of a <dict> that has just started.
func decodeDict(d *xml.Decoder) (map[string]any, error) {
	out := map[string]any{}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("plist: unexpected end of document inside <dict>")
		}
		if err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "key" {
				return nil, fmt.Errorf("plist: <%s> where <dict> expects a <key>", t.Name.Local)
			}
			key, err := elementText(d, t)
			if err != nil {
				return nil, err
			}
			val, err := decodeNext(d, "dict")
			if err != nil {
				return nil, err
			}
			if val == nil {
				return nil, fmt.Errorf("plist: key %q has no value", key)
			}
			out[key] = val
		case xml.EndElement:
			if t.Name.Local != "dict" {
				return nil, fmt.Errorf("plist: </%s> closes <dict>", t.Name.Local)
			}
			return out, nil
		}
	}
}

// decodeArray decodes the body of an <array> that has just started.
func decodeArray(d *xml.Decoder) ([]any, error) {
	out := []any{}
	for {
		v, err := decodeNext(d, "array")
		if err != nil {
			return nil, err
		}
		if v == nil {
			return out, nil
		}
		out = append(out, v)
	}
}

// elementText reads the character data of a leaf element up to its end tag.
func elementText(d *xml.Decoder, start xml.StartElement) (string, error) {
	var sb strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return "", fmt.Errorf("plist: unexpected end of document inside <%s>", start.Name.Local)
		}
		if err != nil {
			return "", fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.StartElement:
			return "", fmt.Errorf("plist: <%s> nested inside <%s>", t.Name.Local, start.Name.Local)
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}

// rootDict decodes data and requires the root value to be a dict, which every
// diskutil -plist output is.
func rootDict(data []byte) (map[string]any, error) {
	v, err := decodePlist(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plist: root value is %T, want a dict", v)
	}
	return m, nil
}

// dictString returns the string at key. A key that is absent yields "" with no
// error -- diskutil omits keys that do not apply, e.g. MountPoint on an
// unmounted volume. A key that is present with another type IS an error.
func dictString(d map[string]any, key string) (string, error) {
	v, ok := d[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("plist: key %q is %T, want a string", key, v)
	}
	return s, nil
}

// dictBool returns the bool at key, false when absent, an error when present
// with another type.
func dictBool(d map[string]any, key string) (bool, error) {
	v, ok := d[key]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("plist: key %q is %T, want a boolean", key, v)
	}
	return b, nil
}

// dictUint returns the non-negative integer at key, 0 when absent, an error
// when present with another type or negative.
func dictUint(d map[string]any, key string) (uint64, error) {
	v, ok := d[key]
	if !ok {
		return 0, nil
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("plist: key %q is %T, want an integer", key, v)
	}
	if n < 0 {
		return 0, fmt.Errorf("plist: key %q is %d, want a non-negative integer", key, n)
	}
	return uint64(n), nil
}

// dictArray returns the array at key, nil when absent, an error when present
// with another type.
func dictArray(d map[string]any, key string) ([]any, error) {
	v, ok := d[key]
	if !ok {
		return nil, nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("plist: key %q is %T, want an array", key, v)
	}
	return a, nil
}

// parseInfoPlist decodes "diskutil info -plist <target>" output.
//
// The key names are pinned against real output captured from the lab rig
// (testdata/disk3s7.plist). Two are worth naming: case sensitivity is only
// expressed in the human-readable FilesystemName ("Case-sensitive APFS"), and
// the encryption flag's key is Encryption, not Encrypted.
func parseInfoPlist(data []byte) (Info, error) {
	d, err := rootDict(data)
	if err != nil {
		return Info{}, err
	}
	var info Info
	strs := []struct {
		key string
		dst *string
	}{
		{"DeviceIdentifier", &info.DeviceIdentifier},
		{"VolumeUUID", &info.VolumeUUID},
		{"VolumeName", &info.VolumeName},
		{"MountPoint", &info.MountPoint},
		{"APFSContainerReference", &info.ContainerReference},
		{"FilesystemType", &info.FilesystemType},
		{"FilesystemName", &info.FilesystemName},
	}
	for _, f := range strs {
		v, err := dictString(d, f.key)
		if err != nil {
			return Info{}, err
		}
		*f.dst = v
	}
	bools := []struct {
		key string
		dst *bool
	}{
		{"Encryption", &info.Encrypted},
		{"FileVault", &info.FileVault},
		{"Locked", &info.Locked},
	}
	for _, f := range bools {
		v, err := dictBool(d, f.key)
		if err != nil {
			return Info{}, err
		}
		*f.dst = v
	}
	info.CaseSensitive = strings.Contains(info.FilesystemName, "Case-sensitive")
	return info, nil
}

// parseCapacityPlist decodes "diskutil apfs list -plist <container>" output and
// returns the capacity of the volume whose APFSVolumeUUID is uuid. The compare
// is case-insensitive because diskutil prints UUIDs upper-case while a record
// may carry whatever case it was given.
//
// container may be empty, which searches every container in the listing.
func parseCapacityPlist(data []byte, container, uuid string) (Capacity, error) {
	d, err := rootDict(data)
	if err != nil {
		return Capacity{}, err
	}
	containers, err := dictArray(d, "Containers")
	if err != nil {
		return Capacity{}, err
	}
	for _, c := range containers {
		cd, ok := c.(map[string]any)
		if !ok {
			return Capacity{}, fmt.Errorf("plist: container entry is %T, want a dict", c)
		}
		ref, err := dictString(cd, "ContainerReference")
		if err != nil {
			return Capacity{}, err
		}
		if container != "" && !strings.EqualFold(ref, container) {
			continue
		}
		volumes, err := dictArray(cd, "Volumes")
		if err != nil {
			return Capacity{}, err
		}
		for _, v := range volumes {
			vd, ok := v.(map[string]any)
			if !ok {
				return Capacity{}, fmt.Errorf("plist: volume entry is %T, want a dict", v)
			}
			got, err := dictString(vd, "APFSVolumeUUID")
			if err != nil {
				return Capacity{}, err
			}
			if !strings.EqualFold(got, uuid) {
				continue
			}
			var out Capacity
			nums := []struct {
				key string
				dst *uint64
			}{
				{"CapacityQuota", &out.Quota},
				{"CapacityReserve", &out.Reserve},
				{"CapacityInUse", &out.InUse},
			}
			for _, f := range nums {
				n, err := dictUint(vd, f.key)
				if err != nil {
					return Capacity{}, err
				}
				*f.dst = n
			}
			return out, nil
		}
	}
	return Capacity{}, fmt.Errorf("no volume %s in apfs container %q", uuid, container)
}
