//go:build darwin

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
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// rtmNames names the routing-message types S1 cares about; anything else is
// printed by number.
var rtmNames = map[int]string{
	unix.RTM_IFINFO:  "RTM_IFINFO",
	unix.RTM_NEWADDR: "RTM_NEWADDR",
	unix.RTM_DELADDR: "RTM_DELADDR",
	unix.RTM_ADD:     "RTM_ADD",
	unix.RTM_DELETE:  "RTM_DELETE",
	unix.RTM_CHANGE:  "RTM_CHANGE",
}

// rawRoute reads a second, independent PF_ROUTE socket and reports every
// interface-scoped message with its type, so S1 can say which message (if any)
// an unplug produces, separately from what linkwatch makes of it. It reads the
// same if_msghdr/ifa_msghdr prefix linkwatch decodes (length, version, type,
// addrs, flags, index); route messages carry no interface index in that slot,
// so only the three interface types are attributed to an interface.
func rawRoute(ctx context.Context, out chan<- watchEvent, exists func(string) bool) error {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("open PF_ROUTE socket: %w", err)
	}
	f := os.NewFile(uintptr(fd), "pf_route_raw")
	go func() {
		<-ctx.Done()
		_ = f.Close()
	}()
	go func() {
		names := map[int]string{}
		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			b := buf[:n]
			for len(b) >= 14 {
				msgLen := int(binary.NativeEndian.Uint16(b[0:2]))
				if msgLen < 14 || msgLen > len(b) {
					break
				}
				typ := int(b[3])
				flags := int32(binary.NativeEndian.Uint32(b[8:12]))
				index := int(binary.NativeEndian.Uint16(b[12:14]))
				b = b[msgLen:]
				if typ != unix.RTM_IFINFO && typ != unix.RTM_NEWADDR && typ != unix.RTM_DELADDR {
					continue
				}
				name := names[index]
				if ifi, err := net.InterfaceByIndex(index); err == nil {
					name = ifi.Name
					names[index] = name
				}
				rtm, ok := rtmNames[typ]
				if !ok {
					rtm = fmt.Sprint(typ)
				}
				up := typ == unix.RTM_IFINFO && flags&unix.IFF_UP != 0 && flags&unix.IFF_RUNNING != 0
				select {
				case out <- watchEvent{Time: now(), Source: "raw", Iface: name, Up: up, Exists: name != "" && exists(name), RTM: rtm}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}
