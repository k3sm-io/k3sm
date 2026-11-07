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

package registrysvc

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// watchUserIdent is the EVFILT_USER event stop wakes the watch with.
const watchUserIdent = 1

// watchParent watches pid with kqueue EVFILT_PROC NOTE_EXIT. The returned channel
// closes when pid exits, or when the watch itself fails, since a server that can
// no longer see its parent cannot keep its promise to die with it. stop ends the
// watch and may be called more than once. A pid already gone is ErrParentExited.
func watchParent(pid int) (<-chan struct{}, func(), error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, nil, fmt.Errorf("watch the parent: kqueue: %w", err)
	}
	unix.CloseOnExec(kq)
	changes := []unix.Kevent_t{
		{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT},
		{Ident: watchUserIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR},
	}
	if _, err := unix.Kevent(kq, changes, nil, nil); err != nil {
		_ = unix.Close(kq) // the registration already failed
		if errors.Is(err, unix.ESRCH) {
			return nil, nil, fmt.Errorf("%w: pid %d", ErrParentExited, pid)
		}
		return nil, nil, fmt.Errorf("watch the parent: register pid %d: %w", pid, err)
	}
	gone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		events := make([]unix.Kevent_t, 1)
		for {
			n, err := unix.Kevent(kq, nil, events, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				close(gone)
				return
			}
			if n == 0 {
				continue
			}
			if events[0].Filter != unix.EVFILT_USER {
				close(gone)
			}
			return
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			wake := []unix.Kevent_t{{Ident: watchUserIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}}
			_, _ = unix.Kevent(kq, wake, nil, nil) // a watch that has already ended has nothing to wake
			<-done
			_ = unix.Close(kq) // nothing is left to report a close failure to
		})
	}
	return gone, stop, nil
}
