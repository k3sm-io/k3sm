//go:build darwin && cgo

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

package provider

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>

// k3sm_pm_hold takes a kIOPMAssertionTypePreventSystemSleep assertion
// (IOPMLib.h, IOPMAssertionCreateWithName). The assertion keeps the system
// from idle sleep while on AC power; the OS ignores it on battery and it never
// blocks a user-forced or clamshell sleep. It is tied to this process: the
// kernel releases it if the process exits. Returns an IOReturn.
static int k3sm_pm_hold(const char *name, uint32_t *out) {
	CFStringRef n = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);
	if (n == NULL) return kIOReturnNoMemory;
	IOPMAssertionID id = kIOPMNullAssertionID;
	IOReturn r = IOPMAssertionCreateWithName(kIOPMAssertionTypePreventSystemSleep, kIOPMAssertionLevelOn, n, &id);
	CFRelease(n);
	if (r == kIOReturnSuccess) *out = (uint32_t)id;
	return (int)r;
}

static int k3sm_pm_release(uint32_t id) { return (int)IOPMAssertionRelease((IOPMAssertionID)id); }

// The sleep watcher: IORegisterForSystemPower (IOPMLib.h) on a dedicated
// thread running its own CFRunLoop. The callback never calls into Go: it
// writes one byte per notice to evfd ('S' will-sleep, 'W' has-powered-on) and,
// for will-sleep, waits on ackfd (bounded by ack_ms) before IOAllowPowerChange,
// which the system requires for every kIOMessageCanSystemSleep and
// kIOMessageSystemWillSleep (it otherwise waits 30 s). Closing ackfd's write
// end makes the wait return at once.
typedef struct {
	int evfd, ackfd, ack_ms;
	io_connect_t root;
	IONotificationPortRef port;
	io_object_t notifier;
	CFRunLoopRef rl;
	pthread_t thread;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int ready, err;
} k3sm_pw;

static void k3sm_pw_cb(void *refcon, io_service_t svc, natural_t type, void *arg) {
	k3sm_pw *w = (k3sm_pw *)refcon;
	char b;
	switch (type) {
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(w->root, (long)arg);
		break;
	case kIOMessageSystemWillSleep: {
		b = 'S';
		(void)write(w->evfd, &b, 1);
		struct pollfd p = { .fd = w->ackfd, .events = POLLIN };
		if (poll(&p, 1, w->ack_ms) > 0 && (p.revents & POLLIN)) (void)read(w->ackfd, &b, 1);
		IOAllowPowerChange(w->root, (long)arg);
		break;
	}
	case kIOMessageSystemHasPoweredOn:
		b = 'W';
		(void)write(w->evfd, &b, 1);
		break;
	default:
		break;
	}
}

static void *k3sm_pw_main(void *p) {
	k3sm_pw *w = (k3sm_pw *)p;
	w->root = IORegisterForSystemPower(w, &w->port, k3sm_pw_cb, &w->notifier);
	pthread_mutex_lock(&w->mu);
	if (w->root == MACH_PORT_NULL) {
		w->err = 1;
	} else {
		w->rl = CFRunLoopGetCurrent();
		CFRetain(w->rl);
		CFRunLoopAddSource(w->rl, IONotificationPortGetRunLoopSource(w->port), kCFRunLoopDefaultMode);
	}
	w->ready = 1;
	pthread_cond_signal(&w->cv);
	pthread_mutex_unlock(&w->mu);
	if (w->root == MACH_PORT_NULL) return NULL;
	CFRunLoopRun();
	CFRunLoopRemoveSource(w->rl, IONotificationPortGetRunLoopSource(w->port), kCFRunLoopDefaultMode);
	IODeregisterForSystemPower(&w->notifier);
	IOServiceClose(w->root);
	IONotificationPortDestroy(w->port);
	return NULL;
}

// k3sm_pw_start returns a running watcher, or NULL when registration failed.
static k3sm_pw *k3sm_pw_start(int evfd, int ackfd, int ack_ms) {
	k3sm_pw *w = calloc(1, sizeof(*w));
	if (w == NULL) return NULL;
	w->evfd = evfd; w->ackfd = ackfd; w->ack_ms = ack_ms;
	pthread_mutex_init(&w->mu, NULL);
	pthread_cond_init(&w->cv, NULL);
	if (pthread_create(&w->thread, NULL, k3sm_pw_main, w) != 0) {
		free(w);
		return NULL;
	}
	pthread_mutex_lock(&w->mu);
	while (!w->ready) pthread_cond_wait(&w->cv, &w->mu);
	pthread_mutex_unlock(&w->mu);
	if (w->err) {
		pthread_join(w->thread, NULL);
		free(w);
		return NULL;
	}
	return w;
}

// k3sm_pw_stop stops the run loop, joins the thread and frees the watcher.
static void k3sm_pw_stop(k3sm_pw *w) {
	CFRunLoopStop(w->rl);
	CFRunLoopWakeUp(w->rl);
	pthread_join(w->thread, NULL);
	CFRelease(w->rl);
	pthread_mutex_destroy(&w->mu);
	pthread_cond_destroy(&w->cv);
	free(w);
}
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"sync"
	"unsafe"
)

// sleepAckTimeoutMillis bounds how long the watcher holds a will-sleep notice
// for the reporter's acknowledgement. It covers the reporter's publish bound
// and flush grace with margin, and stays under the system's 30 s limit.
const sleepAckTimeoutMillis = 10000

// iokitPowerHost is the darwin PowerHost over IOKit's IOPMLib.
type iokitPowerHost struct{}

func newPowerHost() PowerHost { return iokitPowerHost{} }

// PreventSleep implements PowerHost with IOPMAssertionCreateWithName.
func (iokitPowerHost) PreventSleep(name string) (func() error, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var id C.uint32_t
	if r := C.k3sm_pm_hold(cname, &id); r != 0 {
		return nil, fmt.Errorf("IOPMAssertionCreateWithName(PreventSystemSleep): IOReturn %#x", uint32(r))
	}
	var once sync.Once
	var err error
	return func() error {
		once.Do(func() {
			if r := C.k3sm_pm_release(id); r != 0 {
				err = fmt.Errorf("IOPMAssertionRelease: IOReturn %#x", uint32(r))
			}
		})
		return err
	}, nil
}

// WatchSleep implements PowerHost with IORegisterForSystemPower.
func (iokitPowerHost) WatchSleep(ctx context.Context) (<-chan PowerNotice, error) {
	evR, evW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("sleep watcher pipe: %w", err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		_ = evR.Close()
		_ = evW.Close()
		return nil, fmt.Errorf("sleep watcher pipe: %w", err)
	}
	w := C.k3sm_pw_start(C.int(evW.Fd()), C.int(ackR.Fd()), C.int(sleepAckTimeoutMillis))
	if w == nil {
		for _, f := range []*os.File{evR, evW, ackR, ackW} {
			_ = f.Close()
		}
		return nil, fmt.Errorf("IORegisterForSystemPower failed")
	}
	out := make(chan PowerNotice)
	// The stopper: on ctx done, unblock any held will-sleep (closing ackW),
	// stop the watcher thread, then close evW so the reader below ends.
	go func() {
		<-ctx.Done()
		_ = ackW.Close()
		C.k3sm_pw_stop(w)
		_ = evW.Close()
		_ = ackR.Close()
	}()
	// The reader: one notice per byte, until evW is closed.
	go func() {
		defer close(out)
		defer evR.Close()
		buf := make([]byte, 1)
		for {
			if _, err := evR.Read(buf); err != nil {
				return
			}
			n := PowerNotice{Kind: PowerDidWake}
			if buf[0] == 'S' {
				var once sync.Once
				n = PowerNotice{Kind: PowerWillSleep, Ack: func() {
					once.Do(func() { _, _ = ackW.Write([]byte{'A'}) })
				}}
			}
			select {
			case out <- n:
			case <-ctx.Done():
				if n.Ack != nil {
					n.Ack()
				}
			}
		}
	}()
	return out, nil
}
