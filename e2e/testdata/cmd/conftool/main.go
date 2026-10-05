// Command conftool is the one-shot multi-tool the k3sm e2e conformance suite runs
// inside native pods for the assertions a /bin/sh script can't express cleanly:
//
//   - memhog  — allocate and TOUCH N MiB (so the pages count toward the runtimed
//     ri_phys_footprint), then idle, to drive the userspace memory-limit kill →
//     OOMKilled (TestM2_ResourceLimitsOOMKilled).
//   - apicall — read the projected bound SA token + CA from the canonical in-pod
//     path and HTTPS-GET the apiserver, asserting an exact status (TestM2_InPodKubectl).
//   - resolve — resolve cluster DNS names via the in-pod getaddrinfo shim
//     (TestM2_InPodDNS).
//
// Each subcommand exits 0 on success, non-zero (with a stderr reason) on failure,
// so the test asserts the pod phase (Succeeded/Failed) — no log parsing. stdlib
// only: builds CGO_ENABLED=0 and, ad-hoc-signed, execs under the default-deny
// Seatbelt profile.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// saDir is the canonical in-pod mount of the projected ServiceAccount token + the
// apiserver serving CA (kube-root-ca.crt), where a stock in-cluster client looks.
const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

func main() {
	if len(os.Args) < 2 {
		fail("usage: conftool <memhog|apicall|resolve|readfile|writeread|marker|dial> [flags]")
	}
	switch os.Args[1] {
	case "memhog":
		memhog(os.Args[2:])
	case "apicall":
		apicall(os.Args[2:])
	case "resolve":
		resolve(os.Args[2:])
	case "readfile":
		readfile(os.Args[2:])
	case "writeread":
		writeread(os.Args[2:])
	case "marker":
		marker(os.Args[2:])
	case "dial":
		dial(os.Args[2:])
	default:
		fail("conftool: unknown subcommand %q", os.Args[1])
	}
}

// memhog allocates and touches mb MiB, then idles forever (the parent pod is
// killed by the runtime's memory-limit enforcement once its footprint exceeds the
// limit). Touching every page makes the memory resident so it counts.
func memhog(args []string) {
	fs := flag.NewFlagSet("memhog", flag.ExitOnError)
	mb := fs.Int("mb", 256, "MiB to allocate and touch")
	_ = fs.Parse(args)

	const pageSize = 4096
	blocks := make([][]byte, 0, *mb)
	for i := 0; i < *mb; i++ {
		b := make([]byte, 1<<20)
		for j := 0; j < len(b); j += pageSize {
			b[j] = byte(i) // fault the page in so it's resident (counts toward footprint)
		}
		blocks = append(blocks, b)
	}
	fmt.Printf("memhog: allocated and touched %d MiB; idling\n", *mb)
	for {
		time.Sleep(time.Hour)
	}
}

// apicall reads the projected SA token + CA and HTTPS-GETs the apiserver, exiting
// non-zero unless the response status equals expect.
func apicall(args []string) {
	fs := flag.NewFlagSet("apicall", flag.ExitOnError)
	base := fs.String("url", "https://kubernetes.default.svc", "apiserver base URL (resolved via in-pod DNS)")
	path := fs.String("path", "/api/v1/namespaces/default/pods", "request path")
	expect := fs.Int("expect-status", 200, "required HTTP status code")
	_ = fs.Parse(args)

	token, err := os.ReadFile(saDir + "/token")
	if err != nil {
		fail("read SA token %s/token: %v", saDir, err)
	}
	caPEM, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		fail("read SA ca.crt %s/ca.crt: %v", saDir, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fail("parse SA ca.crt: no PEM certificates")
	}

	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	req, err := http.NewRequest(http.MethodGet, *base+*path, nil)
	if err != nil {
		fail("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err := client.Do(req)
	if err != nil {
		fail("GET %s%s: %v", *base, *path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != *expect {
		fail("GET %s%s: status %d, want %d (body: %s)", *base, *path, resp.StatusCode, *expect, body)
	}
	fmt.Printf("apicall: GET %s%s -> %d (ok)\n", *base, *path, resp.StatusCode)
}

// resolve looks up each -name, exiting non-zero if any fails to resolve (the
// in-pod DNS path: the getaddrinfo shim against the per-node cluster resolver).
func resolve(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	var names hostList
	fs.Var(&names, "name", "hostname to resolve (repeatable)")
	_ = fs.Parse(args)
	if len(names) == 0 {
		names = hostList{"kubernetes.default.svc"}
	}
	for _, n := range names {
		addrs, err := net.LookupHost(n)
		if err != nil {
			fail("resolve %s: %v", n, err)
		}
		fmt.Printf("resolve: %s -> %v\n", n, addrs)
	}
}

// hostList collects repeated -name flags.
type hostList []string

func (h *hostList) String() string     { return fmt.Sprint([]string(*h)) }
func (h *hostList) Set(v string) error { *h = append(*h, v); return nil }

// fail prints to stderr and exits 1.
// dial connects to -addr and reads the first line the peer writes. With
// -expect it retries for -for until that line contains the expected text,
// failing at once if a DIFFERENT banner answers (the wrong pod reached). With
// -refused it expects the connection itself to fail, and fail fast: an error that
// is a timeout (a dial that hung) fails the check, as does any connection.
func dial(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port to dial")
	expect := fs.String("expect", "", "text the peer's first line must contain")
	refused := fs.Bool("refused", false, "expect the connection to be refused (fast), not answered")
	within := fs.Duration("for", 2*time.Minute, "how long to retry for the expected banner")
	_ = fs.Parse(args)
	if *addr == "" {
		fail("dial: -addr is required")
	}
	if *refused {
		conn, err := net.DialTimeout("tcp", *addr, 10*time.Second)
		if err == nil {
			_ = conn.Close() // the check failed; the close error adds nothing
			fail("dial %s: connected, want refused", *addr)
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			fail("dial %s: timed out (a hang), want a fast refusal: %v", *addr, err)
		}
		fmt.Printf("REFUSED=%v\n", err)
		return
	}
	deadline := time.Now().Add(*within)
	var last string
	for time.Now().Before(deadline) {
		line, err := readBanner(*addr)
		switch {
		case err != nil:
			last = err.Error()
		case strings.Contains(line, *expect):
			fmt.Printf("BANNER=%s\n", line)
			return
		case strings.HasPrefix(line, "BANNER="):
			fail("dial %s: answered %q, want %q (another pod answered)", *addr, line, *expect)
		default:
			last = fmt.Sprintf("unexpected first line %q", line)
		}
		time.Sleep(time.Second)
	}
	fail("dial %s: no %q within %s; last: %s", *addr, *expect, *within, last)
}

// readBanner dials addr and returns the first line the peer writes.
func readBanner(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }() // read-only use; nothing to flush
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
