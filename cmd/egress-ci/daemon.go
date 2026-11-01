package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Docker daemon pulls the job's images itself: it runs as root in its own cgroup, so neither HTTPS_PROXY nor the
// lock's rules for the job's user see its connections to the registry, the registry's token service and the CDN that
// serves the layers (auth.docker.io, production.cloudflare.docker.com, pkg-containers.githubusercontent.com…). The
// lock sends the daemon's TCP to public addresses through the transparent proxy on daemonAddr, which names each
// connection by its SNI and records it while the job has a pull, push, build or login in flight through its Docker
// socket. Those connections are never refused: the daemon serves the whole runner, and the job's pulls are held by
// registry at the socket.

// daemonAddr is where the lock sends the daemon's connections (the transparent port): an address of its own tells
// them apart from the job's.
const daemonAddr = "127.0.0.2"

// daemonGrace keeps the window open a little after the last operation ends (connections the daemon opens late).
const daemonGrace = 2 * time.Second

// daemonWindow is the set of the job's Docker operations in flight that make the daemon reach a registry.
type daemonWindow struct {
	mu     sync.Mutex
	active map[int]string
	next   int
	last   []string
	ended  time.Time
}

// begin records an operation ("pull alpine:3") until the returned function is called (nil-safe).
func (w *daemonWindow) begin(op string) func() {
	if w == nil {
		return func() {}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active == nil {
		w.active = map[int]string{}
	}
	id := w.next
	w.next++
	w.active[id] = op
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if _, ok := w.active[id]; !ok {
			return
		}
		delete(w.active, id)
		w.last, w.ended = []string{op}, time.Now()
		for _, o := range w.active {
			w.last = appendUnique(w.last, o)
		}
	}
}

// ops returns the operations in flight, or those that ended within daemonGrace; empty outside the window.
func (w *daemonWindow) ops(now time.Time) []string {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for i := range w.next {
		if op, ok := w.active[i]; ok {
			out = appendUnique(out, op)
		}
	}
	if len(out) == 0 && !w.ended.IsZero() && now.Sub(w.ended) <= daemonGrace {
		out = append(out, w.last...)
	}
	return out
}

var reCgroupPath = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+(/[A-Za-z0-9_.@:-]+)*$`)

// daemonCgroups returns the cgroup v2 paths (relative to the cgroup root) of the Docker daemon behind sock, found
// from the socket's peer when it is dockerd, and of the usual systemd units of dockerd and containerd (its image
// store); never the sidecar's own cgroup.
func daemonCgroups(chroot, sock string) []string {
	self := cgroupOf("/proc/self/cgroup")
	var out []string
	add := func(p string) {
		p = strings.Trim(p, "/")
		if p == "" || p == self || !reCgroupPath.MatchString(p) || contains(out, p) {
			return
		}
		if st, err := os.Stat(filepath.Join(chroot, "/sys/fs/cgroup", p)); err != nil || !st.IsDir() {
			return
		}
		out = append(out, p)
	}
	if pid := socketPeerPID(sock); pid > 0 {
		proc := filepath.Join(chroot, "/proc", strconv.Itoa(pid))
		if comm, _ := os.ReadFile(filepath.Join(proc, "comm")); strings.TrimSpace(string(comm)) == "dockerd" {
			add(cgroupOf(filepath.Join(proc, "cgroup")))
		}
	}
	add("system.slice/docker.service")
	add("system.slice/containerd.service")
	return out
}

// cgroupOf reads the cgroup v2 path of a /proc/<pid>/cgroup file ("0::/system.slice/docker.service").
func cgroupOf(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.Trim(p, "/")
		}
	}
	return ""
}

// observeDaemon sends the TCP of the given cgroups to public addresses to the transparent port on daemonAddr. Apart
// from the lock's table so a kernel without cgroup v2 socket matching only loses this.
func (l *nftLock) observeDaemon(cgroups []string, port int) error {
	var b strings.Builder
	for _, cg := range cgroups {
		fmt.Fprintf(&b, "add rule inet %s job_nat meta nfproto ipv4 socket cgroupv2 level %d \"%s\" ip daddr != { 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12 } fib daddr type != local meta l4proto tcp dnat ip to %s:%d\n",
			l.table, strings.Count(cg, "/")+1, cg, daemonAddr, port)
	}
	_, err := l.run(b.String(), "-f", "-")
	return err
}

func (t *transparent) serveDaemon(ln net.Listener) {
	acceptLoop(ln, t.handleDaemon)
}

// handleDaemon passes a connection of the Docker daemon to where it was going, recording it when the job has an
// operation in flight that makes the daemon reach a registry. Recorded once named, without byte counts: the daemon
// keeps its registry connections open past the job's end.
func (t *transparent) handleDaemon(c net.Conn) {
	defer c.Close()
	dst, err := originalDst(c)
	if err != nil {
		return
	}
	ip := dst.IP.String()
	br := bufio.NewReaderSize(c, 16<<10)
	ops := t.daemon.ops(time.Now())
	name, _ := t.peekName(c, br, dst.Port)
	if len(ops) > 0 {
		ev := Event{Kind: "daemon", Host: name, Port: dst.Port, SNI: name, Decision: "allow", Note: strings.Join(ops, ", ")}
		if ev.Host == "" {
			if known := t.dns.namesFor(ip); len(known) > 0 {
				ev.Host = known[0]
			} else {
				ev.Host = ip
			}
		}
		t.p.log.add(ev)
	}
	up, err := t.p.dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, strconv.Itoa(dst.Port)))
	if err != nil {
		return
	}
	defer up.Close()
	pipe(c, br, up)
}
