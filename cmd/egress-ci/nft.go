package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// nftLock is the per-job nftables table egress_ci_<uid>. It only matches sockets of the job's user (meta skuid) and
// the subnets of the job's Docker networks, so on a runner shared by several job users it never touches another job.
type nftLock struct {
	chroot string
	uid    int
	table  string
	nft    string
}

func newNFTLock(chroot string, uid int) (*nftLock, error) {
	if uid <= 0 {
		return nil, fmt.Errorf("refusing to lock uid %d: the sidecar itself runs as root", uid)
	}
	l := &nftLock{chroot: chroot, uid: uid, table: "egress_ci_" + strconv.Itoa(uid)}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(filepath.Join(chroot, p)); err == nil {
			l.nft = p
			break
		}
	}
	if l.nft == "" {
		return nil, fmt.Errorf("nft not found under %q", chroot)
	}
	return l, nil
}

func (l *nftLock) run(stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command(l.nft, args...)
	if l.chroot != "" && l.chroot != "/" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: l.chroot}
		cmd.Dir = "/"
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// lockConfig is what the table needs from the sidecar.
type lockConfig struct {
	dnsPort    int    // DNS forwarder
	tPort      int    // transparent proxy
	bridgeIP   string // the sidecar's address on docker0 ("" without Docker): containers' DNS and TCP go there
	enforce    bool
	lockAllCts bool // enforce on every container of the runner, not only the job's (single-job runners)
}

func (l *nftLock) ruleset(c lockConfig) string {
	u := strconv.Itoa(l.uid)
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("table inet %s {", l.table)
	w("  set allow4 { type ipv4_addr; }")
	w("  set ct4 { type ipv4_addr; flags interval; }") // the job's Docker networks, by subnet
	w("  set seen { type ipv4_addr . inet_service; flags dynamic; size 65536; }")
	w("  set seen6 { type ipv6_addr . inet_service; flags dynamic; size 65536; }")
	w("  set seen_ct { type ipv4_addr . ipv4_addr . inet_service; flags dynamic; size 65536; }")
	w("  set seen_fwd { type ipv4_addr . ipv4_addr . inet_service; flags dynamic; size 65536; }")
	// The job's DNS to the forwarder, its TCP (anything not loopback or Docker) to the transparent proxy.
	w("  chain job_nat {")
	w("    type nat hook output priority -110; policy accept;")
	w("    meta nfproto ipv4 ip daddr { 172.16.0.0/12 } accept") // Docker networks: a container's DNS server stays one
	w("    meta nfproto ipv4 ip daddr @ct4 accept")              // the job's own containers stay direct
	w("    meta skuid %s meta l4proto { tcp, udp } th dport 53 redirect to :%d", u, c.dnsPort)
	// The runner's own addresses (a test server on the VM's address) stay local.
	w("    meta skuid %s meta nfproto ipv4 ip daddr != { 127.0.0.0/8, 172.16.0.0/12 } fib daddr type != local meta l4proto tcp redirect to :%d", u, c.tPort)
	w("  }")
	// What is left (UDP, ICMP, IPv6) is recorded, and refused in enforce unless it goes to an allowed name.
	w("  chain job_out {")
	w("    type filter hook output priority 10; policy accept;")
	w("    meta skuid != %s accept", u)
	w("    oifname \"lo\" accept")
	w("    meta nfproto ipv4 ip daddr 127.0.0.0/8 accept")
	w("    ct state established,related accept")
	w("    meta nfproto ipv4 ip daddr 172.16.0.0/12 accept")
	w("    meta nfproto ipv4 ip daddr @ct4 accept")
	w("    meta nfproto ipv4 ct state new meta l4proto { tcp, udp } add @seen { ip daddr . th dport }")
	w("    meta nfproto ipv6 ct state new meta l4proto { tcp, udp } add @seen6 { ip6 daddr . th dport }")
	w("    meta nfproto ipv4 ip daddr @allow4 meta l4proto udp accept")
	if c.enforce {
		w("    meta l4proto tcp counter reject with tcp reset")
		w("    counter reject with icmpx type admin-prohibited")
	}
	w("  }")
	if c.bridgeIP != "" {
		// The job's containers (set ct4: the subnets of the job's Docker networks, in the lock before any container
		// joins them): same treatment as the job.
		w("  chain ct_nat {")
		w("    type nat hook prerouting priority -110; policy accept;")
		w("    ip saddr @ct4 meta l4proto { tcp, udp } th dport 53 dnat ip to %s:%d", c.bridgeIP, c.dnsPort)
		w("    ip saddr @ct4 ip daddr @ct4 accept")
		w("    ip saddr @ct4 ip daddr != 172.16.0.0/12 fib daddr type != local meta l4proto tcp dnat ip to %s:%d", c.bridgeIP, c.tPort)
		w("  }")
		w("  chain ct_fwd {")
		w("    type filter hook forward priority 10; policy accept;")
		w("    ct state established,related accept")
		w("    ip daddr 172.16.0.0/12 accept")
		w("    ip saddr @ct4 ip daddr @ct4 accept")
		w("    ip saddr @ct4 ct state new meta l4proto { tcp, udp } add @seen_ct { ip saddr . ip daddr . th dport }")
		w("    ip saddr @ct4 ip daddr @allow4 meta l4proto udp accept")
		if c.enforce {
			w("    ip saddr @ct4 counter reject with icmpx type admin-prohibited")
		}
		w("    iifname { \"docker0\", \"br-*\" } ct state new meta l4proto { tcp, udp } add @seen_fwd { ip saddr . ip daddr . th dport }")
		if c.enforce && c.lockAllCts {
			w("    iifname { \"docker0\", \"br-*\" } counter reject with icmpx type admin-prohibited")
		}
		w("  }")
	}
	w("}")
	return b.String()
}

func (l *nftLock) remove() error {
	_, err := l.run("", "delete", "table", "inet", l.table)
	if err != nil && strings.Contains(err.Error(), "No such file") {
		return nil
	}
	return err
}

func (l *nftLock) install(c lockConfig) error {
	_ = l.remove() // a table left by a job that never ran its post step
	_, err := l.run(l.ruleset(c), "-f", "-")
	return err
}

// setElems adds or deletes addresses of a set (allow4, ct4).
func (l *nftLock) setElems(op, set string, ips []string) error {
	_, err := l.run(fmt.Sprintf("%s element inet %s %s { %s }\n", op, l.table, set, strings.Join(ips, ", ")), "-f", "-")
	return err
}

// Endpoint is one element of a set: a destination address and port, with the source for container sets.
type Endpoint struct {
	Src  string `json:"src,omitempty"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// dumpSet lists a set of the table: plain addresses or address . port pairs.
func (l *nftLock) dumpSet(name string) ([]Endpoint, error) {
	out, err := l.run("", "-j", "list", "set", "inet", l.table, name)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	var eps []Endpoint
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, err
		}
		for _, e := range set.Elem {
			if ep, ok := parseElem(e); ok {
				eps = append(eps, ep)
			}
		}
	}
	return eps, nil
}

func parseElem(raw json.RawMessage) (Endpoint, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return Endpoint{IP: s}, net.ParseIP(s) != nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return Endpoint{}, false
	}
	if inner, ok := obj["elem"]; ok { // dynamic sets wrap elements: {"elem": {"val": …}}
		var w struct {
			Val json.RawMessage `json:"val"`
		}
		if json.Unmarshal(inner, &w) == nil && w.Val != nil {
			return parseElem(w.Val)
		}
	}
	c, ok := obj["concat"]
	if !ok {
		return Endpoint{}, false
	}
	var parts []json.RawMessage
	if json.Unmarshal(c, &parts) != nil || len(parts) < 2 || len(parts) > 3 {
		return Endpoint{}, false
	}
	var ep Endpoint
	if len(parts) == 3 {
		if json.Unmarshal(parts[0], &ep.Src) != nil {
			return Endpoint{}, false
		}
		parts = parts[1:]
	}
	if json.Unmarshal(parts[0], &ep.IP) != nil {
		return Endpoint{}, false
	}
	if json.Unmarshal(parts[1], &ep.Port) != nil {
		var svc string
		if json.Unmarshal(parts[1], &svc) != nil {
			return Endpoint{}, false
		}
		p, err := net.LookupPort("tcp", svc)
		if err != nil {
			return Endpoint{}, false
		}
		ep.Port = p
	}
	return ep, true
}
