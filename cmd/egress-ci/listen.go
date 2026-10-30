package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// listenerSet: on every host, the proxy on port, the DNS forwarder (UDP and TCP) on port+1 and the transparent proxy
// on port+2. The job reaches them on 127.0.0.1, its containers on the Docker bridge address.
type listenerSet struct {
	port        int
	proxy       []net.Listener
	udp         []net.PacketConn
	tcpDNS      []net.Listener
	transparent []net.Listener
}

func (l *listenerSet) close() {
	for _, c := range l.udp {
		c.Close()
	}
	for _, group := range [][]net.Listener{l.proxy, l.tcpDNS, l.transparent} {
		for _, c := range group {
			c.Close()
		}
	}
}

// bindListeners binds the triple at base, moving to the next triple when a port is taken (up to 32 tries). base 0
// lets the kernel choose the proxy port (tests, local runs).
func bindListeners(hosts []string, base int) (*listenerSet, error) {
	var hs []string
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			hs = append(hs, h)
		}
	}
	if len(hs) == 0 {
		return nil, errors.New("no listen host")
	}
	var last error
	for i := range 32 {
		p := 0
		if base != 0 {
			p = base + 3*i
		}
		if p+2 > 65535 {
			break
		}
		set, err := bindTriple(hs, p)
		if err == nil {
			return set, nil
		}
		last = err
	}
	return nil, fmt.Errorf("no free port triple from %d: %w", base, last)
}

func bindTriple(hosts []string, port int) (*listenerSet, error) {
	set := &listenerSet{}
	fail := func(err error) (*listenerSet, error) {
		set.close()
		return nil, err
	}
	for _, h := range hosts {
		ln, err := net.Listen("tcp4", net.JoinHostPort(h, strconv.Itoa(port)))
		if err != nil {
			return fail(err)
		}
		if port == 0 {
			port = ln.Addr().(*net.TCPAddr).Port
		}
		set.proxy = append(set.proxy, ln)
	}
	set.port = port
	for _, h := range hosts {
		u, err := net.ListenPacket("udp4", net.JoinHostPort(h, strconv.Itoa(port+1)))
		if err != nil {
			return fail(err)
		}
		set.udp = append(set.udp, u)
		t, err := net.Listen("tcp4", net.JoinHostPort(h, strconv.Itoa(port+1)))
		if err != nil {
			return fail(err)
		}
		set.tcpDNS = append(set.tcpDNS, t)
		tp, err := net.Listen("tcp4", net.JoinHostPort(h, strconv.Itoa(port+2)))
		if err != nil {
			return fail(err)
		}
		set.transparent = append(set.transparent, tp)
	}
	return set, nil
}
