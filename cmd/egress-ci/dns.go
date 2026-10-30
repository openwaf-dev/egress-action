package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dnsServer answers the job's DNS and its containers' (both redirected by nftables): it logs every name with who
// asked, remembers which names each address answered for (the transparent proxy checks a connection's name against
// its address), adds the addresses of allowed names to the lock's allow set, and in enforce answers NXDOMAIN for
// names outside the allowlist.
type dnsServer struct {
	pol       *Policy
	enforce   bool
	log       *eventLog
	upstreams []string
	lock      *nftLock          // nil without the lock
	ct        *containerTracker // nil without Docker tracking

	mu      sync.Mutex
	allowed map[string]bool     // IPv4 addresses already in the lock's allow set
	names   map[string][]string // address -> names whose answers contained it
}

// namesFor returns the names the job or its containers resolved to ip.
func (d *dnsServer) namesFor(ip string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.names[ip]...)
}

func (d *dnsServer) remember(name string, ips []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.names == nil {
		d.names = map[string][]string{}
	}
	for _, ip := range ips {
		d.names[ip] = appendUnique(d.names[ip], name)
	}
}

func resolvConfUpstreams(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"1.1.1.1:53"}
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, net.JoinHostPort(fields[1], "53"))
		}
	}
	if len(out) == 0 {
		out = []string{"1.1.1.1:53"}
	}
	return out
}

func (d *dnsServer) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := d.handle(q, false, hostOf(addr)); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}

func (d *dnsServer) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			for {
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := d.handle(q, true, hostOf(c.RemoteAddr()))
				if resp == nil {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func (d *dnsServer) handle(q []byte, tcp bool, client string) []byte {
	name, qtype, qend, err := parseQuestion(q)
	if err != nil {
		resp, _ := d.exchange(q, tcp)
		return resp
	}
	ev := Event{Kind: "dns", Client: client, Container: d.ct.name(client), Host: name, QType: qtypeName(qtype), Detections: scanName(name)}
	allowed := d.pol.AllowedName(name)
	switch {
	case allowed:
		ev.Decision = "allow"
	case d.enforce:
		ev.Decision, ev.Reason = "block", "not_allowed"
		d.log.add(ev)
		return nxdomain(q, qend)
	default:
		ev.Decision, ev.Reason = "audit", "not_allowed"
	}
	resp, err := d.exchange(q, tcp)
	if err != nil {
		ev.Note = "upstream: " + err.Error()
		d.log.add(ev)
		return nil
	}
	v4, others := parseAnswers(resp)
	ev.Answers = append(v4, others...)
	d.remember(name, v4)
	if allowed && d.lock != nil && len(v4) > 0 {
		d.allowIPs(v4)
	}
	d.log.add(ev)
	return resp
}

func (d *dnsServer) allowIPs(ips []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var add []string
	for _, ip := range ips {
		if !d.allowed[ip] {
			add = append(add, ip)
		}
	}
	if len(add) == 0 {
		return
	}
	if err := d.lock.setElems("add", "allow4", add); err != nil {
		d.log.add(Event{Kind: "lock", Decision: "allow", Note: "nft add element: " + err.Error()})
		return
	}
	for _, ip := range add {
		d.allowed[ip] = true
	}
}

func (d *dnsServer) exchange(q []byte, tcp bool) ([]byte, error) {
	var last error
	for _, up := range d.upstreams {
		resp, err := exchangeWith(up, q, tcp)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func exchangeWith(up string, q []byte, tcp bool) ([]byte, error) {
	if !tcp {
		c, err := net.DialTimeout("udp", up, 3*time.Second)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := c.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	c, err := net.DialTimeout("tcp", up, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	out := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(out, uint16(len(q)))
	copy(out[2:], q)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(c, resp)
	return resp, err
}

// readName decodes a possibly compressed name at off and returns it with the offset just past it.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errors.New("name past end")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("pointer past end")
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 32 {
				return "", 0, errors.New("pointer loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("label past end")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func parseQuestion(msg []byte) (name string, qtype uint16, end int, err error) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:]) < 1 {
		return "", 0, 0, errors.New("no question")
	}
	name, off, err := readName(msg, 12)
	if err != nil {
		return "", 0, 0, err
	}
	if off+4 > len(msg) {
		return "", 0, 0, errors.New("short question")
	}
	return name, binary.BigEndian.Uint16(msg[off:]), off + 4, nil
}

// parseAnswers returns the A addresses and the other answer data (AAAA, CNAME targets) of a response.
func parseAnswers(msg []byte) (v4, others []string) {
	if len(msg) < 12 {
		return nil, nil
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for range qd {
		_, o, err := readName(msg, off)
		if err != nil {
			return
		}
		off = o + 4
	}
	for range an {
		_, o, err := readName(msg, off)
		if err != nil || o+10 > len(msg) {
			return
		}
		typ := binary.BigEndian.Uint16(msg[o:])
		rdlen := int(binary.BigEndian.Uint16(msg[o+8:]))
		rd := o + 10
		if rd+rdlen > len(msg) {
			return
		}
		switch {
		case typ == 1 && rdlen == 4:
			v4 = append(v4, net.IP(msg[rd:rd+4]).String())
		case typ == 28 && rdlen == 16:
			others = append(others, net.IP(msg[rd:rd+16]).String())
		case typ == 5:
			if cname, _, err := readName(msg, rd); err == nil {
				others = append(others, "cname:"+cname)
			}
		}
		off = rd + rdlen
	}
	return
}

// nxdomain answers a query with NXDOMAIN, echoing only its question.
func nxdomain(q []byte, qend int) []byte {
	resp := append([]byte(nil), q[:qend]...)
	flags := binary.BigEndian.Uint16(q[2:])
	flags = 0x8000 | (flags & 0x7900) | 0x0080 | 3 // QR, opcode+RD kept, RA, RCODE=3
	binary.BigEndian.PutUint16(resp[2:], flags)
	binary.BigEndian.PutUint16(resp[4:], 1)
	for i := 6; i < 12; i++ {
		resp[i] = 0
	}
	return resp
}

func qtypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	}
	return strconv.Itoa(int(t))
}
