package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// transparent takes every TCP connection of the job's user and of its containers that did not go through
// HTTPS_PROXY (nftables redirects them here: the runner itself, tools that ignore the proxy variables, containers).
// It names the connection from its TLS SNI or HTTP Host, checks that name against the policy and that the
// original address is one the name resolves to (an allowed SNI sent to another address is fronting), then
// connects to the original address. A connection without a name passes only to an address an allowed name
// resolved to.
type transparent struct {
	p   *proxy
	dns *dnsServer
	ct  *containerTracker
}

func (t *transparent) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go t.handle(c)
	}
}

func (t *transparent) handle(c net.Conn) {
	defer c.Close()
	start := time.Now()
	dst, err := originalDst(c)
	client := hostOf(c.RemoteAddr())
	ev := Event{Kind: "direct", Client: client, Container: t.ct.name(client)}
	defer func() {
		ev.DurMS = time.Since(start).Milliseconds()
		t.p.log.add(ev)
	}()
	if err != nil {
		ev.Decision, ev.Reason, ev.Note = "block", "no_original_destination", err.Error()
		return
	}
	ip := dst.IP.String()
	ev.Port = dst.Port
	br := bufio.NewReaderSize(c, 16<<10)
	name, peeked := t.peekName(c, br, dst.Port)
	ev.SNI = name
	known := t.dns.namesFor(ip)
	host := name
	if host == "" && len(known) > 0 {
		host = known[0]
	}
	if host == "" {
		host = ip
	}
	ev.Host = host
	ev.Detections = scanName(host)
	if len(peeked) > 0 && !bytes.HasPrefix(peeked, []byte{0x16}) {
		ev.Detections = dedupe(append(ev.Detections, scanText(host, string(peeked))...))
	}
	ev.Decision, ev.Reason = t.decide(name, known, ip, dst.Port)
	if ev.Decision == "allow" && len(ev.Detections) > 0 && hasDLP(ev.Detections) {
		ev.Decision, ev.Reason = "audit", "dlp"
		if t.p.enforce {
			ev.Decision = "block"
		}
	}
	if ev.Decision == "block" {
		return // the client sees a reset; the job summary says why
	}
	up, err := t.p.dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, strconv.Itoa(dst.Port)))
	if err != nil {
		ev.Note = "dial: " + err.Error()
		if errors.Is(err, errPrivateDestination) {
			ev.Decision, ev.Reason = "block", "private_destination"
		}
		return
	}
	defer up.Close()
	ev.Up, ev.Down = pipe(c, br, up)
}

func hasDLP(dets []string) bool {
	for _, d := range dets {
		if strings.HasPrefix(d, "dlp.") {
			return true
		}
	}
	return false
}

// decide: a named connection needs an allowed name whose DNS answers include the address; an unnamed one needs an
// address some allowed name resolved to.
func (t *transparent) decide(name string, known []string, ip string, port int) (string, string) {
	verdict := func(ok bool, reason string) (string, string) {
		switch {
		case ok:
			return "allow", ""
		case t.p.enforce:
			return "block", reason
		}
		return "audit", reason
	}
	if name != "" {
		if !t.p.pol.Allowed(name, port) {
			return verdict(false, "not_allowed")
		}
		if contains(known, normHost(name)) || t.resolvesTo(name, ip) {
			return verdict(true, "")
		}
		return verdict(false, "name_ip_mismatch")
	}
	for _, n := range known {
		if t.p.pol.Allowed(n, port) {
			return verdict(true, "")
		}
	}
	return verdict(false, "not_allowed")
}

// resolvesTo checks a name the job did not resolve through the forwarder (cached answers, hard-coded hosts).
func (t *transparent) resolvesTo(name, ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		return false
	}
	t.dns.remember(normHost(name), addrs)
	return contains(addrs, ip)
}

// peekName reads, without consuming, the TLS ClientHello's SNI or an HTTP request's Host. Protocols where the server
// speaks first get a short wait and stay unnamed.
func (t *transparent) peekName(c net.Conn, br *bufio.Reader, port int) (string, []byte) {
	wait := 300 * time.Millisecond
	if port == 443 || port == 80 || port == 8080 || port == 8443 {
		wait = 5 * time.Second
	}
	_ = c.SetReadDeadline(time.Now().Add(wait))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	hdr, err := br.Peek(5)
	if err != nil {
		return "", nil
	}
	if hdr[0] == 0x16 { // TLS handshake record
		n := 5 + (int(hdr[3])<<8 | int(hdr[4]))
		if n > br.Size() {
			n = br.Size()
		}
		rec, _ := br.Peek(n)
		if len(rec) > 5 {
			return normHost(parseSNI(rec[5:])), rec
		}
		return "", rec
	}
	if isHTTPMethodPrefix(hdr) {
		buf, _ := br.Peek(min(br.Buffered(), br.Size()))
		for !bytes.Contains(buf, []byte("\r\n\r\n")) && len(buf) < br.Size() {
			if _, err := br.Peek(len(buf) + 1); err != nil {
				break
			}
			buf, _ = br.Peek(br.Buffered())
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
		if err != nil {
			return "", buf
		}
		h, _ := splitHostPortDefault(req.Host, port)
		return h, buf
	}
	return "", nil
}

func isHTTPMethodPrefix(b []byte) bool {
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS "} {
		k := min(len(m), len(b))
		if string(b[:k]) == m[:k] {
			return true
		}
	}
	return false
}
