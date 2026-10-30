package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const maxScanBody = 4 << 20 // request bodies up to 4 MiB are scanned whole; larger ones pass unscanned (noted)

type proxy struct {
	pol     *Policy
	enforce bool
	log     *eventLog
	ca      *mitmCA // nil when nothing is inspected
	tlsPort int     // CONNECT port whose first bytes are read as a ClientHello (SNI check, inspection)
	dialer  *net.Dialer
	tr      *http.Transport
}

func newProxy(pol *Policy, enforce bool, log *eventLog, ca *mitmCA) *proxy {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: guardDial}
	return &proxy{
		pol: pol, enforce: enforce, log: log, ca: ca, dialer: d, tlsPort: 443,
		tr: &http.Transport{
			DialContext:           d.DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 10 * time.Minute,
		},
	}
}

// guardDial refuses loopback, link-local (cloud metadata) and unspecified destinations after resolution: the proxy
// runs in the runner's network namespace and must not become a way into the runner itself.
func guardDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return errPrivateDestination
	}
	return nil
}

var errPrivateDestination = errors.New("destination not allowed: loopback or link-local")

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.IsAbs() && r.URL.Scheme == "http" {
		p.plainHTTP(w, r)
		return
	}
	http.Error(w, "OpenWAF Egress CI proxy", http.StatusBadRequest)
}

// decide applies the policy: allow, audit (logged, passes) or block.
func (p *proxy) decide(host string, port int) (decision, reason string) {
	if p.pol.Allowed(host, port) {
		return "allow", ""
	}
	if p.enforce {
		return "block", "not_allowed"
	}
	return "audit", "not_allowed"
}

func splitHostPortDefault(hp string, def int) (string, int) {
	h, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return normHost(strings.Trim(hp, "[]")), def
	}
	n, err := strconv.Atoi(ps)
	if err != nil {
		return normHost(h), def
	}
	return normHost(h), n
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host, port := splitHostPortDefault(r.Host, 443)
	ev := Event{Kind: "connect", Client: clientIP(r), Host: host, Port: port, Detections: scanName(host)}
	ev.Decision, ev.Reason = p.decide(host, port)
	defer func() {
		ev.DurMS = time.Since(start).Milliseconds()
		p.log.add(ev)
	}()
	if ev.Decision == "block" {
		w.Header().Set("X-OpenWAF-Egress", "blocked")
		http.Error(w, "blocked by OpenWAF Egress CI policy: "+host+" is not in .github/egress.yml", http.StatusForbidden)
		return
	}
	upstream, err := p.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		ev.Note = "dial: " + err.Error()
		if errors.Is(err, errPrivateDestination) {
			ev.Decision, ev.Reason = "block", "private_destination"
			http.Error(w, "blocked by OpenWAF Egress CI: loopback or link-local destination", http.StatusForbidden)
			return
		}
		http.Error(w, "OpenWAF Egress CI: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	var cr io.Reader = brw.Reader
	if port == p.tlsPort {
		_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
		hello, sni, perr := peekClientHello(brw.Reader)
		_ = client.SetReadDeadline(time.Time{})
		if perr == nil {
			ev.SNI = sni
			if sni != "" && normHost(sni) != host {
				d, _ := p.decide(sni, port)
				if d != "allow" {
					ev.Detections = append(ev.Detections, "tls.sni_mismatch")
					if p.enforce {
						ev.Decision, ev.Reason = "block", "sni_mismatch"
						return
					}
					if ev.Decision == "allow" {
						ev.Decision, ev.Reason = "audit", "sni_mismatch"
					}
				}
			}
			if p.ca != nil && p.pol.Inspected(host) {
				ev.Inspected = true
				p.inspect(&ev, &prefixConn{Conn: client, r: io.MultiReader(strings.NewReader(string(hello)), brw.Reader)}, upstream, host, port)
				return
			}
		}
		cr = io.MultiReader(strings.NewReader(string(hello)), brw.Reader)
	}
	up, down := pipe(client, cr, upstream)
	ev.Up, ev.Down = up, down
}

// pipe copies both directions until either side closes and returns the bytes sent up and down.
func pipe(client net.Conn, cr io.Reader, upstream net.Conn) (int64, int64) {
	var up, down atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, cr)
		up.Store(n)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, upstream)
		down.Store(n)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	return up.Load(), down.Load()
}

// peekClientHello reads the first TLS record and returns its bytes and the SNI. It does not consume beyond it.
func peekClientHello(r *bufio.Reader) ([]byte, string, error) {
	hdr, err := r.Peek(5)
	if err != nil {
		return nil, "", err
	}
	if hdr[0] != 0x16 {
		return nil, "", errors.New("not TLS")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec := make([]byte, 5+n)
	if _, err := io.ReadFull(r, rec); err != nil {
		return rec, "", err
	}
	return rec, parseSNI(rec[5:]), nil
}

func parseSNI(h []byte) string {
	// handshake: type(1) len(3) version(2) random(32) session_id cipher_suites compression extensions
	if len(h) < 38 || h[0] != 1 {
		return ""
	}
	off := 38
	if off >= len(h) {
		return ""
	}
	off += 1 + int(h[off])
	if off+2 > len(h) {
		return ""
	}
	off += 2 + int(binary.BigEndian.Uint16(h[off:]))
	if off >= len(h) {
		return ""
	}
	off += 1 + int(h[off])
	if off+2 > len(h) {
		return ""
	}
	end := off + 2 + int(binary.BigEndian.Uint16(h[off:]))
	off += 2
	if end > len(h) {
		end = len(h)
	}
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(h[off:])
		l := int(binary.BigEndian.Uint16(h[off+2:]))
		off += 4
		if off+l > end {
			return ""
		}
		if typ == 0 && l >= 5 { // server_name: list len(2) type(1) name len(2) name
			e := h[off : off+l]
			nl := int(binary.BigEndian.Uint16(e[3:5]))
			if e[2] == 0 && 5+nl <= len(e) {
				return string(e[5 : 5+nl])
			}
			return ""
		}
		off += l
	}
	return ""
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// inspect terminates the client's TLS with a per-run CA, scans each HTTP/1.1 request and forwards it over a new TLS
// connection to the real host. Only for hosts listed under inspect: everything else stays an opaque tunnel.
func (p *proxy) inspect(ev *Event, client net.Conn, upstream net.Conn, host string, port int) {
	upstream.Close() // requests go through the transport (verified TLS to the real host)
	tconn := tls.Server(client, &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hi.ServerName
			if name == "" {
				name = host
			}
			return p.ca.leaf(name)
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tconn.Handshake(); err != nil {
		ev.Note = "inspect handshake: " + err.Error()
		return
	}
	defer tconn.Close()
	br := bufio.NewReader(tconn)
	cw := &countWriter{w: tconn}
	for {
		_ = tconn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			break
		}
		_ = tconn.SetReadDeadline(time.Time{})
		req.URL.Scheme, req.URL.Host = "https", net.JoinHostPort(host, strconv.Itoa(port))
		if port == 443 {
			req.URL.Host = host
		}
		dets, body, scanned := scanRequest(req, host)
		ev.Up += req.ContentLength
		if !scanned {
			ev.Note = "body larger than 4 MiB or binary: not scanned"
		}
		if len(dets) > 0 {
			ev.Detections = dedupe(append(ev.Detections, dets...))
			if p.enforce {
				ev.Decision, ev.Reason = "block", "dlp"
				resp := &http.Response{StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"X-Openwaf-Egress": {"dlp"}, "Connection": {"close"}}, Body: io.NopCloser(strings.NewReader("blocked by OpenWAF Egress CI: sensitive data in request\n")), ContentLength: 56}
				_ = resp.Write(cw)
				break
			}
			if ev.Decision == "allow" {
				ev.Decision, ev.Reason = "audit", "dlp"
			}
		}
		req.Body = body
		req.RequestURI = ""
		removeHopHeaders(req.Header)
		resp, err := p.tr.RoundTrip(req.WithContext(context.Background()))
		if err != nil {
			ev.Note = "inspect upstream: " + err.Error()
			bad := &http.Response{StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": {"close"}}, Body: http.NoBody}
			_ = bad.Write(cw)
			break
		}
		removeHopHeaders(resp.Header)
		err = resp.Write(cw)
		resp.Body.Close()
		if err != nil || req.Close || resp.Close {
			break
		}
	}
	ev.Down = cw.n
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Upgrade"}

func removeHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// scanRequest scans the URL, the headers and a textual body. It returns the detections and a body to forward.
func scanRequest(req *http.Request, host string) ([]string, io.ReadCloser, bool) {
	var sb strings.Builder
	sb.WriteString(req.URL.RequestURI())
	for k, vs := range req.Header {
		for _, v := range vs {
			sb.WriteString("\n" + k + ": " + v)
		}
	}
	body := req.Body
	scanned := true
	if req.Body != nil && req.Body != http.NoBody {
		ct := strings.ToLower(req.Header.Get("Content-Type"))
		binary := strings.Contains(ct, "octet-stream") || strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.Contains(ct, "zip") || strings.Contains(ct, "gzip") || strings.Contains(ct, "tar")
		if binary || req.ContentLength > maxScanBody {
			scanned = false
		} else {
			buf, err := io.ReadAll(io.LimitReader(req.Body, maxScanBody+1))
			rest := req.Body
			if err == nil && len(buf) <= maxScanBody {
				sb.WriteString("\n")
				sb.Write(buf)
				body = io.NopCloser(strings.NewReader(string(buf)))
			} else {
				scanned = false
				body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(strings.NewReader(string(buf)), rest), rest}
			}
		}
	}
	return scanText(host, sb.String()), body, scanned
}

func (p *proxy) plainHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host, port := splitHostPortDefault(r.URL.Host, 80)
	ev := Event{Kind: "http", Client: clientIP(r), Host: host, Port: port, Method: r.Method, Detections: scanName(host)}
	ev.Decision, ev.Reason = p.decide(host, port)
	defer func() {
		ev.DurMS = time.Since(start).Milliseconds()
		p.log.add(ev)
	}()
	if ev.Decision == "block" {
		w.Header().Set("X-OpenWAF-Egress", "blocked")
		http.Error(w, "blocked by OpenWAF Egress CI policy: "+host+" is not in .github/egress.yml", http.StatusForbidden)
		return
	}
	dets, body, scanned := scanRequest(r, host)
	if !scanned {
		ev.Note = "body larger than 4 MiB or binary: not scanned"
	}
	if len(dets) > 0 {
		ev.Detections = dedupe(append(ev.Detections, dets...))
		if p.enforce {
			ev.Decision, ev.Reason = "block", "dlp"
			http.Error(w, "blocked by OpenWAF Egress CI: sensitive data in request", http.StatusForbidden)
			return
		}
		if ev.Decision == "allow" {
			ev.Decision, ev.Reason = "audit", "dlp"
		}
	}
	out := r.Clone(r.Context())
	out.Body = body
	out.RequestURI = ""
	removeHopHeaders(out.Header)
	resp, err := p.tr.RoundTrip(out)
	if err != nil {
		ev.Note = "upstream: " + err.Error()
		if errors.Is(err, errPrivateDestination) {
			ev.Decision, ev.Reason = "block", "private_destination"
		}
		http.Error(w, "OpenWAF Egress CI: upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	ev.Up, ev.Down = max(r.ContentLength, 0), n
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
