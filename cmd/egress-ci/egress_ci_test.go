package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustPolicy(t *testing.T, yml string) *Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyMatching(t *testing.T) {
	p := mustPolicy(t, `
version: 1
presets: [github-actions]
allow:
  - proxy.golang.org
  - "*.npmjs.org"
  - registry.example.com:5000
  - any.example.net:*
`)
	if p.Mode != "audit" {
		t.Fatalf("default mode %q, want audit", p.Mode)
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"proxy.golang.org", 443, true},
		{"PROXY.golang.org.", 80, true},                               // case and trailing dot
		{"proxy.golang.org", 8443, false},                             // default ports are 80 and 443 only
		{"registry.npmjs.org", 443, true},                             // wildcard
		{"npmjs.org", 443, false},                                     // a wildcard never matches the apex
		{"evilnpmjs.org", 443, false},                                 // nor a suffix that is not a label boundary
		{"registry.example.com", 5000, true},                          // explicit port
		{"registry.example.com", 443, false},                          // explicit port replaces the defaults
		{"any.example.net", 22, true},                                 // any port
		{"results-receiver.actions.githubusercontent.com", 443, true}, // preset
		{"example.org", 443, false},
	}
	for _, c := range cases {
		if got := p.Allowed(c.host, c.port); got != c.want {
			t.Errorf("Allowed(%q, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
	if !p.AllowedName("registry.example.com") || p.AllowedName("npmjs.org") {
		t.Error("AllowedName ignores ports but keeps wildcard rules")
	}
}

func TestPolicyRejectsInvalid(t *testing.T) {
	for name, yml := range map[string]string{
		"mode":          "mode: block\n",
		"unknown field": "allow: [a.com]\nallowed: [b.com]\n",
		"preset":        "presets: [everything]\n",
		"url":           "allow: [https://a.com/x]\n",
		"port":          "allow: [a.com:99999]\n",
		"inner star":    "allow: [a.*.com]\n",
	} {
		path := filepath.Join(t.TempDir(), "egress.yml")
		_ = os.WriteFile(path, []byte(yml), 0o644)
		if _, err := loadPolicy(path); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
}

func TestParseSNIFromRealClientHello(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		_ = tls.Client(c1, &tls.Config{ServerName: "registry.npmjs.org", InsecureSkipVerify: true}).Handshake()
	}()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	rec, sni, err := peekClientHello(bufio.NewReader(c2))
	c2.Close()
	c1.Close()
	if err != nil {
		t.Fatal(err)
	}
	if sni != "registry.npmjs.org" {
		t.Fatalf("sni %q", sni)
	}
	if rec[0] != 0x16 {
		t.Fatal("record not returned whole")
	}
}

// A query for example.com (A), as a stub resolver sends it.
func dnsQuery(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func TestDNSParseAndNXDOMAIN(t *testing.T) {
	q := dnsQuery("Exfil.Example.com")
	name, qtype, end, err := parseQuestion(q)
	if err != nil || name != "exfil.example.com" || qtype != 1 || end != len(q) {
		t.Fatalf("parseQuestion = %q %d %d %v", name, qtype, end, err)
	}
	r := nxdomain(q, end)
	if r[0] != 0x12 || r[1] != 0x34 || r[2]&0x80 == 0 || r[3]&0x0f != 3 || r[2]&0x01 == 0 {
		t.Fatalf("nxdomain header % x: want same id, QR, RD kept, RCODE 3", r[:4])
	}
	// A response: question, then a compressed CNAME and an A record.
	resp := append([]byte(nil), q...)
	resp[2], resp[3], resp[7] = 0x81, 0x80, 2
	resp = append(resp, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, 'w', 'w', 'w', 0xc0, 12)
	resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14)
	v4, others := parseAnswers(resp)
	if len(v4) != 1 || v4[0] != "93.184.215.14" || len(others) != 1 || others[0] != "cname:www.exfil.example.com" {
		t.Fatalf("parseAnswers = %v %v", v4, others)
	}
	// A pointer loop must not hang.
	loop := append(append([]byte(nil), q[:12]...), 0xc0, 12, 0, 1, 0, 1)
	if _, _, _, err := parseQuestion(loop); err == nil {
		t.Fatal("pointer loop accepted")
	}
}

func TestDetections(t *testing.T) {
	if d := scanName("aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3JldC1wYXlsb2Fk.attacker.example"); len(d) != 1 || d[0] != "dns.high_entropy_label" {
		t.Fatalf("encoded label: %v", d)
	}
	if d := scanName("proxy.golang.org"); d != nil {
		t.Fatalf("plain name flagged: %v", d)
	}
	tok := "ghp_" + strings.Repeat("a1B2", 9)
	if d := scanText("api.github.com", "Authorization: token "+tok); d != nil {
		t.Fatalf("GitHub token to GitHub flagged: %v", d)
	}
	if d := scanText("paste.example.com", "x="+tok); len(d) != 1 || d[0] != "dlp.github_token" {
		t.Fatalf("GitHub token elsewhere: %v", d)
	}
	if d := scanText("x.example.com", "AKIAIOSFODNN7EXAMPLE"); len(d) != 1 || d[0] != "dlp.aws_access_key" {
		t.Fatalf("AWS key: %v", d)
	}
}

func TestParseNFTElements(t *testing.T) {
	doc := `{"nftables":[{"metainfo":{}},{"set":{"name":"seen","elem":[
	  {"concat":["104.18.24.232",443]},
	  {"elem":{"val":{"concat":["1.1.1.1","https"]},"expires":10}},
	  {"concat":["172.17.0.5","140.82.112.3",53]},
	  "93.184.215.14"]}}]}`
	var parsed struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatal(err)
	}
	var set struct {
		Elem []json.RawMessage `json:"elem"`
	}
	_ = json.Unmarshal(parsed.Nftables[1]["set"], &set)
	var got []Endpoint
	for _, e := range set.Elem {
		if ep, ok := parseElem(e); ok {
			got = append(got, ep)
		}
	}
	want := []Endpoint{{IP: "104.18.24.232", Port: 443}, {IP: "1.1.1.1", Port: 443}, {Src: "172.17.0.5", IP: "140.82.112.3", Port: 53}, {IP: "93.184.215.14"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func newTestProxy(t *testing.T, yml string, enforce bool) (*proxy, string, string) {
	t.Helper()
	dir := t.TempDir()
	log, err := openEventLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.close() })
	p := newProxy(mustPolicy(t, yml), enforce, log, nil)
	p.dialer.Control = nil // tests talk to loopback servers
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return p, srv.URL, filepath.Join(dir, "events.jsonl")
}

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	b, _ := os.ReadFile(path)
	var out []Event
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestProxyAuditPassesEnforceBlocks(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("ok:" + string(body)))
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	target := "http://127.0.0.1:" + port + "/up"

	for _, mode := range []string{"audit", "enforce"} {
		_, purl, events := newTestProxy(t, "allow: [allowed.example]\n", mode == "enforce")
		u, _ := url.Parse(purl)
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
		resp, err := c.Post(target, "text/plain", strings.NewReader("key AKIAIOSFODNN7EXAMPLE"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		evs := readEvents(t, events)
		if len(evs) != 1 {
			t.Fatalf("%s: %d events", mode, len(evs))
		}
		e := evs[0]
		switch mode {
		case "audit":
			if resp.StatusCode != 200 || e.Decision != "audit" || e.Reason != "not_allowed" || !contains(e.Detections, "dlp.aws_access_key") {
				t.Fatalf("audit: status %d event %+v", resp.StatusCode, e)
			}
		case "enforce":
			if resp.StatusCode != 403 || e.Decision != "block" || e.Reason != "not_allowed" {
				t.Fatalf("enforce: status %d event %+v", resp.StatusCode, e)
			}
		}
	}
}

func TestProxyEnforceBlocksDLPToAllowedHost(t *testing.T) {
	hits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	_, purl, events := newTestProxy(t, "allow: [\"127.0.0.1:"+port+"\"]\n", true)
	u, _ := url.Parse(purl)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := c.Post("http://127.0.0.1:"+port+"/", "text/plain", strings.NewReader("-----BEGIN OPENSSH PRIVATE KEY-----"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	e := readEvents(t, events)[0]
	if resp.StatusCode != 403 || hits != 0 || e.Reason != "dlp" || !contains(e.Detections, "dlp.private_key") {
		t.Fatalf("status %d hits %d event %+v", resp.StatusCode, hits, e)
	}
}

// A CONNECT to an allowed address whose ClientHello names another host (domain fronting, or a tool that tunnels to
// an allowed IP) is cut in enforce; a matching handshake goes through the tunnel untouched.
func TestConnectSNIMismatch(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	for _, sni := range []string{"localhost", "exfil.example"} {
		p, purl, events := newTestProxy(t, "mode: enforce\nallow: [\"localhost:*\"]\n", true)
		fmt.Sscan(port, &p.tlsPort)
		conn, err := net.Dial("tcp", strings.TrimPrefix(purl, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("CONNECT localhost:" + port + " HTTP/1.1\r\nHost: localhost:" + port + "\r\n\r\n"))
		br := bufio.NewReader(conn)
		if line, _ := br.ReadString('\n'); !strings.Contains(line, " 200 ") {
			t.Fatalf("CONNECT: %q", line)
		}
		_, _ = br.ReadString('\n') // blank line after the status
		tc := tls.Client(&prefixConn{Conn: conn, r: br}, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		herr := tc.Handshake()
		conn.Close()
		time.Sleep(50 * time.Millisecond)
		evs := readEvents(t, events)
		if len(evs) != 1 {
			t.Fatalf("%s: events %+v", sni, evs)
		}
		e := evs[0]
		if sni == "localhost" && (herr != nil || e.Decision != "allow" || e.SNI != "localhost") {
			t.Fatalf("matching SNI: handshake %v, event %+v", herr, e)
		}
		if sni == "exfil.example" && (herr == nil || e.Decision != "block" || e.Reason != "sni_mismatch") {
			t.Fatalf("mismatched SNI: handshake %v, event %+v", herr, e)
		}
	}
}

// The GitHub preset opens GitHub's storage accounts by exact name, never the rest of Azure Blob.
func TestGitHubPresetBlobAccountsAreExact(t *testing.T) {
	p := mustPolicy(t, "presets: [github-actions]\n")
	if !p.Allowed("productionresultssa5.blob.core.windows.net", 443) {
		t.Fatal("a GitHub results storage account is refused")
	}
	for _, h := range []string{"attacker.blob.core.windows.net", "productionresultssa5x.blob.core.windows.net", "blob.core.windows.net"} {
		if p.Allowed(h, 443) {
			t.Errorf("%s allowed by the GitHub preset", h)
		}
	}
}

func TestTransparentDecisions(t *testing.T) {
	pol := mustPolicy(t, "allow: [proxy.golang.org]\n")
	for _, enforce := range []bool{false, true} {
		log, _ := openEventLog(filepath.Join(t.TempDir(), "e.jsonl"))
		defer log.close()
		ds := &dnsServer{pol: pol}
		ds.remember("proxy.golang.org", []string{"142.250.0.1"})
		ds.remember("evil.example", []string{"198.51.100.7"})
		tp := &transparent{p: newProxy(pol, enforce, log, nil), dns: ds}
		refuse := "audit"
		if enforce {
			refuse = "block"
		}
		for _, c := range []struct{ name, ip, want, reason string }{
			{"proxy.golang.org", "142.250.0.1", "allow", ""},
			{"", "142.250.0.1", "allow", ""},                                 // no SNI: an address an allowed name resolved to
			{"proxy.golang.org", "198.51.100.7", refuse, "name_ip_mismatch"}, // allowed SNI sent elsewhere (fronting)
			{"evil.example", "198.51.100.7", refuse, "not_allowed"},          // named, outside the policy
			{"", "198.51.100.7", refuse, "not_allowed"},                      // unnamed, only a name outside the policy
		} {
			got, reason := tp.decide(c.name, ds.namesFor(c.ip), c.ip, 443)
			if got != c.want || reason != c.reason {
				t.Errorf("enforce=%v decide(%q, %s) = %s %s, want %s %s", enforce, c.name, c.ip, got, reason, c.want, c.reason)
			}
		}
	}
}

func TestRegistryOf(t *testing.T) {
	for ref, want := range map[string]string{
		"alpine:3":                      "registry-1.docker.io",
		"docker.io/library/alpine":      "registry-1.docker.io",
		"index.docker.io/moby/buildkit": "registry-1.docker.io",
		"user/repo:tag":                 "registry-1.docker.io",
		"ghcr.io/openwaf-dev/egress":    "ghcr.io",
		"registry.example.com:5000/a/b": "registry.example.com",
		"localhost/img":                 "localhost",
	} {
		if got := registryOf(ref); got != want {
			t.Errorf("registryOf(%q) = %q, want %q", ref, got, want)
		}
	}
}

// Containers the job creates carry its label, the rest of the request untouched; in enforce a pull from a registry
// outside the policy never reaches the daemon.
func TestDockerSocketLabelsAndPullPolicy(t *testing.T) {
	var got map[string]any
	calls := 0
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer daemon.Close()
	log, _ := openEventLog(filepath.Join(t.TempDir(), "e.jsonl"))
	defer log.close()
	d := newDockerProxy("/nonexistent.sock", 1001, map[string]string{jobLabel: "1001"}, mustPolicy(t, "allow: []\n"), true, log, newContainerTracker(nil, log))
	u, _ := url.Parse(daemon.URL)
	d.rp.Transport = http.DefaultTransport
	d.rp.Rewrite = func(r *httputil.ProxyRequest) { r.SetURL(u) }
	d.jobNet = "egress-ci-1001"
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1.47/containers/create?name=x", strings.NewReader(`{"Image":"alpine","Labels":{"a":"b"},"HostConfig":{"NetworkMode":"default"}}`)))
	labels, _ := got["Labels"].(map[string]any)
	hc, _ := got["HostConfig"].(map[string]any)
	if rec.Code != http.StatusCreated || labels[jobLabel] != "1001" || labels["a"] != "b" || got["Image"] != "alpine" || hc["NetworkMode"] != "egress-ci-1001" {
		t.Fatalf("status %d, body seen by the daemon %v", rec.Code, got)
	}
	// A container on a network of its own choosing keeps it.
	d.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1.47/containers/create", strings.NewReader(`{"Image":"alpine","HostConfig":{"NetworkMode":"compose_default"}}`)))
	if hc, _ = got["HostConfig"].(map[string]any); hc["NetworkMode"] != "compose_default" {
		t.Fatalf("explicit network rewritten: %v", got)
	}
	rec = httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1.47/images/create?fromImage=ghcr.io%2Fx%2Fy&tag=1", nil))
	if rec.Code != http.StatusForbidden || calls != 2 {
		t.Fatalf("pull from ghcr.io: status %d, daemon calls %d (2 creates before)", rec.Code, calls)
	}
}
