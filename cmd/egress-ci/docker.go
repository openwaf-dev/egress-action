package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The job's Docker goes through a socket the sidecar serves (DOCKER_HOST): containers it creates get a label with
// the job's uid, their addresses are tracked from start to death (nftables set ct4: their DNS and TCP come to the
// sidecar like the job's own, the rest is refused in enforce) and image pulls are checked against the allowlist by
// registry before the daemon fetches anything.

const jobLabel = "org.openwaf.egress-ci.uid"

type containerTracker struct {
	mu      sync.Mutex
	byIP    map[string]string   // live: address -> container name
	ips     map[string][]string // live: container id -> addresses
	history map[string]string   // every address a job container had (the report reads the lock's sets after they die)
	nets    map[string][]string // job network id and name -> subnets (in the lock's set ct4)
	lock    *nftLock
	log     *eventLog
	seen    []string // every container of the job, for the report: "name (image)"
}

func newContainerTracker(lock *nftLock, log *eventLog) *containerTracker {
	return &containerTracker{byIP: map[string]string{}, ips: map[string][]string{}, history: map[string]string{}, nets: map[string][]string{}, lock: lock, log: log}
}

// snapshot returns every address a job container had (nil-safe).
func (t *containerTracker) snapshot() map[string]string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]string, len(t.history))
	for k, v := range t.history {
		out[k] = v
	}
	return out
}

// name returns the job's container at ip, or "" (nil-safe).
func (t *containerTracker) name(ip string) string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byIP[ip]
}

// add names a started container's addresses for the report. The lock does not wait for this: it holds the job's
// networks by subnet from their creation (addNetwork), so a container is covered from its first packet.
func (t *containerTracker) add(id, name, image string, addrs []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range addrs {
		t.byIP[a] = name
		t.history[a] = name
		t.ips[id] = appendUnique(t.ips[id], a)
	}
	t.seen = appendUnique(t.seen, name+" ("+image+")")
}

func (t *containerTracker) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range t.ips[id] {
		delete(t.byIP, a)
	}
	delete(t.ips, id)
}

// addNetwork puts a job network's subnets in the lock (set ct4) before any container can join it.
func (t *containerTracker) addNetwork(id, name string, subnets []string) error {
	t.mu.Lock()
	t.nets[id] = subnets
	t.nets[name] = subnets
	t.mu.Unlock()
	if len(subnets) == 0 || t.lock == nil {
		return nil
	}
	return t.lock.setElems("add", "ct4", subnets)
}

// removeNetwork takes a deleted job network's subnets out of the lock (Docker gives them to the next network,
// maybe another job's).
func (t *containerTracker) removeNetwork(idOrName string) {
	t.mu.Lock()
	subnets := t.nets[idOrName]
	for k, v := range t.nets {
		if len(v) > 0 && len(subnets) > 0 && v[0] == subnets[0] {
			delete(t.nets, k)
		}
	}
	t.mu.Unlock()
	if len(subnets) > 0 && t.lock != nil {
		_ = t.lock.setElems("delete", "ct4", subnets)
	}
}

func (t *containerTracker) containers() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.seen...)
}

type dockerProxy struct {
	uid      int
	upstream string            // daemon socket
	labels   map[string]string // added to every container, network and volume created through the socket
	pol      *Policy           // nil: no pull policy (runner slot mode)
	enforce  bool
	log      *eventLog         // nil-safe
	ct       *containerTracker // nil: no address tracking (runner slot mode)
	client   *http.Client
	rp       *httputil.ReverseProxy
	jobNet   string // the job's bridge network (job mode): containers asking for the default bridge get it

	regMu    sync.Mutex
	registry *os.File // optional: "kind id" of everything created, one per line
}

func newDockerProxy(upstream string, uid int, labels map[string]string, pol *Policy, enforce bool, log *eventLog, ct *containerTracker) *dockerProxy {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", upstream)
	}
	tr := &http.Transport{DialContext: dial, DisableCompression: true}
	d := &dockerProxy{uid: uid, upstream: upstream, labels: labels, pol: pol, enforce: enforce, log: log, ct: ct, client: &http.Client{Transport: tr}}
	d.rp = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host = "http", "docker"
			r.Out.Host = "docker"
		},
		Transport:      tr,
		FlushInterval:  -1, // logs, events, attach streams
		ModifyResponse: d.afterResponse,
	}
	return d
}

var (
	reCreate   = regexp.MustCompile(`^(?:/v[0-9.]+)?/(containers|networks|volumes)/create$`)
	reStart    = regexp.MustCompile(`^(?:/v[0-9.]+)?/containers/([^/]+)/start$`)
	reConnect  = regexp.MustCompile(`^(?:/v[0-9.]+)?/networks/[^/]+/connect$`)
	reNetwork  = regexp.MustCompile(`^(?:/v[0-9.]+)?/networks/([^/]+)$`)
	rePull     = regexp.MustCompile(`^(?:/v[0-9.]+)?/images/create$`)
	defaultNet = map[string]bool{"": true, "default": true, "bridge": true}
)

type connectKey struct{}

func (d *dockerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && reCreate.MatchString(r.URL.Path):
		if err := d.labelCreate(r, reCreate.FindStringSubmatch(r.URL.Path)[1]); err != nil {
			http.Error(w, `{"message":"OpenWAF Egress CI: `+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
	case r.Method == http.MethodPost && reConnect.MatchString(r.URL.Path):
		// The container joining a network gets a new address: remember which one, re-inspect it once connected.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var c struct{ Container string }
		_ = json.Unmarshal(body, &c)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), connectKey{}, c.Container))
	case r.Method == http.MethodPost && rePull.MatchString(r.URL.Path) && d.pol != nil:
		if img := r.URL.Query().Get("fromImage"); img != "" {
			reg := registryOf(img)
			ev := Event{Kind: "docker", Method: "pull", Host: reg, Note: img, Decision: "allow"}
			if !d.pol.AllowedName(reg) {
				ev.Decision, ev.Reason = "audit", "registry_not_allowed"
				if d.enforce {
					ev.Decision = "block"
					d.log.add(ev)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprintf(w, `{"message":"OpenWAF Egress CI: registry %s is not in .github/egress.yml"}`, reg)
					return
				}
			}
			d.log.add(ev)
		}
	}
	d.rp.ServeHTTP(w, r)
}

// labelCreate adds the labels to a container, network or volume create request. With a job network, a container
// asking for Docker's default bridge gets the job network instead: its subnet is in the lock before the container
// exists, so no packet of it leaves before the lock knows it.
func (d *dockerProxy) labelCreate(r *http.Request, kind string) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	var spec map[string]any
	if len(bytes.TrimSpace(body)) == 0 {
		spec = map[string]any{} // POST /volumes/create may come without a body
	} else if err := json.Unmarshal(body, &spec); err != nil {
		return fmt.Errorf("create body: %w", err)
	}
	labels, _ := spec["Labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	for k, v := range d.labels {
		labels[k] = v
	}
	spec["Labels"] = labels
	if kind == "containers" && d.jobNet != "" {
		hc, _ := spec["HostConfig"].(map[string]any)
		if hc == nil {
			hc = map[string]any{}
			spec["HostConfig"] = hc
		}
		mode, _ := hc["NetworkMode"].(string)
		if defaultNet[mode] {
			hc["NetworkMode"] = d.jobNet
			if nc, ok := spec["NetworkingConfig"].(map[string]any); ok {
				if eps, ok := nc["EndpointsConfig"].(map[string]any); ok {
					for _, k := range []string{"bridge", "default"} {
						if ep, ok := eps[k]; ok {
							delete(eps, k)
							eps[d.jobNet] = ep
						}
					}
				}
			}
		}
	}
	out, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	r.Header.Set("Content-Length", strconv.Itoa(len(out)))
	r.Header.Set("Content-Type", "application/json")
	return nil
}

func (d *dockerProxy) afterResponse(resp *http.Response) error {
	r := resp.Request
	if resp.StatusCode >= 300 {
		return nil
	}
	if r.Method == http.MethodDelete && d.ct != nil {
		if m := reNetwork.FindStringSubmatch(r.URL.Path); m != nil {
			d.ct.removeNetwork(m[1])
		}
		return nil
	}
	if r.Method != http.MethodPost {
		return nil
	}
	if m := reCreate.FindStringSubmatch(r.URL.Path); m != nil {
		id := createdID(m[1], resp)
		if d.registry != nil && id != "" {
			d.regMu.Lock()
			_, _ = fmt.Fprintf(d.registry, "%s %s\n", strings.TrimSuffix(m[1], "s"), id)
			d.regMu.Unlock()
		}
		// The network's subnets enter the lock before the client hears it exists.
		if m[1] == "networks" && d.ct != nil && id != "" {
			if err := d.trackNetwork(id); err != nil {
				d.log.add(Event{Kind: "lock", Decision: "block", Note: "job network " + id + ": " + err.Error()})
			}
		}
	}
	if d.ct == nil {
		return nil
	}
	if m := reStart.FindStringSubmatch(r.URL.Path); m != nil {
		d.track(m[1])
	} else if id, _ := r.Context().Value(connectKey{}).(string); id != "" {
		d.track(id)
	}
	return nil
}

// createdID reads what was created from the answer (containers and networks {"Id"}, volumes {"Name"}) and leaves the
// body for the client.
func createdID(kind string, resp *http.Response) string {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var v struct {
		ID   string `json:"Id"`
		Name string
	}
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	if kind == "volumes" {
		return v.Name
	}
	return v.ID
}

// trackNetwork puts a job network's subnets in the lock.
func (d *dockerProxy) trackNetwork(idOrName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/networks/"+url.PathEscape(idOrName), nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var n struct {
		ID   string `json:"Id"`
		Name string
		IPAM struct{ Config []struct{ Subnet string } }
	}
	if err := json.NewDecoder(resp.Body).Decode(&n); err != nil {
		return err
	}
	var subnets []string
	for _, c := range n.IPAM.Config {
		if c.Subnet != "" && !strings.Contains(c.Subnet, ":") {
			subnets = append(subnets, c.Subnet)
		}
	}
	if len(subnets) == 0 {
		return errors.New("no IPv4 subnet")
	}
	d.log.add(Event{Kind: "docker", Method: "network", Note: n.Name, Answers: subnets, Decision: "allow"})
	return d.ct.addNetwork(n.ID, n.Name, subnets)
}

// ensureJobNetwork creates the job's own bridge network, where containers asking for the default bridge go.
func (d *dockerProxy) ensureJobNetwork(name string) error {
	body, _ := json.Marshal(map[string]any{"Name": name, "Driver": "bridge", "Labels": d.labels})
	req, _ := http.NewRequest(http.MethodPost, "http://docker/networks/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusConflict { // 409: left by a job killed before its post step
		return fmt.Errorf("create network %s: %s", name, resp.Status)
	}
	if err := d.trackNetwork(name); err != nil {
		return err
	}
	d.jobNet = name
	return nil
}

// removeJobNetwork deletes the job network at the end (it fails while a container still uses it; the runner's
// cleanup removes both later).
func (d *dockerProxy) removeJobNetwork() {
	if d.jobNet == "" {
		return
	}
	req, _ := http.NewRequest(http.MethodDelete, "http://docker/networks/"+url.PathEscape(d.jobNet), nil)
	if resp, err := d.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

// track inspects a started container of the job and records its addresses.
func (d *dockerProxy) track(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+url.PathEscape(id)+"/json", nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var c struct {
		ID     string `json:"Id"`
		Name   string
		Config struct {
			Image  string
			Labels map[string]string
		}
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil || c.Config.Labels[jobLabel] != strconv.Itoa(d.uid) {
		return
	}
	var addrs []string
	for _, n := range c.NetworkSettings.Networks {
		if n.IPAddress != "" {
			addrs = append(addrs, n.IPAddress)
		}
	}
	name := strings.TrimPrefix(c.Name, "/")
	d.ct.add(c.ID, name, c.Config.Image, addrs)
	d.log.add(Event{Kind: "docker", Method: "start", Container: name, Note: c.Config.Image, Answers: addrs, Decision: "allow"})
}

// watch follows the daemon's events for the job's containers and forgets the addresses of the dead ones (Docker
// reuses them for other containers, maybe of another job on the runner).
func (d *dockerProxy) watch(ctx context.Context) {
	filters := fmt.Sprintf(`{"type":["container"],"event":["die","destroy"],"label":["%s=%d"]}`, jobLabel, d.uid)
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/events?filters="+url.QueryEscape(filters), nil)
		resp, err := d.client.Do(req)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var e struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.ID != "" {
				d.ct.remove(e.ID)
			}
		}
		resp.Body.Close()
	}
}

// serve listens on a unix socket only the job's user can open.
func (d *dockerProxy) serve(ctx context.Context, path string) (*http.Server, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, d.uid, -1); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	srv := &http.Server{Handler: d, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	if d.ct != nil {
		go d.watch(ctx)
	}
	return srv, nil
}

// registryOf returns the registry host an image reference pulls from (docker.io references from
// registry-1.docker.io, the host the daemon contacts).
func registryOf(ref string) string {
	first, _, found := strings.Cut(ref, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		h, _, err := net.SplitHostPort(first)
		if err != nil {
			h = first
		}
		h = strings.ToLower(h)
		if h != "docker.io" && h != "index.docker.io" {
			return h
		}
	}
	return "registry-1.docker.io"
}
