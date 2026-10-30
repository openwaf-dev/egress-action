// Command egress-ci is the OpenWAF Egress CI sidecar: a forward proxy and a transparent proxy with a domain
// allowlist, a logging DNS forwarder, a Docker socket that attributes the job's containers, and an nftables lock
// scoped to the job's user and containers; plus the per-run report.
//
//	egress-ci run    -policy FILE -state DIR -uid N [-chroot /host] [-hosts 127.0.0.1,BRIDGE] [-port P] [-docker SOCK] [-lock on|off]
//	egress-ci report -state DIR [-summary FILE]
//	egress-ci check  -policy FILE
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: egress-ci run|report|check|version …")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "docker-label":
		err = cmdDockerLabel(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "egress-ci:", err)
		os.Exit(1)
	}
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	policy := fs.String("policy", ".github/egress.yml", "policy file")
	meta := fs.String("github-meta", "", "api.github.com/meta copy for the github-actions preset")
	_ = fs.Parse(args)
	if *meta != "" {
		if err := useGitHubMeta(*meta); err != nil {
			fmt.Fprintln(os.Stderr, "egress-ci: github meta:", err, "(embedded snapshot used)")
		}
	}
	p, err := loadPolicy(*policy)
	if err != nil {
		return err
	}
	fmt.Printf("%s: mode %s, %d allow rules (github-actions preset from %s), %d inspected\n", *policy, p.Mode, len(p.allow), activeGitHubMeta.Source, len(p.inspect))
	return nil
}

// cmdDockerLabel serves a Docker socket that labels every container, network and volume created through it and
// records them, so a runner that runs several job slots can clean one slot's Docker state without touching the
// other's (one socket per slot, given to its jobs as DOCKER_HOST).
func cmdDockerLabel(args []string) error {
	fs := flag.NewFlagSet("docker-label", flag.ExitOnError)
	listen := fs.String("listen", "", "socket to serve")
	upstream := fs.String("upstream", "/var/run/docker.sock", "Docker daemon socket")
	uid := fs.Int("uid", -1, "owner of the socket (mode 0600)")
	label := fs.String("label", "", "key=value added to everything created")
	registry := fs.String("registry", "", "file where every creation is appended as «kind id»")
	_ = fs.Parse(args)
	k, v, ok := strings.Cut(*label, "=")
	if *listen == "" || *uid < 0 || !ok || k == "" {
		return errors.New("-listen, -uid and -label key=value required")
	}
	dp := newDockerProxy(*upstream, *uid, map[string]string{k: v}, nil, false, nil, nil)
	if *registry != "" {
		f, err := os.OpenFile(*registry, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		dp.registry = f
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	srv, err := dp.serve(ctx, *listen)
	if err != nil {
		return err
	}
	fmt.Printf("egress-ci %s: docker-label %s -> %s, label %s\n", version, *listen, *upstream, *label)
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// Meta is state/meta.json, written at start and completed at stop.
type Meta struct {
	Version     string    `json:"version"`
	Mode        string    `json:"mode"`
	PolicyFile  string    `json:"policy_file"`
	PolicySHA   string    `json:"policy_sha256"`
	GitHubMeta  string    `json:"github_meta"` // where the github-actions preset came from
	UID         int       `json:"uid"`
	Lock        string    `json:"lock"`   // on, off, failed: …
	Docker      string    `json:"docker"` // tracked, off, failed: …
	Proxy       []string  `json:"proxy"`
	DNS         string    `json:"dns"`
	Transparent string    `json:"transparent"`
	DockerSock  string    `json:"docker_socket,omitempty"`
	Inspect     bool      `json:"inspect"`
	Started     time.Time `json:"started"`
	Stopped     time.Time `json:"stopped,omitzero"`
	StartupMS   int64     `json:"startup_ms"`
	Allowed4    int       `json:"allowed4,omitempty"`
	Containers  []string  `json:"containers,omitempty"` // the job's containers: "name (image)"
	SetsDumpErr string    `json:"sets_dump_error,omitempty"`
}

// Sets is state/nft.json: what the lock observed besides the proxies' own logs.
type Sets struct {
	Direct       []Endpoint        `json:"direct"`                  // the job's new non-TCP flows (UDP, ICMP) outside loopback and Docker
	Direct6      []Endpoint        `json:"direct6"`                 // the same for IPv6
	JobCts       []Endpoint        `json:"job_cts"`                 // the job's containers' new non-TCP flows (src . dst . port)
	OtherCts     []Endpoint        `json:"other_cts"`               // every container flow on the runner's bridges (src . dst . port)
	Allowed4     []Endpoint        `json:"allowed4"`                // addresses allowed names resolved to
	ContainerIPs map[string]string `json:"container_ips,omitempty"` // address -> job container, as tracked
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	policyPath := fs.String("policy", ".github/egress.yml", "policy file")
	state := fs.String("state", "", "state directory (events.jsonl, meta.json, nft.json, ca.pem, docker.sock)")
	uid := fs.Int("uid", -1, "uid of the job's user (the lock matches only its sockets)")
	chroot := fs.String("chroot", "", "root of the host filesystem for nft (when the sidecar runs in a container)")
	hosts := fs.String("hosts", "127.0.0.1", "comma-separated listen addresses; the second, when given, is the Docker bridge address containers are sent to")
	basePort := fs.Int("port", 0, "proxy port; DNS on port+1, transparent proxy on port+2; taken triples move on (0: any free port)")
	dockerSock := fs.String("docker", "", "Docker daemon socket to serve to the job (empty: no container tracking)")
	lockMode := fs.String("lock", "on", "nftables lock: on, off")
	mode := fs.String("mode", "", "override the policy mode (audit, enforce)")
	ghMeta := fs.String("github-meta", "", "api.github.com/meta copy for the github-actions preset (default: embedded snapshot)")
	lockAll := fs.Bool("lock-all-containers", false, "enforce on every container of the runner (single-job runners only)")
	_ = fs.Parse(args)
	t0 := time.Now()
	if *state == "" {
		return errors.New("-state required")
	}
	if err := os.MkdirAll(*state, 0o755); err != nil {
		return err
	}
	if *ghMeta != "" {
		if err := useGitHubMeta(*ghMeta); err != nil {
			fmt.Fprintln(os.Stderr, "egress-ci: github meta:", err, "(embedded snapshot used)")
		}
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if *mode != "" {
		pol.Mode = *mode
		if err := pol.compile(); err != nil {
			return err
		}
	}
	enforce := pol.Mode == "enforce"
	raw, _ := os.ReadFile(*policyPath)
	sum := sha256.Sum256(raw)
	meta := &Meta{Version: version, Mode: pol.Mode, PolicyFile: *policyPath, PolicySHA: hex.EncodeToString(sum[:]),
		GitHubMeta: activeGitHubMeta.Source + " (" + activeGitHubMeta.Fetched + ")", UID: *uid, Started: t0.UTC(), Docker: "off"}

	elog, err := openEventLog(filepath.Join(*state, "events.jsonl"))
	if err != nil {
		return err
	}
	defer elog.close()

	var ca *mitmCA
	if len(pol.inspect) > 0 {
		if ca, err = newMITMCA(); err != nil {
			return err
		}
		if err := ca.writePEM(filepath.Join(*state, "ca.pem")); err != nil {
			return err
		}
		meta.Inspect = true
	}

	// Ports: fixed per job user and below the ephemeral range (Linux 32768-60999), so neither a client socket nor
	// a random pick can take a port the job binds itself (a Compose stack's fixed ports); a taken triple moves on.
	hostList := strings.Split(*hosts, ",")
	ls, err := bindListeners(hostList, *basePort)
	if err != nil {
		return err
	}
	for _, ln := range ls.proxy {
		meta.Proxy = append(meta.Proxy, ln.Addr().String())
	}
	meta.DNS = ls.udp[0].LocalAddr().String()
	meta.Transparent = ls.transparent[0].Addr().String()
	bridgeIP := ""
	if len(hostList) > 1 {
		bridgeIP = strings.TrimSpace(hostList[1])
	}

	var lock *nftLock
	meta.Lock = "off"
	if *lockMode == "on" {
		lock, err = newNFTLock(*chroot, *uid)
		if err == nil {
			err = lock.install(lockConfig{dnsPort: ls.port + 1, tPort: ls.port + 2, bridgeIP: bridgeIP, enforce: enforce, lockAllCts: *lockAll})
		}
		if err != nil {
			if enforce {
				return fmt.Errorf("enforce needs the lock: %w", err)
			}
			meta.Lock = "failed: " + err.Error()
			lock = nil
		} else {
			meta.Lock = "on"
		}
	}
	defer func() {
		if lock != nil {
			_ = lock.remove()
		}
	}()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var ct *containerTracker
	var dp *dockerProxy
	var dockerSrv *http.Server
	if *dockerSock != "" {
		ct = newContainerTracker(lock, elog)
		dp = newDockerProxy(*dockerSock, *uid, map[string]string{jobLabel: strconv.Itoa(*uid)}, pol, enforce, elog, ct)
		path := filepath.Join(*state, "docker.sock")
		err := dp.ensureJobNetwork("egress-ci-" + strconv.Itoa(*uid))
		if err == nil {
			dockerSrv, err = dp.serve(ctx, path)
		}
		if err != nil {
			if enforce {
				return fmt.Errorf("Docker tracking: %w", err)
			}
			meta.Docker, ct, dp = "failed: "+err.Error(), nil, nil
		} else {
			meta.Docker, meta.DockerSock = "tracked", path
		}
	}

	ds := &dnsServer{pol: pol, enforce: enforce, log: elog, upstreams: resolvConfUpstreams("/etc/resolv.conf"), lock: lock, ct: ct, allowed: map[string]bool{}}
	px := newProxy(pol, enforce, elog, ca)
	srv := &http.Server{Handler: px, ReadHeaderTimeout: 30 * time.Second}
	tp := &transparent{p: px, dns: ds, ct: ct}
	for _, c := range ls.udp {
		go ds.serveUDP(c)
	}
	for _, l := range ls.tcpDNS {
		go ds.serveTCP(l)
	}
	for _, l := range ls.proxy {
		go func() { _ = srv.Serve(l) }()
	}
	for _, l := range ls.transparent {
		go tp.serve(l)
	}

	meta.StartupMS = time.Since(t0).Milliseconds()
	if err := writeJSON(filepath.Join(*state, "meta.json"), meta); err != nil {
		return err
	}
	fmt.Printf("egress-ci %s: mode %s, proxy %s, dns %s, transparent %s, lock %s, docker %s\n", version, pol.Mode,
		strings.Join(meta.Proxy, " "), meta.DNS, meta.Transparent, meta.Lock, meta.Docker)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = srv.Shutdown(sctx)
	if dockerSrv != nil {
		_ = dockerSrv.Shutdown(sctx)
		dp.removeJobNetwork()
	}
	cancel()
	stop()
	ls.close()
	if ct != nil {
		meta.Containers = ct.containers()
	}
	if lock != nil {
		sets := Sets{ContainerIPs: ct.snapshot()}
		var errs []string
		for _, s := range []struct {
			name string
			dst  *[]Endpoint
		}{{"seen", &sets.Direct}, {"seen6", &sets.Direct6}, {"seen_ct", &sets.JobCts}, {"seen_fwd", &sets.OtherCts}, {"allow4", &sets.Allowed4}} {
			eps, err := lock.dumpSet(s.name)
			if err != nil && !(bridgeIP == "" && (s.name == "seen_ct" || s.name == "seen_fwd")) {
				errs = append(errs, s.name+": "+err.Error())
			}
			*s.dst = eps
		}
		meta.SetsDumpErr = strings.Join(errs, "; ")
		meta.Allowed4 = len(sets.Allowed4)
		_ = writeJSON(filepath.Join(*state, "nft.json"), sets)
	}
	meta.Stopped = time.Now().UTC()
	return writeJSON(filepath.Join(*state, "meta.json"), meta)
}
