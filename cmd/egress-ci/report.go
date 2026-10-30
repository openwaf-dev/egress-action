package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Dest is one destination of the report, keyed by name (or by address when no name is known).
type Dest struct {
	Host        string   `json:"host"`
	Ports       []int    `json:"ports"`
	Via         []string `json:"via"`                  // proxy (HTTPS_PROXY), direct (caught by the lock), container, udp, dns
	Containers  []string `json:"containers,omitempty"` // the job's containers that connected
	Connections int      `json:"connections"`
	Up          int64    `json:"bytes_up"`
	Down        int64    `json:"bytes_down"`
	Allowed     bool     `json:"allowed"`
	Blocked     int      `json:"blocked"`     // attempts refused (enforce)
	Audited     int      `json:"audited"`     // attempts that enforce would refuse
	DNSRefused  int      `json:"dns_refused"` // queries answered NXDOMAIN (enforce)
	Reasons     []string `json:"reasons,omitempty"`
	Detections  []string `json:"detections,omitempty"`
}

// Report is state/report.json.
type Report struct {
	Meta        Meta     `json:"meta"`
	DurationS   float64  `json:"duration_s"`
	Dests       []*Dest  `json:"destinations"`
	Blocked     int      `json:"blocked"`
	Audited     int      `json:"would_block"` // destinations
	DNSRefused  int      `json:"dns_refused"` // names
	Detections  int      `json:"detections"`
	Suggested   []string `json:"suggested_allow"`
	DNSQueries  int      `json:"dns_queries"`
	Unresolved  []string `json:"unattributed_addresses,omitempty"` // non-TCP flows to addresses no DNS answer named
	Pulls       []string `json:"image_pulls,omitempty"`            // Docker pulls through the job's socket: "image: decision"
	OtherCts    []string `json:"other_containers,omitempty"`       // container flows on the runner that are not this job's
	InspectNote string   `json:"inspect_note,omitempty"`
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	state := fs.String("state", "", "state directory of the run")
	summary := fs.String("summary", os.Getenv("GITHUB_STEP_SUMMARY"), "markdown file to append the summary to")
	link := fs.String("link", "", "URL shown at the end of the summary (the run's artifact or the Egress events)")
	send := fs.Bool("send", false, "send the destinations to OpenWAF Egress events (GitHub OIDC; the job needs id-token: write)")
	api := fs.String("api", "https://dash.openwaf.dev", "OpenWAF API base URL for -send")
	_ = fs.Parse(args)
	if *state == "" {
		return errors.New("-state required")
	}
	rep, err := buildReport(*state)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(*state, "report.json"), rep); err != nil {
		return err
	}
	md := renderMarkdown(rep, *link)
	if *send {
		line := sendReport(*api, rep)
		fmt.Println("egress-ci:", line)
		if strings.HasPrefix(line, "Events not sent") {
			fmt.Println("::warning title=OpenWAF Egress CI::" + line)
		}
		md = strings.TrimSuffix(md, "\n") + "\n" + line + "\n\n"
	}
	if *summary != "" {
		f, err := os.OpenFile(*summary, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.WriteString(f, md); err != nil {
			return err
		}
	} else {
		fmt.Print(md)
	}
	fmt.Printf("egress-ci: %d destinations, %d blocked, %d would be blocked in enforce, %d DLP/exfiltration detections\n",
		len(rep.Dests), rep.Blocked, rep.Audited, rep.Detections)
	return nil
}

func buildReport(state string) (*Report, error) {
	rep := &Report{}
	if b, err := os.ReadFile(filepath.Join(state, "meta.json")); err == nil {
		_ = json.Unmarshal(b, &rep.Meta)
	} else {
		return nil, fmt.Errorf("no meta.json: the sidecar did not start (%w)", err)
	}
	stop := rep.Meta.Stopped
	if stop.IsZero() {
		stop = time.Now().UTC()
	}
	rep.DurationS = stop.Sub(rep.Meta.Started).Seconds()
	pol := &Policy{}
	if p, err := loadPolicy(rep.Meta.PolicyFile); err == nil {
		pol = p
	}

	dests := map[string]*Dest{}
	get := func(host string) *Dest {
		d, ok := dests[host]
		if !ok {
			d = &Dest{Host: host}
			dests[host] = d
		}
		return d
	}
	addPort := func(d *Dest, port int) {
		for _, p := range d.Ports {
			if p == port {
				return
			}
		}
		d.Ports = append(d.Ports, port)
	}
	addVia := func(d *Dest, v string) {
		for _, x := range d.Via {
			if x == v {
				return
			}
		}
		d.Via = append(d.Via, v)
	}
	ipNames := map[string][]string{} // address → names whose DNS answers contained it (the job's queries)

	f, err := os.Open(filepath.Join(state, "events.jsonl"))
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e Event
			if json.Unmarshal(sc.Bytes(), &e) != nil || e.Host == "" {
				continue
			}
			if e.Kind == "docker" {
				if e.Method == "pull" {
					s := e.Note + ": " + e.Decision
					if e.Reason != "" {
						s += " (" + e.Reason + ")"
					}
					rep.Pulls = appendUnique(rep.Pulls, s)
				}
				continue
			}
			d := get(e.Host)
			switch e.Kind {
			case "dns":
				rep.DNSQueries++
				addVia(d, "dns")
				for _, a := range e.Answers {
					if !strings.HasPrefix(a, "cname:") {
						ipNames[a] = appendUnique(ipNames[a], e.Host)
					}
				}
			case "connect", "http", "direct":
				via := "proxy"
				if e.Kind == "direct" {
					via = "direct"
				}
				if e.Container != "" {
					via = "container"
					d.Containers = appendUnique(d.Containers, e.Container)
				}
				addVia(d, via)
				addPort(d, e.Port)
				d.Connections++
				d.Up += e.Up
				d.Down += e.Down
			}
			if e.Reason != "" {
				d.Reasons = appendUnique(d.Reasons, e.Reason)
			}
			switch {
			case e.Kind == "dns" && e.Decision == "block":
				d.DNSRefused++
			case e.Kind == "dns":
			case e.Decision == "block":
				d.Blocked++
			case e.Decision == "audit":
				d.Audited++
			}
			for _, det := range e.Detections {
				d.Detections = appendUnique(d.Detections, det)
			}
			if e.Inspected {
				rep.InspectNote = "TLS terminated for the hosts under inspect: request bodies scanned with the Egress DLP detectors"
			}
		}
	}

	var sets Sets
	if b, err := os.ReadFile(filepath.Join(state, "nft.json")); err == nil {
		_ = json.Unmarshal(b, &sets)
	}
	attribute := func(eps []Endpoint) {
		for _, ep := range eps {
			names := ipNames[ep.IP]
			if len(names) == 0 {
				rep.Unresolved = appendUnique(rep.Unresolved, net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port)))
				names = []string{ep.IP}
			}
			for _, n := range names {
				d := get(n)
				addVia(d, "udp")
				addPort(d, ep.Port)
				d.Connections++
				if c := sets.ContainerIPs[ep.Src]; c != "" {
					d.Containers = appendUnique(d.Containers, c)
				}
				// Non-TCP flows outside the allowlist: refused by the lock in enforce.
				if !pol.AllowedName(n) {
					if rep.Meta.Mode == "enforce" {
						d.Blocked++
					} else {
						d.Audited++
					}
				}
			}
		}
	}
	attribute(sets.Direct)
	attribute(sets.Direct6)
	attribute(sets.JobCts)
	// The bridges carry every container of the runner; those that are not this job's are listed apart.
	for _, ep := range sets.OtherCts {
		if _, mine := sets.ContainerIPs[ep.Src]; mine {
			continue
		}
		rep.OtherCts = appendUnique(rep.OtherCts, ep.Src+" → "+net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port)))
	}
	sort.Strings(rep.OtherCts)

	for _, d := range dests {
		d.Allowed = pol.AllowedName(d.Host)
		sort.Ints(d.Ports)
		sort.Strings(d.Detections)
		sort.Strings(d.Containers)
		if d.Blocked > 0 {
			rep.Blocked++
		}
		if d.Audited > 0 {
			rep.Audited++
		}
		if d.DNSRefused > 0 {
			rep.DNSRefused++
		}
		rep.Detections += len(d.Detections)
		if !d.Allowed && !isIP(d.Host) && d.Connections > 0 {
			rep.Suggested = append(rep.Suggested, d.Host)
		}
		rep.Dests = append(rep.Dests, d)
	}
	sort.Slice(rep.Dests, func(i, j int) bool {
		a, b := rep.Dests[i], rep.Dests[j]
		if (a.Blocked+a.Audited > 0) != (b.Blocked+b.Audited > 0) {
			return a.Blocked+a.Audited > 0
		}
		if a.Up+a.Down != b.Up+b.Down {
			return a.Up+a.Down > b.Up+b.Down
		}
		return a.Host < b.Host
	})
	sort.Strings(rep.Suggested)
	sort.Strings(rep.Unresolved)
	return rep, nil
}

func renderMarkdown(rep *Report, link string) string {
	var b strings.Builder
	m := rep.Meta
	fmt.Fprintf(&b, "### OpenWAF Egress CI: %s\n\n", m.Mode)
	lock := m.Lock
	if lock == "" {
		lock = "off"
	}
	fmt.Fprintf(&b, "Policy `%s` (sha256 %s), %.0f s observed, lock %s, Docker %s, %d DNS queries, sidecar start %d ms. GitHub preset: %s.\n\n",
		m.PolicyFile, short(m.PolicySHA), rep.DurationS, lock, m.Docker, rep.DNSQueries, m.StartupMS, m.GitHubMeta)
	var conn, dnsOnly, refused []*Dest
	for _, d := range rep.Dests {
		switch {
		case d.Connections > 0 || d.Blocked > 0 || d.Audited > 0 || len(d.Detections) > 0:
			conn = append(conn, d)
		case d.DNSRefused > 0:
			refused = append(refused, d)
		default:
			dnsOnly = append(dnsOnly, d)
		}
	}
	if m.Mode == "enforce" {
		fmt.Fprintf(&b, "**%d destinations, %d blocked, %d names refused at DNS, %d detections.**\n\n", len(conn), rep.Blocked, rep.DNSRefused, rep.Detections)
	} else {
		fmt.Fprintf(&b, "**%d destinations, %d outside the policy (enforce would block them), %d detections.**\n\n", len(conn), rep.Audited, rep.Detections)
	}
	b.WriteString("| Destination | Ports | Via | Conn. | Up | Down | Policy | Detections |\n|---|---|---|---:|---:|---:|---|---|\n")
	for _, d := range conn {
		pol := "allowed"
		switch {
		case d.Blocked > 0:
			pol = fmt.Sprintf("**blocked** (%d)", d.Blocked)
		case d.Audited > 0:
			pol = "**not allowed**"
		case !d.Allowed:
			pol = "not allowed"
		}
		if len(d.Reasons) > 0 && pol != "allowed" {
			pol += " " + strings.Join(d.Reasons, ", ")
		}
		via := strings.Join(d.Via, ", ")
		if len(d.Containers) > 0 {
			via += " (" + strings.Join(d.Containers, ", ") + ")"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %d | %s | %s | %s | %s |\n", d.Host, ports(d.Ports), via,
			d.Connections, bytesHuman(d.Up), bytesHuman(d.Down), pol, codeList(d.Detections))
	}
	if len(refused) > 0 {
		b.WriteString("\nRefused at DNS (NXDOMAIN, outside the policy): ")
		b.WriteString(hostList(refused) + "\n")
	}
	if len(dnsOnly) > 0 {
		fmt.Fprintf(&b, "\n<details><summary>%d names resolved without a connection seen</summary>\n\n%s\n</details>\n", len(dnsOnly), hostList(dnsOnly))
	}
	if len(rep.Suggested) > 0 {
		b.WriteString("\n<details><summary>Names outside the policy (add to <code>allow</code> to keep them in enforce)</summary>\n\n```yaml\nallow:\n")
		for _, s := range rep.Suggested {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
		b.WriteString("```\n</details>\n")
	}
	if len(rep.Unresolved) > 0 {
		fmt.Fprintf(&b, "\nNon-TCP flows to addresses no DNS query named: %s\n", codeList(rep.Unresolved))
	}
	if len(m.Containers) > 0 {
		fmt.Fprintf(&b, "\nThe job's containers (through its Docker socket; their DNS and TCP pass the sidecar like the job's): %s\n", codeList(m.Containers))
	}
	if len(rep.Pulls) > 0 {
		fmt.Fprintf(&b, "\nImage pulls: %s\n", codeList(rep.Pulls))
	}
	if len(rep.OtherCts) > 0 {
		fmt.Fprintf(&b, "\n<details><summary>%d flows from containers that are not this job's (other jobs on the runner, or Docker used without the job's socket)</summary>\n\n%s\n</details>\n", len(rep.OtherCts), codeList(rep.OtherCts))
	}
	if rep.InspectNote != "" {
		b.WriteString("\n" + rep.InspectNote + ".\n")
	}
	b.WriteString("\nVia: `proxy` through HTTPS_PROXY, `direct` caught by the lock (tools that ignore the proxy variables, the runner itself), `container` the job's containers, `udp` non-TCP flows, `dns` only resolved. Every TCP connection is named by its TLS SNI or HTTP Host and checked against the address it went to.\n")
	if link != "" {
		fmt.Fprintf(&b, "\nEvents: %s\n", link)
	}
	b.WriteString("\n")
	return b.String()
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func isIP(s string) bool {
	return strings.Count(s, ".") == 3 && strings.Trim(s, "0123456789.") == "" || strings.Contains(s, ":")
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func ports(p []int) string {
	if len(p) == 0 {
		return ""
	}
	out := make([]string, len(p))
	for i, n := range p {
		out[i] = fmt.Sprint(n)
	}
	return strings.Join(out, ", ")
}

func codeList(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return "`" + strings.Join(s, "`, `") + "`"
}

func bytesHuman(n int64) string {
	switch {
	case n == 0:
		return ""
	case n < 1<<10:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
}

func hostList(ds []*Dest) string {
	names := make([]string, len(ds))
	for i, d := range ds {
		names[i] = d.Host
	}
	sort.Strings(names)
	return codeList(names)
}
