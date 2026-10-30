package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy is .github/egress.yml: which destinations a job may reach and how the rest is treated.
type Policy struct {
	Version int      `yaml:"version"`
	Mode    string   `yaml:"mode"`    // audit (log only) or enforce (block the rest)
	Presets []string `yaml:"presets"` // named allowlists maintained with the action (github-actions)
	Allow   []string `yaml:"allow"`   // host, *.domain, host:port, host:* (default ports 80 and 443)
	Inspect []string `yaml:"inspect"` // hosts whose TLS the proxy terminates to scan bodies (DLP)

	allow   []rule
	inspect []rule
}

type rule struct {
	host     string // lowercase, no trailing dot; for wildcards the parent domain
	wildcard bool   // *.example.com: any name below example.com, not example.com itself
	anyPort  bool
	ports    map[int]bool // nil: 80 and 443
}

func loadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.compile(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

func (p *Policy) compile() error {
	if p.Version != 0 && p.Version != 1 {
		return fmt.Errorf("version %d not supported (1)", p.Version)
	}
	switch p.Mode {
	case "":
		p.Mode = "audit"
	case "audit", "enforce":
	default:
		return fmt.Errorf("mode %q: audit or enforce", p.Mode)
	}
	p.allow, p.inspect = nil, nil
	all := append([]string(nil), p.Allow...)
	for _, name := range p.Presets {
		list, ok := presets()[name]
		if !ok {
			return fmt.Errorf("preset %q unknown (known: github-actions)", name)
		}
		all = append(all, list...)
	}
	for _, s := range all {
		r, err := parseRule(s)
		if err != nil {
			return err
		}
		p.allow = append(p.allow, r)
	}
	for _, s := range p.Inspect {
		r, err := parseRule(s)
		if err != nil {
			return err
		}
		p.inspect = append(p.inspect, r)
	}
	return nil
}

func parseRule(s string) (rule, error) {
	in := s
	s = strings.ToLower(strings.TrimSpace(s))
	var r rule
	if h, port, ok := strings.Cut(s, ":"); ok {
		s = h
		if port == "*" {
			r.anyPort = true
		} else {
			r.ports = map[int]bool{}
			for _, ps := range strings.Split(port, ",") {
				n, err := strconv.Atoi(ps)
				if err != nil || n < 1 || n > 65535 {
					return r, fmt.Errorf("rule %q: bad port %q", in, ps)
				}
				r.ports[n] = true
			}
		}
	}
	s = strings.TrimSuffix(s, ".")
	if strings.HasPrefix(s, "*.") {
		r.wildcard = true
		s = s[2:]
	}
	if s == "" || strings.ContainsAny(s, "*/ @?#") {
		return r, fmt.Errorf("rule %q: host must be a name, *.domain or an IP", in)
	}
	r.host = s
	return r, nil
}

func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

func (r rule) matchName(h string) bool {
	if r.wildcard {
		return strings.HasSuffix(h, "."+r.host)
	}
	return h == r.host
}

func (r rule) matchPort(port int) bool {
	if r.anyPort {
		return true
	}
	if r.ports == nil {
		return port == 80 || port == 443
	}
	return r.ports[port]
}

// Allowed reports whether host:port is in the allowlist.
func (p *Policy) Allowed(host string, port int) bool {
	h := normHost(host)
	for _, r := range p.allow {
		if r.matchName(h) && r.matchPort(port) {
			return true
		}
	}
	return false
}

// AllowedName reports whether a name is allowed on any port (DNS answers, IP lock).
func (p *Policy) AllowedName(host string) bool {
	h := normHost(host)
	for _, r := range p.allow {
		if r.matchName(h) {
			return true
		}
	}
	return false
}

// Inspected reports whether the proxy terminates TLS for host.
func (p *Policy) Inspected(host string) bool {
	h := normHost(host)
	for _, r := range p.inspect {
		if r.matchName(h) {
			return true
		}
	}
	return false
}

// githubMeta is the Actions part of api.github.com/meta: the exact names a runner needs (results storage accounts
// one by one, never *.blob.core.windows.net, under which any Azure customer can create an account).
type githubMeta struct {
	Fetched string   `json:"fetched"`
	Source  string   `json:"source,omitempty"`
	Actions []string `json:"actions"`
}

//go:embed github-meta-actions.json
var embeddedGitHubMeta []byte

var activeGitHubMeta = mustGitHubMeta(embeddedGitHubMeta, "embedded snapshot")

func mustGitHubMeta(b []byte, source string) githubMeta {
	var m githubMeta
	if err := json.Unmarshal(b, &m); err != nil || len(m.Actions) == 0 {
		panic("github meta snapshot: " + fmt.Sprint(err))
	}
	m.Source = source
	return m
}

// useGitHubMeta replaces the embedded snapshot with a current copy of api.github.com/meta (the action fetches it at
// start); a file that does not parse keeps the snapshot.
func useGitHubMeta(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var full struct {
		Domains struct {
			Actions []string `json:"actions"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(b, &full); err != nil || len(full.Domains.Actions) == 0 {
		return fmt.Errorf("%s: no domains.actions", path)
	}
	activeGitHubMeta = githubMeta{Fetched: "this run", Source: "api.github.com/meta", Actions: full.Domains.Actions}
	return nil
}

// presets are the destinations a job needs whatever it does. github-actions: GitHub's published list for Actions
// runners (the runner, checkout, the API, cache, artifacts and logs storage) plus raw.githubusercontent.com, where
// setup-* actions read their version manifests.
func presets() map[string][]string {
	return map[string][]string{
		"github-actions": append(append([]string(nil), activeGitHubMeta.Actions...), "raw.githubusercontent.com"),
	}
}

// exactNames returns the allowlist entries that are plain names (resolved at start to seed the IP lock).
func (p *Policy) exactNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range p.allow {
		if !r.wildcard && !seen[r.host] {
			seen[r.host] = true
			out = append(out, r.host)
		}
	}
	sort.Strings(out)
	return out
}
