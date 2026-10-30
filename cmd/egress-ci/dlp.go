package main

import (
	"math"
	"sort"
	"strings"

	"github.com/openwaf-dev/egress/pkg/egress"
)

// githubHosts legitimately receive GitHub tokens (the job's own GITHUB_TOKEN, checkout, the cache and results APIs).
var githubHosts = []string{"github.com", "githubusercontent.com", "ghcr.io", "githubapp.com", "actions.githubusercontent.com"}

func isGitHubHost(host string) bool {
	h := normHost(host)
	for _, g := range githubHosts {
		if h == g || strings.HasSuffix(h, "."+g) {
			return true
		}
	}
	return false
}

// scanText runs the Egress DLP detectors (the same ones the AI gateway uses) on outbound text bound for host and
// returns stable detection ids. GitHub tokens sent to GitHub are expected and not reported.
func scanText(host, text string) []string {
	if text == "" {
		return nil
	}
	var ids []string
	for _, m := range egress.ScanDLP(text) {
		id := m.Type
		switch {
		case strings.Contains(m.Description, "AWS"):
			id = "aws_access_key"
		case strings.Contains(m.Description, "OpenAI"):
			id = "openai_key"
		case strings.Contains(m.Description, "GitHub"):
			if isGitHubHost(host) {
				continue
			}
			id = "github_token"
		}
		ids = append(ids, "dlp."+id)
	}
	return dedupe(ids)
}

// scanName looks for data smuggled in a DNS name or a CONNECT host: secrets in labels, long high-entropy labels
// (encoded payloads) and overlong names. Visible without terminating TLS, so it covers every destination.
func scanName(name string) []string {
	n := normHost(name)
	ids := scanText("", strings.ReplaceAll(n, ".", " "))
	for _, label := range strings.Split(n, ".") {
		if len(label) >= 40 && entropy(label) >= 3.8 {
			ids = append(ids, "dns.high_entropy_label")
			break
		}
	}
	if len(n) >= 150 {
		ids = append(ids, "dns.long_name")
	}
	return dedupe(ids)
}

func entropy(s string) float64 {
	var freq [256]int
	for i := range len(s) {
		freq[s[i]]++
	}
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
