package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPIs plays GitHub's OIDC endpoint and the control plane.
type fakeAPIs struct {
	mu        sync.Mutex
	audience  string
	exchanged string // bearer the CP saw at /token
	batches   []CIBatch
	failFirst int // events answers 503 this many times
	seenIDs   []string
}

func (f *fakeAPIs) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer request-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.audience = r.URL.Query().Get("audience")
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"value":"github-jwt"}`))
	})
	mux.HandleFunc("/v1/egress/ci/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.exchanged = r.Header.Get("Authorization")
		f.mu.Unlock()
		if f.exchanged != "Bearer github-jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"invalid_token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"OWE_CI_x","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/egress/ci/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer OWE_CI_x" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var b CIBatch
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &b); err != nil {
			t.Errorf("batch: %v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.seenIDs = append(f.seenIDs, b.BatchID)
		if f.failFirst > 0 {
			f.failFirst--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.batches = append(f.batches, b)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":` + itoa(len(b.Events)) + `}`))
	})
	return mux
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func testReport(n int) *Report {
	rep := &Report{Meta: Meta{Mode: "enforce", Stopped: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}, Blocked: 1}
	rep.Dests = append(rep.Dests,
		&Dest{Host: "example.org", Ports: []int{443}, Via: []string{"dns", "container"}, Containers: []string{"probe"}, Connections: 1, Blocked: 1, Reasons: []string{"not_allowed"}},
		&Dest{Host: "proxy.golang.org", Ports: []int{443}, Via: []string{"proxy"}, Connections: 3, Down: 2048, Allowed: true},
		&Dest{Host: "resolved-only.example", Via: []string{"dns"}, Allowed: true}, // not an event
	)
	for i := range n {
		rep.Dests = append(rep.Dests, &Dest{Host: "h" + itoa(i) + ".example", Via: []string{"proxy"}, Connections: 1, Allowed: true})
	}
	return rep
}

func TestSendExchangesOIDCAndSendsDestinations(t *testing.T) {
	f := &fakeAPIs{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/oidc?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_RUN_ID", "42")
	s := &sender{api: srv.URL, client: srv.Client(), sleep: func(time.Duration) {}}
	n, err := s.send(t.Context(), testReport(0))
	if err != nil || n != 2 {
		t.Fatalf("send = %d, %v", n, err)
	}
	if f.audience != oidcAudience {
		t.Fatalf("audience %q", f.audience)
	}
	b := f.batches[0]
	if b.Run.Repository != "owner/repo" || b.Run.RunID != 42 || b.Mode != "enforce" || len(b.Events) != 2 {
		t.Fatalf("batch %+v", b)
	}
	e := b.Events[0]
	if e.Host != "example.org" || e.Decision != "block" || e.Reason != "not_allowed" || e.Via != "container" || e.Container != "probe" {
		t.Fatalf("blocked destination sent as %+v", e)
	}
}

// 5xx is retried with the same batch_id (the control plane deduplicates); more than 1000 events split.
func TestSendRetriesWithSameBatchIDAndSplits(t *testing.T) {
	f := &fakeAPIs{failFirst: 2}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	s := &sender{api: srv.URL, client: srv.Client(), sleep: func(time.Duration) {}}
	n, err := s.send(t.Context(), testReport(1500))
	if err != nil || n != 1502 || len(f.batches) != 2 || len(f.batches[0].Events) != maxBatchEvents {
		t.Fatalf("send = %d, %v, %d batches", n, err, len(f.batches))
	}
	if f.seenIDs[0] != f.seenIDs[1] || f.seenIDs[1] != f.seenIDs[2] || f.seenIDs[2] == f.seenIDs[3] {
		t.Fatalf("batch ids %v: retries must reuse it, the next batch must not", f.seenIDs)
	}
}

// Without id-token: write, or with a refused exchange, the line explains it and never carries a token.
func TestSendReportFailuresAreExplainedWithoutSecrets(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	if line := sendReport("https://api.example", testReport(0)); !strings.Contains(line, "id-token: write") {
		t.Fatalf("no OIDC: %q", line)
	}
	f := &fakeAPIs{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "wrong-request-token")
	line := sendReport(srv.URL, testReport(0))
	if !strings.HasPrefix(line, "Events not sent") || strings.Contains(line, "request-token") {
		t.Fatalf("refused OIDC: %q", line)
	}
	if line := sendReport("http://api.example", testReport(0)); !strings.Contains(line, "https") {
		t.Fatalf("plain http accepted: %q", line)
	}
}
