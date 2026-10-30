package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Sending a run's destinations to OpenWAF (contract: the Action's OIDC token from GitHub, exchanged at the control
// plane for a short-lived token, then batches of events). No token is ever printed, logged or put on argv.

const oidcAudience = "openwaf-egress-ci"

// CIEvent is one destination of the run, as the control plane stores it.
type CIEvent struct {
	TS          time.Time `json:"ts"`
	Host        string    `json:"host"`
	Port        int       `json:"port,omitempty"`
	Via         string    `json:"via"`
	Container   string    `json:"container,omitempty"`
	Decision    string    `json:"decision"`
	Reason      string    `json:"reason,omitempty"`
	Detections  []string  `json:"detections,omitempty"`
	Connections int       `json:"connections"`
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
}

// CIRun identifies the job.
type CIRun struct {
	Repository string `json:"repository"`
	RunID      int64  `json:"run_id"`
	RunAttempt int    `json:"run_attempt"`
	Workflow   string `json:"workflow"`
	Job        string `json:"job"`
	SHA        string `json:"sha"`
	Ref        string `json:"ref"`
	Event      string `json:"event"`
	Runner     string `json:"runner"`
}

// CIBatch is the body of POST /v1/egress/ci/events.
type CIBatch struct {
	BatchID string         `json:"batch_id"`
	Run     CIRun          `json:"run"`
	Mode    string         `json:"mode"`
	Summary map[string]int `json:"summary"`
	Events  []CIEvent      `json:"events"`
}

const maxBatchEvents = 1000

// ciEvents turns the report into one event per destination (names refused at DNS included).
func ciEvents(rep *Report) []CIEvent {
	ts := rep.Meta.Stopped
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	var out []CIEvent
	for _, d := range rep.Dests {
		if d.Connections == 0 && d.DNSRefused == 0 && d.Blocked == 0 && d.Audited == 0 && len(d.Detections) == 0 {
			continue // resolved only
		}
		e := CIEvent{TS: ts, Host: d.Host, Decision: "allow", Detections: d.Detections, Connections: d.Connections, BytesUp: d.Up, BytesDown: d.Down}
		if len(d.Ports) > 0 {
			e.Port = d.Ports[0]
		}
		for _, v := range d.Via {
			if v != "dns" {
				e.Via = v
				break
			}
		}
		if e.Via == "" {
			e.Via = "dns"
		}
		if len(d.Containers) > 0 {
			e.Container = d.Containers[0]
		}
		switch {
		case d.Blocked > 0 || d.DNSRefused > 0:
			e.Decision = "block"
		case d.Audited > 0:
			e.Decision = "audit"
		}
		if len(d.Reasons) > 0 {
			e.Reason = d.Reasons[0]
		}
		out = append(out, e)
	}
	return out
}

func runFromEnv() CIRun {
	id, _ := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	att, _ := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	return CIRun{
		Repository: os.Getenv("GITHUB_REPOSITORY"), RunID: id, RunAttempt: att, Workflow: os.Getenv("GITHUB_WORKFLOW"),
		Job: os.Getenv("GITHUB_JOB"), SHA: os.Getenv("GITHUB_SHA"), Ref: os.Getenv("GITHUB_REF"),
		Event: os.Getenv("GITHUB_EVENT_NAME"), Runner: os.Getenv("RUNNER_NAME"),
	}
}

type sender struct {
	api    string // control plane base URL
	client *http.Client
	sleep  func(time.Duration)
}

// send delivers the report; it returns how many events the control plane accepted.
func (s *sender) send(ctx context.Context, rep *Report) (int, error) {
	idt, err := s.githubOIDC(ctx)
	if err != nil {
		return 0, fmt.Errorf("GitHub OIDC token: %w", err)
	}
	tok, err := s.exchange(ctx, idt)
	if err != nil {
		return 0, err
	}
	events := ciEvents(rep)
	run := runFromEnv()
	summary := map[string]int{"destinations": len(events), "blocked": rep.Blocked, "would_block": rep.Audited,
		"detections": rep.Detections, "dns_queries": rep.DNSQueries}
	accepted := 0
	// One batch at least (a run without destinations still reports its summary), then ≤1000 events each.
	chunks := [][]CIEvent{events}
	if len(events) > maxBatchEvents {
		chunks = nil
		for start := 0; start < len(events); start += maxBatchEvents {
			chunks = append(chunks, events[start:min(start+maxBatchEvents, len(events))])
		}
	}
	for _, chunk := range chunks {
		b := CIBatch{BatchID: newUUID(), Run: run, Mode: rep.Meta.Mode, Summary: summary, Events: chunk}
		n, err := s.postBatch(ctx, tok, &b)
		if err != nil {
			return accepted, err
		}
		accepted += n
	}
	return accepted, nil
}

func (s *sender) githubOIDC(ctx context.Context) (string, error) {
	reqURL, reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		return "", errors.New("not available (the job needs permissions: id-token: write)")
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", errors.New("bad ACTIONS_ID_TOKEN_REQUEST_URL")
	}
	q := u.Query()
	q.Set("audience", oidcAudience)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+reqTok)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var v struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&v); err != nil || v.Value == "" {
		return "", errors.New("no token in the answer")
	}
	return v.Value, nil
}

type apiError struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func readAPIError(resp *http.Response) string {
	var e apiError
	_ = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&e)
	for _, s := range []string{e.Code, e.Error, e.Message} {
		if s != "" {
			return fmt.Sprintf("%d %s", resp.StatusCode, s)
		}
	}
	return strconv.Itoa(resp.StatusCode)
}

func (s *sender) exchange(ctx context.Context, idToken string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.api+"/v1/egress/ci/token", nil)
	req.Header.Set("Authorization", "Bearer "+idToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", errors.New("token exchange: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange: %s", readAPIError(resp))
	}
	var v struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&v); err != nil || v.Token == "" {
		return "", errors.New("token exchange: no token in the answer")
	}
	return v.Token, nil
}

// postBatch sends one batch, retrying network errors and 5xx with the same batch_id (idempotent).
func (s *sender) postBatch(ctx context.Context, tok string, b *CIBatch) (int, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return 0, err
	}
	var last error
	for attempt := range 3 {
		if attempt > 0 {
			s.sleep(time.Duration(attempt) * 2 * time.Second)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.api+"/v1/egress/ci/events", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			last = errors.New("events: request failed")
			continue
		}
		if resp.StatusCode >= 500 {
			last = fmt.Errorf("events: %s", readAPIError(resp))
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("events: %s", readAPIError(resp))
			resp.Body.Close()
			return 0, err
		}
		var v struct {
			Accepted int `json:"accepted"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&v)
		resp.Body.Close()
		return v.Accepted, nil
	}
	return 0, last
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// sendReport is the report command's -send: never fails the job, returns the line for the summary.
func sendReport(api string, rep *Report) string {
	api = strings.TrimRight(api, "/")
	if !strings.HasPrefix(api, "https://") && !strings.HasPrefix(api, "http://127.0.0.1") && !strings.HasPrefix(api, "http://localhost") {
		return "Events not sent to OpenWAF: openwaf-api must be an https URL."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Direct, never through HTTPS_PROXY: in the post step the sidecar it points at is already stopped (and inside the
	// lock a direct connection goes through the transparent proxy anyway).
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	s := &sender{api: api, client: &http.Client{Timeout: 20 * time.Second, Transport: tr}, sleep: time.Sleep}
	n, err := s.send(ctx, rep)
	if err != nil {
		return "Events not sent to OpenWAF: " + err.Error() + "."
	}
	return fmt.Sprintf("%d destinations sent to OpenWAF Egress events (%s).", n, api)
}
