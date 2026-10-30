package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event is one line of events.jsonl: a connection (through the proxy or caught by the lock), a DNS query, a Docker
// API decision or a DLP finding.
type Event struct {
	TS         time.Time `json:"ts"`
	Kind       string    `json:"kind"` // connect, http (through HTTPS_PROXY), direct (transparent), dns, docker, lock
	Client     string    `json:"client,omitempty"`
	Container  string    `json:"container,omitempty"` // the job's container that made it (Docker tracking)
	Host       string    `json:"host,omitempty"`
	Port       int       `json:"port,omitempty"`
	SNI        string    `json:"sni,omitempty"`
	Method     string    `json:"method,omitempty"`
	QType      string    `json:"qtype,omitempty"`
	Decision   string    `json:"decision"`         // allow, audit (would be blocked in enforce), block
	Reason     string    `json:"reason,omitempty"` // not_allowed, sni_mismatch, name_ip_mismatch, dlp, private_destination, registry_not_allowed…
	Up         int64     `json:"up,omitempty"`
	Down       int64     `json:"down,omitempty"`
	DurMS      int64     `json:"dur_ms,omitempty"`
	Detections []string  `json:"detections,omitempty"`
	Answers    []string  `json:"answers,omitempty"`
	Inspected  bool      `json:"inspected,omitempty"`
	Note       string    `json:"note,omitempty"`
}

type eventLog struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func openEventLog(path string) (*eventLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &eventLog{f: f, enc: json.NewEncoder(f)}, nil
}

func (l *eventLog) add(e Event) {
	if l == nil {
		return
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

func (l *eventLog) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
