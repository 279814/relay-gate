package transform

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
)

// SSEShadow accumulates a shadow diff over a live SSE stream one complete
// event at a time, so the stream is never buffered whole (§15.2 / §15.5).
// It only reads copies; nothing it computes reaches the client.
type SSEShadow struct {
	c       *Compiled
	events  int
	changed int
	hits    []string
	seen    map[string]bool
	in, out hash.Hash
	err     string
}

// NewSSEShadow starts a per-stream shadow accumulator for c.
func (c *Compiled) NewSSEShadow() *SSEShadow {
	return &SSEShadow{c: c, seen: map[string]bool{}, in: sha256.New(), out: sha256.New()}
}

// Event applies the shadow version to a copy of one live event.
func (s *SSEShadow) Event(ev SSEEvent) {
	s.events++
	s.in.Write(ev.Raw)
	out, hits, _, err := s.c.ApplySSEEvent(ev)
	for _, h := range hits {
		if !s.seen[h] {
			s.seen[h] = true
			s.hits = append(s.hits, h)
		}
	}
	if err != nil {
		s.Fail(err)
		s.out.Write(ev.Raw)
		return
	}
	if out.Event != ev.Event || out.Data != ev.Data {
		s.changed++
		s.out.Write(out.Raw)
		return
	}
	s.out.Write(ev.Raw)
}

// Fail keeps the first shadow error (framing, size, budget) for the summary.
func (s *SSEShadow) Fail(err error) {
	if err != nil && s.err == "" {
		s.err = err.Error()
	}
}

// Err returns the first shadow error, or "".
func (s *SSEShadow) Err() string { return s.err }

// InputHash is the SHA-256 of every live event fed so far, in order.
func (s *SSEShadow) InputHash() string { return hex.EncodeToString(s.in.Sum(nil)) }

// Summary is the redacted diff line: counts, hit rules, hashes, error.
func (s *SSEShadow) Summary() string {
	return fmt.Sprintf("sse events=%d changed=%d hits=%v in=%s out=%s err=%v",
		s.events, s.changed, s.hits, s.InputHash(), hex.EncodeToString(s.out.Sum(nil)), s.err)
}
