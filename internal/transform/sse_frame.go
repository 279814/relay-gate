package transform

import (
	"bytes"
	"strings"
)

// SSEScanner accumulates upstream bytes and emits complete SSE events
// (terminated by a blank line). Trailing bytes without a blank line are
// available via Flush at EOF (§15: no half-event output).
type SSEScanner struct {
	buf      []byte
	overflow bool
}

// maxSSEScannerHold bounds the scanner buffer: one event at the limit plus the
// longest blank-line delimiter ("\r\n\r\n").
const maxSSEScannerHold = MaxSSEEventBytes + 4

// Feed appends p and returns every complete event found. When a pending event
// exceeds MaxSSEEventBytes, Feed returns an *SSELimitError carrying the
// unframed original bytes (held buffer plus the unconsumed rest of p), clears
// its buffer and rejects all further input the same way, so the scanner never
// holds more than maxSSEScannerHold bytes.
func (s *SSEScanner) Feed(p []byte) ([]SSEEvent, error) {
	if s.overflow {
		return nil, &SSELimitError{Pending: append([]byte(nil), p...)}
	}
	var out []SSEEvent
	for {
		take := maxSSEScannerHold - len(s.buf)
		if take > len(p) {
			take = len(p)
		}
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		for {
			sep, n := findSSEBoundary(s.buf)
			if sep < 0 {
				break
			}
			raw := append([]byte(nil), s.buf[:sep+n]...)
			s.buf = s.buf[sep+n:]
			out = append(out, ParseSSEEvent(raw))
		}
		if len(s.buf) > MaxSSEEventBytes {
			pending := make([]byte, 0, len(s.buf)+len(p))
			pending = append(append(pending, s.buf...), p...)
			s.buf = nil
			s.overflow = true
			return out, &SSELimitError{Pending: pending}
		}
		if len(p) == 0 {
			return out, nil
		}
	}
}

// Buffered reports how many unframed bytes the scanner currently holds.
func (s *SSEScanner) Buffered() int { return len(s.buf) }

// Flush returns a final unterminated event, if any.
func (s *SSEScanner) Flush() (SSEEvent, bool) {
	if len(bytes.TrimSpace(s.buf)) == 0 {
		s.buf = nil
		return SSEEvent{}, false
	}
	raw := append([]byte(nil), s.buf...)
	s.buf = nil
	return ParseSSEEvent(raw), true
}

func findSSEBoundary(b []byte) (idx, sepLen int) {
	// Prefer CRLF blank line, then LF.
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i, 4
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i, 2
	}
	return -1, 0
}

// SSELimitError reports an event over MaxSSEEventBytes. Pending holds the
// original bytes the scanner could not frame, in stream order.
type SSELimitError struct {
	Pending []byte
}

func (e *SSELimitError) Error() string {
	return "sse event exceeds buffer while framing"
}

// ParseSSEEvent decodes one framed SSE block into event/data fields.
func ParseSSEEvent(raw []byte) SSEEvent {
	ev := SSEEvent{Raw: append([]byte(nil), raw...)}
	var dataLines []string
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		if bytes.HasPrefix(line, []byte("event:")) {
			ev.Event = strings.TrimSpace(string(line[len("event:"):]))
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			dataLines = append(dataLines, string(line[len("data:"):]))
			// SSE allows optional single leading space after "data:".
			if len(dataLines[len(dataLines)-1]) > 0 && dataLines[len(dataLines)-1][0] == ' ' {
				dataLines[len(dataLines)-1] = dataLines[len(dataLines)-1][1:]
			}
			continue
		}
	}
	ev.Data = strings.Join(dataLines, "\n")
	return ev
}

// IsSSEContentType reports text/event-stream responses.
func IsSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}
